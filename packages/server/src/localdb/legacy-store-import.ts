import { realpath } from "node:fs/promises";
import type { Database } from "better-sqlite3";
import {
  controlScope,
  IDENTITYLESS_NS,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createImportLedger,
  createLegacyEraseLedger,
  importLegacySource,
  readBackLegacyImport,
  retireLegacyCopies,
  syncBeforeBegin,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  ImportSource,
  ImportTarget,
  LegacyCopy,
  LegacyRetireAccess,
  LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  receiptOutcomes,
  quarantineTally,
  type QuarantineCounts,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { manifestArtifact } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { openLegacyAccess, type LegacyAccess } from "./legacy-access.js";
import { importProjection } from "./sync.js";

/**
 * What the last finished import left out, for owner diagnostics
 * (`read-status?audit=1`). A count of inventory the runner already decides:
 * no rule here changes what is imported.
 *
 * - `excluded`: sources never offered to the database, by the reason the
 *   inventory gave (`older_instance` and `deleted_instance` are the archive
 *   and older copies of a connection; `undeclared_source`, `undeclared_stream`,
 *   `unbound_store`, ... are stores with no verified declaration).
 * - `refused`: sources the database turned down, by its reason
 *   (`generation_not_one`, `connection_deleted`, `source_changed`, ...).
 * - `files`: old data files seen at retirement, and those with no importable
 *   source (file-only scopes). `null` when the retirement pass failed.
 *
 * - `rows`: for the sources the runner offered to the database (the newest
 *   live instance of each declared source): rows the old store held, rows now
 *   imported, rows blocked (staged, but the stream already holds or deleted
 *   the key: a live write wins), rows left out (by reason: no full identity,
 *   an older copy, a valid delete envelope as `delete_envelope`), and rows of
 *   streams the database refused. Every stored record is in exactly one of
 *   them: `legacy = imported + blocked + sum(quarantined) + refused`. `legacy` is
 *   null once any source carried no count; `refused` is null once a refused
 *   source carried none. The receipt keeps the quarantine reasons, so the
 *   count outlives the old files.
 *
 * A source with no rows is not counted: the inventory lists every declared
 * stream of each connection, and an empty one loses nothing.
 *
 * In memory: a restart clears it until the next run, which recounts the whole
 * inventory. `rows` is the inventory's row count at the snapshot, `null` when
 * the source did not carry one.
 */
export interface LegacyStoreImportReport {
  readonly finishedAt: number;
  readonly stopped: boolean;
  readonly imported: number;
  readonly alreadyImported: number;
  readonly excluded: readonly LegacyStoreImportCount[];
  readonly refused: readonly LegacyStoreImportCount[];
  readonly rows: {
    /** Inventory rows; null once a source did not carry a count. */
    readonly legacy: number | null;
    readonly imported: number;
    /** Staged rows the fill-only rules kept out: the stream already holds, or
     * deleted, the key with other content. */
    readonly blocked: number;
    readonly quarantined: QuarantineCounts;
    /** Rows of refused streams (`refused` has them by reason); null once a
     * refused source did not carry a count. */
    readonly refused: number | null;
  };
  readonly files: {
    readonly total: number;
    readonly unimported: number;
  } | null;
}

export interface LegacyStoreImportCount {
  readonly reason: string;
  readonly streams: number;
  readonly rows: number | null;
}

export interface LegacyStoreRunner extends ImportRunner {
  /** The last finished run's report, or null before one has finished. */
  report(): LegacyStoreImportReport | null;
}

export interface LegacyStoreImportOptions {
  /** The server's own `index.db` handle. Borrowed: never closed here. */
  readonly db: Database;
  /** The storage root that holds `index.db`. */
  readonly root: string;
  /** Canonical directory used by the server for legacy data files. */
  readonly dataDir?: string;
  readonly owner: string;
  readonly network: string;
  readonly legacyWriteSeal: LegacyWriteSeal;
  /** The server's one open database for the owner. Throws unless switched. */
  readonly getDeps: () => Promise<LocalSyncDeps>;
  /** Retained declarations, read at each run. */
  readonly declarations: () => readonly DeclarationSnapshot[];
  /** The verified connector a source id belongs to, read at each run. */
  readonly methods: () => readonly { sourceId: string; methodId: string }[];
  /** Verified manifest documents, read at each run. */
  readonly manifests: () => Iterable<string>;
  /** Read at each run, so it follows `streamSync.retireLegacy`. */
  readonly streamSync: () => { readonly retireLegacy?: boolean };
  readonly logger: LocalSyncDeps["logger"];
}

/**
 * The server's own legacy store (`index.db` and `data/`) is a one-time seed
 * for a switched owner. One run imports every importable source, then calls
 * `retireLegacyCopies`, which removes the old files only when
 * `streamSync.retireLegacy` is on; with it off the same call reads back and
 * reports. No host supplies a port: the server builds the access from its own
 * root, data directory, handle and seal.
 *
 * Retirement follows the import in this one run, never before it. It would
 * otherwise remove a file that the import has not read yet. The import waker
 * keeps runs to one at a time, and starts one only for a switched owner.
 *
 * Failures:
 * - A failed import (the access refused, a read threw, the registry did not
 *   answer) retires nothing, and the waker logs it and runs again at the next
 *   Account answer or start.
 * - A refused source (unknown stream, a real write already owns it, a deleted
 *   connection) is counted and not retried. Its file is still retired: old
 *   data is a one-time seed, and the database is authoritative.
 * - A failed retirement is logged and leaves the import done. The next run
 *   retires what is left.
 * - Shutdown aborts the run: no further source is read and no file is erased.
 *
 * A seed already in the database wins over this store. Both write stamp
 * `(0, 'seed')`, and the merge changes no row for an equal stamp, so the older
 * import of a key stays and this store only adds keys the database lacks. A
 * real write always wins over both. See the legacy-migration tests.
 */
export function createLegacyStoreRunner(
  options: LegacyStoreImportOptions,
): LegacyStoreRunner {
  const { logger } = options;
  let last: LegacyStoreImportReport | null = null;
  return {
    report: () => last,
    async run(signal) {
      const deps = await options.getDeps();
      const root = await realpath(options.root);
      const access = await openLegacyAccess({
        importProjection,
        db: options.db,
        owner: options.owner,
        network: options.network,
        root,
        dataDir: options.dataDir,
        declarations: options.declarations(),
        eraseLedger: createLegacyEraseLedger(deps.db, () => deps.now()),
        legacyWriteSeal: options.legacyWriteSeal,
        // The server opened this handle at this root for this owner. The old
        // index holds no owner of its own to compare.
        verifyBinding: async (binding) =>
          binding.db === options.db &&
          binding.root === root &&
          binding.owner.toLowerCase() === options.owner.toLowerCase() &&
          binding.network === options.network,
        // Every legacy write becomes durable inside `legacyWriteSeal.commit`,
        // which refuses for a switched owner, so none can start while the
        // owner stays switched. `openLegacyAccess` rechecks this before each
        // read.
        isQuiescent: async () =>
          options.legacyWriteSeal.verdict() === "switched",
        isSwitched: async () =>
          options.legacyWriteSeal.verdict() === "switched",
        resolveTarget: (sourceId, _instance, stream) =>
          resolveTarget(options, sourceId, stream),
      });
      try {
        const imported = await importSources(deps, access, signal, logger);
        // A run that stopped has not finished: the last finished report stays.
        if (signal.aborted) return;
        const report = imported.report(deps.now(), false);
        let files: LegacyStoreImportReport["files"] = null;
        try {
          files = await retire(options, deps, access, imported.sources, signal);
        } catch (error) {
          logger.warn(
            { error: String(error) },
            "legacy retirement failed; it runs again at the next import run",
          );
        }
        // One publication, after retirement settled: a reader never sees the
        // new counts with `files` still null while a finished report exists.
        if (!signal.aborted) last = { ...report, files };
      } finally {
        await access.close();
      }
    },
  };
}

/** A source id's one verified connector and stream declaration, or null. The
 * connection is the connector's identityless control scope, as for a staged
 * host upload; a legacy instance id never becomes a sync namespace. */
async function resolveTarget(
  options: LegacyStoreImportOptions,
  sourceId: string,
  stream: string,
): Promise<ImportTarget | null> {
  const methods = options
    .methods()
    .filter((method) => method.sourceId === sourceId);
  if (methods.length !== 1) return null;
  const connector = methods[0]!.methodId;
  const artifacts = [...options.manifests()].flatMap((document) => {
    const artifact = manifestArtifact(document);
    return artifact?.declarations.connector === connector ? [artifact] : [];
  });
  if (artifacts.length !== 1) return null;
  const declared = artifacts[0]!.declarations.streams.find(
    (s) => s.name === stream,
  );
  if (!declared) return null;
  return {
    connectionId: controlScope(connector, IDENTITYLESS_NS),
    connector,
    stream,
    primaryKey: declared.primaryKey,
    semantics: declared.semantics,
    incremental: declared.incremental !== false,
  };
}

const sourceKey = (source: string, connectionId: string, stream: string) =>
  JSON.stringify([source, connectionId, stream]);

/** The import descriptors, kept for the read-back that follows. */
type ImportedSources = ReadonlyMap<string, ImportSource>;

/** Streams and rows per reason; `rows` is null once a source carried none. */
function tally() {
  const byReason = new Map<string, { streams: number; rows: number | null }>();
  return {
    add(reason: string, rows: number | undefined) {
      // A stream the inventory lists with no row loses nothing: a connection
      // lists every declared stream, held or not.
      if (rows === 0) return;
      const entry = byReason.get(reason) ?? { streams: 0, rows: 0 };
      entry.streams += 1;
      entry.rows =
        entry.rows === null || rows === undefined ? null : entry.rows + rows;
      byReason.set(reason, entry);
    },
    counts: (): LegacyStoreImportCount[] =>
      [...byReason]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([reason, { streams, rows }]) => ({ reason, streams, rows })),
  };
}

async function importSources(
  deps: LocalSyncDeps,
  access: LegacyAccess,
  signal: AbortSignal,
  logger: LocalSyncDeps["logger"],
): Promise<{
  readonly sources: ImportedSources;
  report(finishedAt: number, stopped: boolean): LegacyStoreImportReport;
}> {
  const ledger = createImportLedger(deps.db);
  const sources = new Map<string, ImportSource>();
  const refreshed = new Set<string>();
  const counts: Record<string, number> = {};
  const count = (name: string) => (counts[name] = (counts[name] ?? 0) + 1);
  const excluded = tally();
  const refused = tally();
  const quarantined = quarantineTally();
  let legacyRows: number | null = 0;
  let importedRows = 0;
  let blockedRows = 0;
  let refusedRows: number | null = 0;
  for await (const entry of access.sources()) {
    if (signal.aborted) break;
    if ("kind" in entry) {
      count(`excluded:${entry.reason}`);
      excluded.add(entry.reason, entry.rows);
      continue;
    }
    const source = entry as ImportSource;
    legacyRows =
      legacyRows === null || source.rows === undefined
        ? null
        : legacyRows + source.rows;
    sources.set(
      sourceKey(
        source.source,
        source.target.connectionId,
        source.target.stream,
      ),
      source,
    );
    // The source name carries its revision, so a receipt under that name is
    // this exact snapshot: nothing is read again on a later start.
    const prior = await ledger.get(
      source.source,
      source.target.connectionId,
      source.target.stream,
    );
    if (prior && prior.state !== "excluded") {
      count("already-imported");
      const outcomes = receiptOutcomes(prior.reason);
      importedRows += prior.rows - outcomes.blocked;
      blockedRows += outcomes.blocked;
      for (const [reason, rows] of Object.entries(outcomes.quarantined))
        quarantined.add(reason, rows);
      continue;
    }
    // The import needs the connector's control row. Read the registry once per
    // connector, as the staged-upload seed does. A registry that does not
    // answer fails the run, so nothing is retired on a guess.
    const { connector } = source.target;
    if (!refreshed.has(connector)) {
      if ((await syncBeforeBegin(deps, connector)).unreachable)
        throw new Error("registry_unreachable");
      refreshed.add(connector);
    }
    const result = await importLegacySource(deps, ledger, source);
    count(result.kind === "refused" ? `refused:${result.reason}` : result.kind);
    if (result.kind === "refused") {
      refused.add(result.reason, source.rows);
      refusedRows =
        refusedRows === null || source.rows === undefined
          ? null
          : refusedRows + source.rows;
    } else {
      importedRows += result.receipt.rows - result.blocked;
      blockedRows += result.blocked;
      for (const [reason, rows] of Object.entries(result.quarantine))
        quarantined.add(reason, rows);
    }
  }
  logger.info(
    { ...counts, stopped: signal.aborted },
    "legacy store import finished",
  );
  return {
    sources,
    report: (finishedAt, stopped) => ({
      finishedAt,
      stopped,
      imported: counts.imported ?? 0,
      alreadyImported: counts["already-imported"] ?? 0,
      excluded: excluded.counts(),
      refused: refused.counts(),
      rows: {
        legacy: legacyRows,
        imported: importedRows,
        blocked: blockedRows,
        quarantined: quarantined.counts(),
        refused: refusedRows,
      },
      files: null,
    }),
  };
}

async function retire(
  options: LegacyStoreImportOptions,
  deps: LocalSyncDeps,
  access: LegacyAccess,
  imported: ImportedSources,
  signal: AbortSignal,
): Promise<{ readonly total: number; readonly unimported: number }> {
  const report = await retireLegacyCopies(
    deps,
    retireAccess(deps, access, imported, signal),
    {
      streamSync: options.streamSync(),
      signal,
      reportFile: (file) =>
        options.logger.info({ ...file }, "legacy file retirement"),
    },
  );
  options.logger.info(
    { ...report, stopped: signal.aborted },
    "legacy retirement finished",
  );
  return { total: report.files, unimported: report.unimported };
}

/** Read-back is diagnostic only, over the sources this run imported. The copy
 * listing ends once aborted, so no further file is read or erased. */
function retireAccess(
  deps: LocalSyncDeps,
  access: LegacyAccess,
  imported: ImportedSources,
  signal: AbortSignal,
): LegacyRetireAccess {
  async function* copies(): AsyncIterable<LegacyCopy> {
    for await (const copy of access.copies()) {
      if (signal.aborted) return;
      yield copy;
    }
  }
  return {
    copies,
    erase: (copy) => access.erase(copy, signal),
    erasedWithIntent: (copy) => access.erasedWithIntent(copy),
    finishErase: (copy) => access.finishErase(copy),
    async readBack(copy) {
      const proofs = [];
      for (const dependency of copy.sources) {
        const source = imported.get(
          sourceKey(
            dependency.source,
            dependency.connectionId,
            dependency.stream,
          ),
        );
        if (source) proofs.push(await readBackLegacyImport(deps, source));
      }
      return proofs;
    },
  };
}
