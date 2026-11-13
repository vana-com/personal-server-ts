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
import { manifestArtifact } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { openLegacyAccess, type LegacyAccess } from "./legacy-access.js";
import { importProjection } from "./sync.js";

export interface LegacyStoreImportOptions {
  /** The server's own `index.db` handle. Borrowed: never closed here. */
  readonly db: Database;
  /** The storage root that holds `index.db` and `data/`. */
  readonly root: string;
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
 * root, handle and seal.
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
): ImportRunner {
  const { logger } = options;
  return {
    async run(signal) {
      const deps = await options.getDeps();
      const root = await realpath(options.root);
      const access = await openLegacyAccess({
        importProjection,
        db: options.db,
        owner: options.owner,
        network: options.network,
        root,
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
        if (signal.aborted) return;
        try {
          await retire(options, deps, access, imported, signal);
        } catch (error) {
          logger.warn(
            { error: String(error) },
            "legacy retirement failed; it runs again at the next import run",
          );
        }
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

async function importSources(
  deps: LocalSyncDeps,
  access: LegacyAccess,
  signal: AbortSignal,
  logger: LocalSyncDeps["logger"],
): Promise<ImportedSources> {
  const ledger = createImportLedger(deps.db);
  const sources = new Map<string, ImportSource>();
  const refreshed = new Set<string>();
  const counts: Record<string, number> = {};
  const count = (name: string) => (counts[name] = (counts[name] ?? 0) + 1);
  for await (const entry of access.sources()) {
    if (signal.aborted) break;
    if ("kind" in entry) {
      count(`excluded:${entry.reason}`);
      continue;
    }
    const source = entry as ImportSource;
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
  }
  logger.info(
    { ...counts, stopped: signal.aborted },
    "legacy store import finished",
  );
  return sources;
}

async function retire(
  options: LegacyStoreImportOptions,
  deps: LocalSyncDeps,
  access: LegacyAccess,
  imported: ImportedSources,
  signal: AbortSignal,
): Promise<void> {
  const report = await retireLegacyCopies(
    deps,
    retireAccess(deps, access, imported, signal),
    {
      streamSync: options.streamSync(),
      reportFile: (file) =>
        options.logger.info({ ...file }, "legacy file retirement"),
    },
  );
  options.logger.info(
    { ...report, stopped: signal.aborted },
    "legacy retirement finished",
  );
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
    erase: (copy) => access.erase(copy),
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
