import {
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import {
  createLegacyScopeStore,
  type LegacyScopeTarget,
  seedLegacyStore,
  type LegacyScopeExclusionReason,
  type LegacySeedStore,
  type LegacySeedStream,
  type QuarantineCounts,
  type SeedIntake,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

/**
 * What the last finished Lite import run did, for owner diagnostics
 * (`read-status?audit=1`, under `legacyStore`). A subset of the Node server's
 * `LegacyStoreImportReport`: Lite cannot split rows the importer's fill-only
 * rules kept out from rows it wrote, so `staged` counts both.
 *
 * Rows are those this run read. A stream that already had a final receipt is
 * not read again (`alreadyImported`), so a repeat run reports no rows.
 * Over the streams read: `legacy = staged + sum(quarantined) + refused`.
 * `quarantined` includes older versions a newer one superseded.
 * `refused` counts the newest stored version's rows of refused streams.
 * In memory: a restart clears it until the next run.
 */
export interface LiteLegacyImportReport {
  readonly finishedAt: number;
  readonly stopped: boolean;
  readonly streams: {
    readonly staged: number;
    readonly alreadyImported: number;
    readonly empty: number;
    readonly refused: readonly {
      reason: string;
      streams: number;
      rows: number;
    }[];
    /** Scopes left out, by reason; they are never imported or removed. */
    readonly excluded: readonly { reason: string; scopes: number }[];
  };
  readonly rows: {
    readonly legacy: number;
    readonly staged: number;
    readonly quarantined: QuarantineCounts;
    readonly refused: number;
  };
  /** Old scope copies removed this run; null while `retireLegacy` is off. */
  readonly retired: { readonly scopes: number } | null;
}

export interface LiteLegacyStoreRunner extends ImportRunner {
  /** The last finished run's report, or null before one has finished. */
  report(): LiteLegacyImportReport | null;
}

export interface LiteLegacyStoreRunnerOptions {
  /** The raw legacy storage: stored bodies, not their projected views. */
  readonly storage: Pick<
    DataStoragePort,
    "listScopes" | "listVersions" | "readEnvelope" | "deleteScope"
  >;
  /** The runtime's own seed intake, once it exists. Waits, or throws if the
   * runtime has none. */
  readonly intake: () => Promise<SeedIntake>;
  /** Verified manifest documents, read at each run. */
  readonly manifests: () => Iterable<string>;
  /** Read at each run, so it follows `streamSync.retireLegacy`. */
  readonly retireLegacy: () => boolean;
  readonly now?: () => number;
  readonly onWarning?: (message: string, detail?: unknown) => void;
}

/** Stream scopes the bindings know, each with the connector streams it may
 * hold. A binding scope with one stream is also stored under its own name.
 * The connector knowledge lives here, not in the database layer. */
function streamScopeTargets(): ReadonlyMap<
  string,
  readonly LegacyScopeTarget[]
> {
  const table = new Map<string, Map<string, LegacyScopeTarget>>();
  const add = (scope: string, target: LegacyScopeTarget) => {
    const targets = table.get(scope) ?? new Map<string, LegacyScopeTarget>();
    targets.set(`${target.connector}\0${target.stream}`, target);
    table.set(scope, targets);
  };
  for (const scope of LEGACY_SCOPE_BINDINGS.keys()) {
    const source = scope.slice(0, scope.indexOf("."));
    for (const alias of legacyAliasScopes(scope)) {
      for (const stream of alias.streams)
        add(`${source}.${stream}`, { connector: alias.connector, stream });
      if (alias.streams.length === 1)
        add(scope, { connector: alias.connector, stream: alias.streams[0]! });
    }
  }
  return new Map([...table].map(([scope, ts]) => [scope, [...ts.values()]]));
}

const tally = <K extends string>() => {
  const byReason = new Map<K, { n: number; rows: number }>();
  return {
    add(reason: K, rows = 0) {
      const entry = byReason.get(reason) ?? { n: 0, rows: 0 };
      entry.n += 1;
      entry.rows += rows;
      byReason.set(reason, entry);
    },
    entries: () =>
      [...byReason].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  };
};

/**
 * Lite's own legacy scope store (the storage `withLegacyProjection` reads) is a
 * one-time seed for a switched owner. One run folds each declared stream's
 * stored versions into the runtime's seed intake, so the importer, its
 * receipts and its fill-only rules apply as for any seed. Then, only when
 * `streamSync.retireLegacy` is on, it removes the scope copies of streams
 * whose receipt is final. A stream that was refused, empty or left out keeps
 * its copy; with the setting off nothing is removed.
 *
 * A failed run (no intake, a read fault) removes nothing; the waker logs it and
 * runs again at the next Account answer or start. Shutdown aborts the run.
 */
export function createLiteLegacyStoreRunner(
  options: LiteLegacyStoreRunnerOptions,
): LiteLegacyStoreRunner {
  let last: LiteLegacyImportReport | null = null;
  // Which scope this runner's own seed put each stream's rows from. A receipt
  // names no source scope, so a final receipt alone does not show that the
  // scope now offered for the stream is the one that was imported (a stream
  // stored under its canonical name and an alias). Memory only: after a
  // restart a stream with a receipt keeps its copy.
  const importedFrom = new Map<string, string>();
  const targets = streamScopeTargets();
  return {
    report: () => last,
    async run(signal) {
      const intake = await options.intake();
      const excluded = tally<LegacyScopeExclusionReason>();
      const store = createLegacyScopeStore({
        storage: options.storage,
        manifests: options.manifests,
        targets,
        onExcluded: ({ reason }) => excluded.add(reason),
      });
      // The newest stored version of each stream, to count a refused stream's
      // rows when the producer reports none.
      const offered = new Map<string, LegacySeedStream>();
      const recording: LegacySeedStore = {
        async *streams() {
          for await (const stream of store.streams()) {
            offered.set(
              JSON.stringify([stream.connector, stream.stream]),
              stream,
            );
            yield stream;
          }
        },
      };
      const seeded = await seedLegacyStore(intake, recording, { signal });
      if (signal.aborted) return;
      const refused = tally<string>();
      let refusedRows = 0;
      let staged = 0;
      let merged = 0;
      let empty = 0;
      for (const s of seeded.streams) {
        if (s.outcome === "staged") staged += 1;
        else if (s.outcome === "merged") merged += 1;
        else if (s.outcome === "empty") empty += 1;
        else {
          let rows = 0;
          const layer = offered.get(JSON.stringify([s.connector, s.stream]))
            ?.layers[0];
          if (layer) for await (const _ of layer.records()) rows += 1;
          refused.add(s.reason ?? "refused", rows);
          refusedRows += rows;
        }
      }
      const quarantined = seeded.quarantine;
      const legacy =
        seeded.rows +
        Object.values(quarantined).reduce((a, b) => a + b, 0) +
        refusedRows;
      for (const s of seeded.streams) {
        const scope = store.scopeOf(s.connector, s.stream);
        if (s.outcome === "staged" && scope !== undefined)
          importedFrom.set(JSON.stringify([s.connector, s.stream]), scope);
      }
      let retired: LiteLegacyImportReport["retired"] = null;
      if (options.retireLegacy()) {
        retired = {
          scopes: await retire(
            options,
            intake,
            store,
            importedFrom,
            seeded.streams,
            signal,
          ),
        };
      }
      if (signal.aborted) return;
      last = {
        finishedAt: (options.now ?? Date.now)(),
        stopped: false,
        streams: {
          staged,
          alreadyImported: merged,
          empty,
          refused: refused
            .entries()
            .map(([reason, { n, rows }]) => ({ reason, streams: n, rows })),
          excluded: excluded
            .entries()
            .map(([reason, { n }]) => ({ reason, scopes: n })),
        },
        rows: {
          legacy,
          staged: seeded.rows,
          quarantined,
          refused: refusedRows,
        },
        retired,
      };
    },
  };
}

/** Remove the scope copies of streams whose receipt is now final. The receipt
 * is read again after the seed, so a stream the importer did not finish keeps
 * its copy. A scope is also kept when it is not the one the runner imported
 * the stream from, or holds versions the import skipped. */
async function retire(
  options: LiteLegacyStoreRunnerOptions,
  intake: SeedIntake,
  store: {
    scopeOf(connector: string, stream: string): string | undefined;
    skippedVersions(connector: string, stream: string): number | undefined;
  },
  importedFrom: ReadonlyMap<string, string>,
  streams: readonly { connector: string; stream: string; outcome: string }[],
  signal: AbortSignal,
): Promise<number> {
  let removed = 0;
  const statusOf = new Map<string, Awaited<ReturnType<SeedIntake["status"]>>>();
  for (const s of streams) {
    if (signal.aborted) break;
    if (s.outcome !== "staged" && s.outcome !== "merged") continue;
    let status = statusOf.get(s.connector);
    if (!status) {
      status = await intake.status(s.connector);
      statusOf.set(s.connector, status);
    }
    if (status.streams[s.stream]?.state !== "merged") continue;
    const scope = store.scopeOf(s.connector, s.stream);
    if (scope === undefined) continue;
    // Only the scope this runner imported the stream from may go, and only
    // when every stored version of it was offered for import.
    if (importedFrom.get(JSON.stringify([s.connector, s.stream])) !== scope)
      continue;
    if (store.skippedVersions(s.connector, s.stream) !== 0) continue;
    await options.storage.deleteScope(scope);
    removed += 1;
  }
  return removed;
}
