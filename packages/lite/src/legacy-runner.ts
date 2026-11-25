import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  legacyAliasScopes,
  legacySourceId,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import {
  createLegacyScopeStore,
  isConnectionDeleted,
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
}

export interface LiteLegacyStoreRunner extends ImportRunner {
  /** The last finished run's report, or null before one has finished. */
  report(): LiteLegacyImportReport | null;
}

export interface LiteLegacyStoreRunnerOptions {
  /** The raw legacy storage: stored bodies, not their projected views. */
  readonly storage: Pick<
    DataStoragePort,
    "listScopes" | "listVersions" | "readEnvelope"
  >;
  /** The runtime's own seed intake, once it exists. Waits, or throws if the
   * runtime has none. */
  readonly intake: () => Promise<SeedIntake>;
  /** Verified manifest documents, read at each run. */
  readonly manifests: () => Iterable<string>;
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
      const binding =
        alternateLegacyBindingsForScope(scope).get(alias.connector) ??
        LEGACY_SCOPE_BINDINGS.get(scope);
      const sourceId = binding && legacySourceId(binding.pdppSource);
      const target = (stream: string): LegacyScopeTarget => ({
        connector: alias.connector,
        stream,
        ...(sourceId ? { sourceId } : {}),
      });
      for (const stream of alias.streams)
        add(`${source}.${stream}`, target(stream));
      if (alias.streams.length === 1) add(scope, target(alias.streams[0]!));
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
 * receipts and its fill-only rules apply as for any seed. Import only: this
 * runner never removes a legacy scope.
 *
 * A failed run (no intake, a read fault) imports what the importer already
 * accepted; the waker logs it and runs again at the next Account answer or
 * start. Shutdown aborts the run.
 */
export function createLiteLegacyStoreRunner(
  options: LiteLegacyStoreRunnerOptions,
): LiteLegacyStoreRunner {
  let last: LiteLegacyImportReport | null = null;
  const targets = streamScopeTargets();
  return {
    report: () => last,
    async run(signal) {
      const intake = await options.intake();
      const excluded = tally<LegacyScopeExclusionReason>();
      const deleted = new Set<string>();
      const refused = tally<string>();
      const store = createLegacyScopeStore({
        storage: options.storage,
        manifests: options.manifests,
        targets,
        onExcluded: ({ reason }) => excluded.add(reason),
        receipt: async (connector, stream) => {
          if (deleted.has(connector)) {
            refused.add("deleted");
            return "leave";
          }
          // Read fresh under the intake's own lock, so a seed upload that
          // arrived since the last stream is seen before this one is put.
          let status: Awaited<ReturnType<SeedIntake["status"]>>;
          try {
            status = await intake.status(connector);
          } catch (error) {
            // A deleted connector refuses its own streams only; its scope
            // stays and the other connectors go on.
            if (!isConnectionDeleted(error)) throw error;
            deleted.add(connector);
            refused.add("deleted");
            return "leave";
          }
          const state = status.streams[stream]?.state;
          if (state === "merged") return "final";
          // An upload waiting for its target is never replaced by a legacy seed.
          if (state === "staged") {
            refused.add("staged_upload_pending");
            return "leave";
          }
          return "open";
        },
        connectorDeleted: async (connector) => {
          if (deleted.has(connector)) return true;
          try {
            await intake.status(connector);
          } catch (error) {
            if (!isConnectionDeleted(error)) return false;
            deleted.add(connector);
            return true;
          }
          return false;
        },
        signal,
      });
      // The rows of each stream's newest stored version, counted as the
      // producer first read them to the end. A refused stream is tallied from
      // this, never from a second read: its envelopes may be gone by then.
      const offered = new Map<string, LegacySeedStream>();
      const rowsRead = new Map<string, number>();
      const recording: LegacySeedStore = {
        async *streams() {
          for await (const stream of store.streams()) {
            const key = JSON.stringify([stream.connector, stream.stream]);
            offered.set(key, stream);
            const [newest, ...older] = stream.layers;
            if (!newest) {
              yield stream;
              continue;
            }
            yield {
              ...stream,
              layers: [
                {
                  async *records() {
                    let n = 0;
                    for await (const row of newest.records()) {
                      n += 1;
                      yield row;
                    }
                    if (!rowsRead.has(key)) rowsRead.set(key, n);
                  },
                },
                ...older,
              ],
            };
          }
        },
      };
      const seeded = await seedLegacyStore(intake, recording, { signal });
      if (signal.aborted) return;
      let refusedRows = 0;
      let staged = 0;
      let merged = 0;
      let empty = 0;
      for (const s of seeded.streams) {
        if (s.outcome === "staged") staged += 1;
        else if (s.outcome === "merged") merged += 1;
        else if (s.outcome === "empty") empty += 1;
        else {
          const key = JSON.stringify([s.connector, s.stream]);
          let rows = rowsRead.get(key) ?? 0;
          // Never read to the end (refused before its read): count it now,
          // unless its envelope is gone.
          const layer = offered.get(key)?.layers[0];
          if (layer && !rowsRead.has(key)) {
            try {
              for await (const _ of layer.records()) rows += 1;
            } catch (error) {
              if (!isConnectionDeleted(error)) throw error;
              rows = 0;
            }
          }
          refused.add(s.reason ?? "refused", rows);
          refusedRows += rows;
        }
      }
      const quarantined = seeded.quarantine;
      const legacy =
        seeded.rows +
        Object.values(quarantined).reduce((a, b) => a + b, 0) +
        refusedRows;
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
      };
    },
  };
}
