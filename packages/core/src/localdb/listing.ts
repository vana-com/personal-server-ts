import { sha256 } from "@noble/hashes/sha2";
import type { StreamSyncReadStatus } from "../stream-sync-read/service.js";
import { logicalStreamScopeParts } from "../stream-sync-read/routing.js";
import type { LocalSyncDeps } from "./deps.js";
import type { OlderVersionCounts } from "./older-versions.js";
import { createRecordQuery } from "./query.js";
import {
  chooseCandidate,
  loadStreams,
  projectAlias,
  selectForTarget,
  type Candidate,
  type Connection as SelectionConnection,
  type Stream,
  type Target,
} from "./read-selection.js";
import type { AliasScopes, AliasTargets } from "./resolve.js";

/** One listed scope of `GET /v1/data` (D.2). */
export interface ListedScope {
  readonly scope: string;
  readonly connector: string;
  readonly ns: string;
  readonly records: number | null;
  readonly updatedAt: number | null;
}

/**
 * D.2 listing and D.4 status, from `connections` + `stream_state`. The
 * listing answers from local state only, in a fixed number of queries: it
 * applies the resolver's selection rule (`read-selection.ts`) to what is
 * stored now and never applies registry heads, fetches blobs or reads a
 * record body. Bringing local state up to date is the sync loop's job. Every
 * scope is filtered by `canRead` FIRST (grant filter); a scope whose check
 * throws is skipped and logged; an alias is listed only if its installed
 * records project (checked after the grant filter); overlapping calls share
 * one in-flight read of local state; the cache key changes on any control-row
 * change. `status()` is `StreamSyncReadStatus` plus the D.3 counts.
 */
export interface LocalListing {
  listScopes(input: {
    readonly canRead: (scope: string) => boolean | Promise<boolean>;
  }): Promise<readonly ListedScope[]>;
  status(): Promise<
    StreamSyncReadStatus & { readonly olderVersionReads: OlderVersionCounts }
  >;
  /** Changes whenever any control row or stream head changes. */
  cacheKey(): Promise<string>;
}

type Connection = {
  connection_id: string;
  connector: string;
  ns: string;
  generation: number;
  control_state: "absent" | "active" | "deleted" | "foreign";
};

type StreamState = {
  connection_id: string;
  stream: string;
  complete: number;
  head_version: number;
  head_generation: number | null;
  head_blob: string | null;
  last_delete_version: number;
  records: number;
};

/** One candidate scope, computed from local state; `canRead` is not applied. */
interface Entry {
  readonly scope: string;
  /** Null when a read of the scope would serve nothing. */
  readonly listed: ListedScope | null;
  /** Memoized for the snapshot: can the alias body be built from local records? */
  readonly bodyBuilds: () => Promise<boolean>;
}

type Count = { records: number; stampedAt: number | null };

export function createLocalListing(
  deps: LocalSyncDeps & {
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
  },
  counts: () => OlderVersionCounts,
): LocalListing {
  const connections = () =>
    deps.db.query<Connection>(
      "SELECT connection_id, connector, ns, generation, control_state FROM connections ORDER BY connector, ns, connection_id",
    );

  /**
   * Everything `listScopes` needs short of `canRead`, read from local state:
   * five queries however many scopes there are. Nothing here depends on the
   * caller's authority, so overlapping callers share one.
   */
  async function readSnapshot(): Promise<readonly Entry[]> {
    const rows = await deps.db.query<SelectionConnection>(
      "SELECT connection_id, connector, ns, generation, control_state, deleted_at FROM connections ORDER BY connector, ns, connection_id",
    );
    const streams = await loadStreams(deps);
    const stamps = await deps.db.query<{
      connection_id: string;
      stream: string;
      records: number;
      stamped_at: number | null;
    }>(
      "SELECT connection_id, stream, COUNT(*) AS records, MAX(stamp_o) AS stamped_at FROM records GROUP BY connection_id, stream",
    );
    const heads = await deps.db.query<{
      connection_id: string;
      stream: string;
      observed_at: number;
    }>(
      "SELECT s.connection_id, s.stream, v.observed_at FROM connections c JOIN stream_state s ON s.connection_id = c.connection_id JOIN stream_versions v ON v.connection_id = s.connection_id AND v.stream = s.stream AND v.version = s.head_version AND v.generation = c.generation",
    );

    const streamsOf = new Map<string, Stream[]>();
    for (const stream of streams) {
      const list = streamsOf.get(stream.connection_id) ?? [];
      list.push(stream);
      streamsOf.set(stream.connection_id, list);
    }
    const byConnector = new Map<string, SelectionConnection[]>();
    for (const row of rows) {
      const list = byConnector.get(row.connector) ?? [];
      list.push(row);
      byConnector.set(row.connector, list);
    }
    // Per connector, namespace and stream, as the old per-scope queries joined
    // `connections` on connector and namespace.
    const key = (c: { connector: string; ns: string }, stream: string) =>
      JSON.stringify([c.connector, c.ns, stream]);
    const connectionById = new Map(rows.map((c) => [c.connection_id, c]));
    const recordTotals = new Map<string, Count>();
    for (const row of stamps) {
      const c = connectionById.get(row.connection_id);
      if (!c) continue;
      const total = recordTotals.get(key(c, row.stream)) ?? {
        records: 0,
        stampedAt: null,
      };
      total.records += row.records;
      if (row.stamped_at !== null) {
        total.stampedAt = Math.max(
          total.stampedAt ?? row.stamped_at,
          row.stamped_at,
        );
      }
      recordTotals.set(key(c, row.stream), total);
    }
    const headTimes = new Map<string, number>();
    for (const row of heads) {
      const c = connectionById.get(row.connection_id);
      if (!c) continue;
      headTimes.set(
        key(c, row.stream),
        Math.max(
          headTimes.get(key(c, row.stream)) ?? row.observed_at,
          row.observed_at,
        ),
      );
    }

    const candidates = new Set<string>();
    for (const c of rows) {
      for (const stream of streamsOf.get(c.connection_id) ?? []) {
        candidates.add(`pdpp.${c.connector}.${stream.stream}`);
      }
    }
    const aliasNames = new Set(deps.aliasScopes?.() ?? []);
    const targets = (scope: string): readonly Target[] => {
      const logical = logicalStreamScopeParts(scope);
      if (logical) {
        return [{ connector: logical.connector, streams: [logical.stream] }];
      }
      if (!aliasNames.has(scope)) return [];
      return (deps.aliasTargets?.(scope) ?? []).map((alias) => ({
        connector: alias.connector,
        streams: alias.streams,
        alias,
      }));
    };
    for (const scope of aliasNames) {
      const logical = logicalStreamScopeParts(scope);
      const wanted = logical
        ? [logical.connector]
        : (deps.aliasTargets?.(scope) ?? []).map((t) => t.connector);
      if (wanted.some((connector) => byConnector.has(connector))) {
        candidates.add(scope);
      }
    }

    const entries: Entry[] = [];
    for (const scope of [...candidates].sort()) {
      const picks: Candidate[] = [];
      for (const target of targets(scope)) {
        const picked = selectForTarget(
          target,
          (byConnector.get(target.connector) ?? []).map((connection) => ({
            connection,
            streams: streamsOf.get(connection.connection_id) ?? [],
          })),
        );
        if (picked.candidate) picks.push(picked.candidate);
      }
      const chosen = chooseCandidate(picks);
      const target = chosen
        ? targets(scope).find(
            (entry) => entry.connector === chosen.connection.connector,
          )
        : undefined;
      if (!chosen || !target || target.streams.length === 0) {
        entries.push({ scope, listed: null, bodyBuilds: async () => false });
        continue;
      }
      const owner = chosen.connection;
      let records = 0;
      const times: number[] = [];
      for (const stream of target.streams) {
        const total = recordTotals.get(key(owner, stream));
        records += total?.records ?? 0;
        if (total?.stampedAt != null) times.push(total.stampedAt);
        const head = headTimes.get(key(owner, stream));
        if (head !== undefined) times.push(head);
      }
      let projection: Promise<boolean> | undefined;
      entries.push({
        scope,
        listed: {
          scope,
          connector: owner.connector,
          ns: owner.ns,
          records: logicalStreamScopeParts(scope) ? records : null,
          updatedAt: times.length === 0 ? null : Math.max(...times),
        },
        bodyBuilds: () => (projection ??= aliasBodyBuilds(target, chosen)),
      });
    }
    return entries;
  }

  /**
   * Can a read build this alias body from the records installed now? A read
   * whose installed head lags the newest complete head would fetch the
   * retained head over the network; the listing does not, so it lists the
   * scope without projecting.
   */
  async function aliasBodyBuilds(
    target: Target,
    chosen: Candidate,
  ): Promise<boolean> {
    if (!target.alias) return true;
    if (chosen.streams.some((s) => s.head_version !== s.installed_version)) {
      return true;
    }
    const projected = await projectAlias(
      target.alias,
      chosen,
      createRecordQuery(deps.db),
      new Date(deps.now()).toISOString(),
    );
    return projected.kind === "ok";
  }

  // Overlapping calls share one read of local state; the next call after it
  // settles starts a new one, so nothing is served from a cache.
  let inflight: Promise<readonly Entry[]> | undefined;
  const snapshot = () => {
    const running = (inflight ??= readSnapshot().finally(() => {
      if (inflight === running) inflight = undefined;
    }));
    return running;
  };

  return {
    async listScopes({ canRead }) {
      const out: ListedScope[] = [];
      for (const entry of await snapshot()) {
        try {
          if (!(await canRead(entry.scope))) continue;
          if (!entry.listed || !(await entry.bodyBuilds())) continue;
          out.push(entry.listed);
        } catch {
          // Exceptions may embed record contents or keys; never log them.
          deps.logger.warn(
            { scope: entry.scope },
            "localdb listing: scope check failed",
          );
        }
      }
      return out;
    },

    async status() {
      const rows = await connections();
      const states = await deps.db.query<StreamState>(
        "SELECT s.*, (SELECT COUNT(*) FROM records r WHERE r.connection_id = s.connection_id AND r.stream = s.stream) AS records FROM stream_state s ORDER BY s.connection_id, s.stream",
      );
      const result: StreamSyncReadStatus["connections"][number][] = [];
      for (const row of rows) {
        const streams: Record<
          string,
          StreamSyncReadStatus["connections"][number]["streams"][string]
        > = {};
        for (const state of states) {
          if (state.connection_id !== row.connection_id) continue;
          const tombstoned =
            state.last_delete_version > 0 &&
            state.head_version <= state.last_delete_version;
          const live =
            row.control_state === "active" &&
            state.head_generation === row.generation &&
            state.head_version > state.last_delete_version &&
            state.head_blob !== null;
          streams[state.stream] = {
            tombstoned,
            live,
            complete: live && state.complete === 1,
            version: live ? state.head_version : null,
            records: live ? state.records : null,
          };
        }
        result.push({
          connector: row.connector,
          ns: row.ns,
          control: row.control_state,
          streams,
        });
      }
      // An open local database is the listing source. Import issues are not
      // persisted by this schema; historical-read counters belong to the caller.
      return {
        listed: true,
        connections: result,
        issues: [],
        olderVersionReads: counts(),
      };
    },

    async cacheKey() {
      // Include every column, not only a control version or the newest head:
      // local edits, deletions and changes to unselected connections count too.
      const controls = await deps.db.query(
        "SELECT * FROM connections ORDER BY connection_id",
      );
      const heads = await deps.db.query(
        "SELECT * FROM stream_state ORDER BY connection_id, stream",
      );
      const digest = sha256(
        new TextEncoder().encode(JSON.stringify([controls, heads])),
      );
      return Array.from(digest, (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
    },
  };
}
