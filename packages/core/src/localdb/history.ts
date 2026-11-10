import {
  ADDITIONS_BUCKET_MS,
  ADDITIONS_FINE_DAYS,
  bucketAdditionsByLocalDay,
  type AdditionsSummary,
} from "../additions/summary.js";
import type { LocalSyncDeps } from "./deps.js";

/** 404 (`not_found`) and 410 (`deleted`) as the other D.1 reads answer them. */
export type HistoryResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly reason: "not_found" | "deleted" };

/** One `/versions` item: the six fields of the legacy contract. */
export interface HistoryVersionItem {
  /** `stream_versions.head_blob`. */
  readonly fileId: string | null;
  readonly schemaId: null;
  /** ISO string of the writer's `observed_at`, never import or registry time. */
  readonly collectedAt: string;
  readonly version: number;
  readonly producer: null;
  readonly producer_provenance: null;
}

export interface HistoryVersionsPage {
  readonly scope: string;
  readonly versions: readonly HistoryVersionItem[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
}

/** `/lineage` on a switched owner: no sources, by construction (r5.2 1.6). */
export interface HistoryLineage {
  readonly scope: string;
  readonly version: number;
  readonly sources: readonly [];
  /** Shape confirmed against the legacy lineage function (r5.2 Doubt 3). */
  readonly proof: unknown;
}

/**
 * r5.2 1.4-1.6: `/additions`, `/:scope/versions` and `/:scope/lineage` served
 * from the database (`records`, `stream_state`, `stream_versions`,
 * `connections`) before any account switches. Never opens a legacy store and
 * names no connector. Route code calls it after the existing auth.
 */
export interface LocalHistory {
  /** `partial` is always false; rows with unknown `first_o` count in `total` only. */
  additions(input: {
    readonly timezone: string;
    readonly days: number;
  }): Promise<AdditionsSummary>;
  versions(input: {
    readonly scope: string;
    readonly limit: number;
    readonly offset: number;
  }): Promise<HistoryResult<HistoryVersionsPage>>;
  lineage(input: {
    readonly scope: string;
    readonly version?: number;
  }): Promise<HistoryResult<HistoryLineage>>;
}

const UTC_DAY_MS = 24 * 60 * 60 * 1000;

type Counts = {
  total: number;
  first: number | null;
  buckets: Map<number, number>;
  daily: Map<number, number>;
};

const newCounts = (): Counts => ({
  total: 0,
  first: null,
  buckets: new Map(),
  daily: new Map(),
});

const sortedBuckets = (counts: Counts): AdditionsSummary["buckets"] =>
  [...counts.buckets]
    .sort(([a], [b]) => a - b)
    .map(([at, added]) => ({ start: new Date(at).toISOString(), added }));

const sortedDaily = (counts: Counts): AdditionsSummary["daily"] =>
  [...counts.daily]
    .sort(([a], [b]) => a - b)
    .map(([at, added]) => ({
      date: new Date(at).toISOString().slice(0, 10),
      added,
    }));

const trackedSince = (counts: Counts): string | null =>
  counts.first === null ? null : new Date(counts.first).toISOString();

export function createLocalHistory(
  deps: LocalSyncDeps,
  options: {
    /** The `olderVersionReads` server config value, read at each call (default true). */
    readonly olderVersionReads: () => boolean;
    /** Registry freshness is not persisted by the current local database schema. */
    readonly behind?: (connectionId: string) => boolean;
  },
): LocalHistory {
  return {
    async additions({ timezone, days }) {
      if (!Number.isInteger(days) || days < 1 || days > 31) {
        throw new RangeError("days must be an integer from 1 to 31");
      }
      const now = new Date(deps.now());
      // Validate the timezone before querying and reuse calendar-day arithmetic.
      bucketAdditionsByLocalDay([], timezone, days, now);
      const fineSinceAt =
        Math.floor(now.getTime() / UTC_DAY_MS) * UTC_DAY_MS -
        ADDITIONS_FINE_DAYS * UTC_DAY_MS;

      // One statement keeps rows, control visibility and frontiers in one
      // committed snapshot, including a connection deleted in a single batch.
      const rows = await deps.db.query<{
        connection_id: string;
        connector: string;
        stream: string | null;
        first_o: number | null;
        row_count: number;
        head_version: number | null;
      }>(`
SELECT c.connection_id, c.connector, s.stream, NULL AS first_o,
       0 AS row_count, s.head_version
FROM connections c
LEFT JOIN stream_state s ON s.connection_id = c.connection_id
WHERE c.control_state = 'active'
UNION ALL
SELECT c.connection_id, c.connector, r.stream, r.first_o,
       COUNT(*) AS row_count, NULL AS head_version
FROM records r
JOIN connections c ON c.connection_id = r.connection_id
WHERE c.control_state = 'active'
GROUP BY c.connection_id, c.connector, r.stream, r.first_o`);

      const all = newCounts();
      const scopes = new Map<string, Counts>();
      const heads = new Map<string, number>();
      const connections = new Set<string>();
      // These carry exact instants, not rounded bucket starts. This preserves
      // exact local dates even before the fine-bucket cutoff.
      const arrivals: AdditionsSummary["buckets"] = [];
      const add = (counts: Counts, first: number | null, amount: number) => {
        counts.total += amount;
        if (first === null || amount === 0) return;
        counts.first =
          counts.first === null ? first : Math.min(counts.first, first);
        const bucket =
          Math.floor(first / ADDITIONS_BUCKET_MS) * ADDITIONS_BUCKET_MS;
        const target = bucket >= fineSinceAt ? counts.buckets : counts.daily;
        const at =
          bucket >= fineSinceAt
            ? bucket
            : Math.floor(first / UTC_DAY_MS) * UTC_DAY_MS;
        target.set(at, (target.get(at) ?? 0) + amount);
      };

      for (const row of rows) {
        connections.add(row.connection_id);
        if (row.stream === null) continue;
        const scope = `${row.connector}.${row.stream}`;
        let counts = scopes.get(scope);
        if (!counts) {
          counts = newCounts();
          scopes.set(scope, counts);
        }
        if (row.head_version !== null) {
          heads.set(scope, Math.max(heads.get(scope) ?? 0, row.head_version));
        }
        add(counts, row.first_o, row.row_count);
        add(all, row.first_o, row.row_count);
        if (row.first_o !== null && row.row_count > 0) {
          arrivals.push({
            start: new Date(row.first_o).toISOString(),
            added: row.row_count,
          });
        }
      }

      return {
        version: 1,
        coverage: [...connections].some((id) => options.behind?.(id) === true)
          ? "behind"
          : "complete",
        through: Object.fromEntries(
          [...heads]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([scope, version]) => [scope, String(version)]),
        ),
        fineSince: new Date(fineSinceAt).toISOString(),
        daily: sortedDaily(all),
        buckets: sortedBuckets(all),
        timezone,
        total: all.total,
        days: bucketAdditionsByLocalDay(arrivals, timezone, days, now),
        trackedSince: trackedSince(all),
        partial: false,
        scopes: [...scopes]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([scope, counts]) => ({
            scope,
            total: counts.total,
            daily: sortedDaily(counts),
            buckets: sortedBuckets(counts),
            trackedSince: trackedSince(counts),
            partial: false,
          })),
      };
    },
    async versions({ scope, limit, offset }) {
      // Logical scopes name the identity-less namespace; physical scopes
      // additionally identify the namespace stored on the connection.
      const name = scope.startsWith("pdpp.") ? scope.slice(5) : scope;
      const match = /^([^.~]+)(?:~([a-f0-9]{16}|))?\.(.+)$/.exec(name);
      const connector = match?.[1];
      const stream = match?.[3];
      if (!connector || !stream) return { ok: false, reason: "not_found" };
      const [connection] = await deps.db.query<{
        connection_id: string;
        generation: number;
        control_state: string;
      }>(
        "SELECT connection_id, generation, control_state FROM connections WHERE connector = ? AND ns = ? ORDER BY connection_id LIMIT 1",
        [connector, match?.[2] ?? ""],
      );
      if (!connection) return { ok: false, reason: "not_found" };
      if (connection.control_state === "deleted") {
        return { ok: false, reason: "deleted" };
      }
      const [state] = await deps.db.query<{ head_version: number }>(
        "SELECT head_version FROM stream_state WHERE connection_id = ? AND stream = ?",
        [connection.connection_id, stream],
      );
      if (!state) return { ok: false, reason: "not_found" };

      const params = [
        connection.connection_id,
        stream,
        connection.generation,
        options.olderVersionReads() ? 1 : 0,
        state.head_version,
      ];
      const predicate =
        "connection_id = ? AND stream = ? AND generation = ? AND kind IN ('published', 'applied') AND (? = 1 OR version = ?)";
      const [count] = await deps.db.query<{ total: number }>(
        "SELECT COUNT(*) AS total FROM stream_versions WHERE " + predicate,
        params,
      );
      const rows = await deps.db.query<{
        head_blob: string;
        observed_at: number;
        version: number;
      }>(
        "SELECT head_blob, observed_at, version FROM stream_versions WHERE " +
          predicate +
          " ORDER BY version DESC LIMIT ? OFFSET ?",
        [...params, limit, offset],
      );
      return {
        ok: true,
        value: {
          scope,
          versions: rows.map((row) => ({
            fileId: row.head_blob,
            schemaId: null,
            collectedAt: new Date(row.observed_at).toISOString(),
            version: row.version,
            producer: null,
            producer_provenance: null,
          })),
          total: count?.total ?? 0,
          limit,
          offset,
        },
      };
    },
    async lineage({ scope, version }) {
      const name = scope.startsWith("pdpp.") ? scope.slice(5) : scope;
      const match = /^([^.~]+)(?:~([a-f0-9]{16}|))?\.(.+)$/.exec(name);
      const connector = match?.[1];
      const stream = match?.[3];
      if (!connector || !stream) return { ok: false, reason: "not_found" };
      const [connection] = await deps.db.query<{
        connection_id: string;
        generation: number;
        control_state: string;
      }>(
        "SELECT connection_id, generation, control_state FROM connections WHERE connector = ? AND ns = ? ORDER BY connection_id LIMIT 1",
        [connector, match?.[2] ?? ""],
      );
      if (!connection) return { ok: false, reason: "not_found" };
      if (connection.control_state === "deleted") {
        return { ok: false, reason: "deleted" };
      }
      const [state] = await deps.db.query<{
        head_version: number;
        head_generation: number | null;
      }>(
        "SELECT head_version, head_generation FROM stream_state WHERE connection_id = ? AND stream = ?",
        [connection.connection_id, stream],
      );
      if (!state) return { ok: false, reason: "not_found" };
      const selected = version ?? state.head_version;
      if (version === undefined) {
        if (selected <= 0 || state.head_generation !== connection.generation) {
          return { ok: false, reason: "not_found" };
        }
      } else {
        const [retained] = await deps.db.query<{ version: number }>(
          "SELECT version FROM stream_versions WHERE connection_id = ? AND stream = ? AND generation = ? AND version = ? AND kind IN ('published', 'applied')",
          [connection.connection_id, stream, connection.generation, selected],
        );
        if (!retained) return { ok: false, reason: "not_found" };
      }
      // The gateway proof requires gateway/user signatures unavailable in
      // this database. A local root has no sources and no fabricated proof.
      return {
        ok: true,
        value: { scope, version: selected, sources: [], proof: null },
      };
    },
  };
}
