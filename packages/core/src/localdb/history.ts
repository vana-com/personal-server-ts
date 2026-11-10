import {
  ADDITIONS_BUCKET_MS,
  ADDITIONS_FINE_DAYS,
  bucketAdditionsByLocalDay,
  type AdditionsSummary,
} from "../additions/summary.js";
import { ProtocolError } from "../errors/catalog.js";
import type { LocalSyncDeps } from "./deps.js";

export const HISTORY_PAGE_LIMIT = 1000;

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
  /** Exclusive version cursor for the next page, or null when exhausted. */
  readonly nextCursor: number | null;
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
    /** Only zero is accepted; continue with cursor instead of an offset. */
    readonly offset: number;
    readonly cursor?: number;
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
        throw new ProtocolError(
          400,
          "invalid_request",
          "days must be an integer from 1 to 31",
        );
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
    async versions({ scope, limit, offset, cursor }) {
      if (
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        !Number.isSafeInteger(offset) ||
        offset !== 0 ||
        (cursor !== undefined && (!Number.isSafeInteger(cursor) || cursor < 1))
      ) {
        throw new ProtocolError(
          400,
          "invalid_request",
          "Use a positive safe limit and cursor; offset must be zero",
        );
      }
      limit = Math.min(limit, HISTORY_PAGE_LIMIT);
      const name = scope.startsWith("pdpp.") ? scope.slice(5) : scope;
      const match = /^([^.~]+)(?:~([a-f0-9]{16}|))?\.(.+)$/.exec(name);
      const connector = match?.[1];
      const stream = match?.[3];
      if (!connector || !stream) return { ok: false, reason: "not_found" };
      // One statement gives control, frontier, total and page one snapshot.
      const rows = await deps.db.query<{
        control_state: string;
        head_version: number | null;
        total: number;
        head_blob: string | null;
        observed_at: number | null;
        version: number | null;
      }>(
        `WITH context AS (
           SELECT c.connection_id, c.generation, c.control_state,
                  s.head_version, s.last_delete_version
           FROM (SELECT * FROM connections WHERE connector = ? AND ns = ?
                 ORDER BY connection_id LIMIT 1) c
           LEFT JOIN stream_state s ON s.connection_id = c.connection_id
             AND s.stream = ?
         ), visible AS (
           SELECT v.head_blob, v.observed_at, v.version
           FROM context c JOIN stream_versions v
             ON v.connection_id = c.connection_id AND v.stream = ?
           WHERE c.control_state = 'active' AND v.generation = c.generation
             AND v.version > c.last_delete_version
             AND v.kind IN ('published', 'applied')
             AND (? = 1 OR v.version = c.head_version)
         ), page AS (
           SELECT * FROM visible WHERE (? IS NULL OR version < ?)
           ORDER BY version DESC LIMIT ?
         )
         SELECT c.control_state, c.head_version,
                (SELECT COUNT(*) FROM visible) AS total,
                p.head_blob, p.observed_at, p.version
         FROM context c LEFT JOIN page p ON 1 = 1
         ORDER BY p.version DESC`,
        [
          connector,
          match?.[2] ?? "",
          stream,
          stream,
          options.olderVersionReads() ? 1 : 0,
          cursor ?? null,
          cursor ?? null,
          limit + 1,
        ],
      );
      const context = rows[0];
      if (context?.control_state === "deleted") {
        return { ok: false, reason: "deleted" };
      }
      if (context?.control_state !== "active" || context.head_version === null) {
        return { ok: false, reason: "not_found" };
      }
      const versions = rows.filter((row) => row.version !== null);
      const page = versions.slice(0, limit);
      return {
        ok: true,
        value: {
          scope,
          versions: page.map((row) => ({
            fileId: row.head_blob,
            schemaId: null,
            collectedAt: new Date(row.observed_at!).toISOString(),
            version: row.version!,
            producer: null,
            producer_provenance: null,
          })),
          total: context.total,
          limit,
          offset: 0,
          nextCursor:
            versions.length > limit ? page[page.length - 1]!.version : null,
        },
      };
    },
    async lineage({ scope, version }) {
      const name = scope.startsWith("pdpp.") ? scope.slice(5) : scope;
      const match = /^([^.~]+)(?:~([a-f0-9]{16}|))?\.(.+)$/.exec(name);
      const connector = match?.[1];
      const stream = match?.[3];
      if (!connector || !stream) return { ok: false, reason: "not_found" };
      const [row] = await deps.db.query<{
        control_state: string;
        version: number | null;
      }>(
        `SELECT c.control_state, v.version
         FROM (SELECT * FROM connections WHERE connector = ? AND ns = ?
               ORDER BY connection_id LIMIT 1) c
         LEFT JOIN stream_state s ON s.connection_id = c.connection_id
           AND s.stream = ?
         LEFT JOIN stream_versions v ON v.connection_id = c.connection_id
           AND v.stream = s.stream AND v.generation = c.generation
           AND c.control_state = 'active'
           AND v.version = COALESCE(?, s.head_version)
           AND v.version > s.last_delete_version
           AND v.kind IN ('published', 'applied')
           AND (? IS NOT NULL OR s.head_generation = c.generation)`,
        [connector, match?.[2] ?? "", stream, version ?? null, version ?? null],
      );
      if (row?.control_state === "deleted") {
        return { ok: false, reason: "deleted" };
      }
      if (!row || row.version === null) {
        return { ok: false, reason: "not_found" };
      }
      // The gateway proof requires gateway/user signatures unavailable in
      // this database. A local root has no sources and no fabricated proof.
      return {
        ok: true,
        value: { scope, version: row.version, sources: [], proof: null },
      };
    },
  };
}
