import { sha256 } from "@noble/hashes/sha2";
import type { StreamSyncReadStatus } from "../stream-sync-read/service.js";
import { logicalStreamScopeParts } from "../stream-sync-read/routing.js";
import type { LocalSyncDeps } from "./deps.js";
import {
  createOlderVersions,
  type OlderVersionCounts,
} from "./older-versions.js";
import { createRecordQuery } from "./query.js";
import {
  createLocalResolver,
  type AliasScopes,
  type AliasTargets,
} from "./resolve.js";

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
 * listing is filtered by `canRead` FIRST (grant filter); a scope whose check
 * throws is skipped and logged; the owner's local-only scopes are included; an
 * alias is listed only if its body can be built; the cache key changes on any
 * control-row change. `status()` is `StreamSyncReadStatus` plus the D.3 counts.
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

export function createLocalListing(
  deps: LocalSyncDeps & {
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
  },
  counts: () => OlderVersionCounts,
): LocalListing {
  // Construct the read path only after the first successful grant check.
  const latest = (aliasNames: readonly string[]) =>
    createLocalResolver(deps, {
      query: createRecordQuery(deps.db),
      // ResolveInput has no historical selector: listing probes latest only.
      olderVersions: createOlderVersions(deps, { enabled: () => false }),
      aliasScopes: () => aliasNames,
      aliasTargets: deps.aliasTargets,
    });

  const connections = () =>
    deps.db.query<Connection>(
      "SELECT connection_id, connector, ns, generation, control_state FROM connections ORDER BY connector, ns, connection_id",
    );

  return {
    async listScopes({ canRead }) {
      const known = new Set((await connections()).map((row) => row.connector));
      const streams = await deps.db.query<{
        connector: string;
        stream: string;
      }>(
        "SELECT DISTINCT c.connector, s.stream FROM connections c JOIN stream_state s ON s.connection_id = c.connection_id ORDER BY c.connector, s.stream",
      );
      const candidates = new Set(
        streams.map((row) => `pdpp.${row.connector}.${row.stream}`),
      );
      const aliasNames = [...(deps.aliasScopes?.() ?? [])];
      const targets = (scope: string) => {
        const logical = logicalStreamScopeParts(scope);
        return logical
          ? [{ connector: logical.connector, streams: [logical.stream] }]
          : (deps.aliasTargets?.(scope) ?? []);
      };
      for (const scope of aliasNames) {
        if (targets(scope).some((target) => known.has(target.connector))) {
          candidates.add(scope);
        }
      }

      const out: ListedScope[] = [];
      let resolver: ReturnType<typeof createLocalResolver> | undefined;
      for (const scope of [...candidates].sort()) {
        try {
          if (!(await canRead(scope))) continue;
          const decision = await (resolver ??= latest(aliasNames)).resolve({
            scope,
            connection: null,
            cursor: null,
            legacyFile: false,
            isOwnerView: true,
          });
          if (decision.kind !== "view" && decision.kind !== "local_pending") {
            continue;
          }
          // Projection can fail lazily. Drain without retaining record bytes,
          // and let the resolver release its snapshot before listing the scope.
          const reader = decision.body.getReader();
          try {
            while (!(await reader.read()).done) {
              // Discard each chunk.
            }
          } finally {
            reader.releaseLock();
          }
          const target = targets(scope).find(
            (entry) => entry.connector === decision.connector,
          );
          if (!target || target.streams.length === 0) continue;
          const placeholders = target.streams.map(() => "?").join(", ");
          const params = [decision.connector, decision.ns, ...target.streams];
          const [records] = await deps.db.query<{
            records: number;
            updated_at: number | null;
          }>(
            `SELECT COUNT(*) AS records, MAX(r.stamp_o) AS updated_at FROM records r JOIN connections c ON c.connection_id = r.connection_id WHERE c.connector = ? AND c.ns = ? AND r.stream IN (${placeholders})`,
            params,
          );
          const [head] = await deps.db.query<{ updated_at: number | null }>(
            `SELECT MAX(v.observed_at) AS updated_at FROM connections c JOIN stream_state s ON s.connection_id = c.connection_id JOIN stream_versions v ON v.connection_id = s.connection_id AND v.stream = s.stream AND v.version = s.head_version AND v.generation = c.generation WHERE c.connector = ? AND c.ns = ? AND s.stream IN (${placeholders})`,
            params,
          );
          const times = [records?.updated_at, head?.updated_at].filter(
            (time): time is number => typeof time === "number",
          );
          out.push({
            scope,
            connector: decision.connector,
            ns: decision.ns,
            records: logicalStreamScopeParts(scope)
              ? (records?.records ?? 0)
              : null,
            updatedAt: times.length === 0 ? null : Math.max(...times),
          });
        } catch {
          // Exceptions may embed record contents or keys; never log them.
          deps.logger.warn({ scope }, "localdb listing: scope check failed");
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
