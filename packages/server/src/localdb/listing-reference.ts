import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { ListedScope } from "../../../core/src/localdb/listing.js";
import { createOlderVersions } from "../../../core/src/localdb/older-versions.js";
import { seenStamp } from "../../../core/src/localdb/merge.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import {
  createLocalResolver,
  type AliasScopes,
  type AliasTargets,
} from "../../../core/src/localdb/resolve.js";
import { logicalStreamScopeParts } from "../../../core/src/stream-sync-read/routing.js";

/**
 * The scope listing as it was before it answered from local state alone: one
 * resolver read per candidate scope, each drained to the end. It is the oracle
 * the bounded listing is compared against, so keep it as it was.
 */
export async function referenceListScopes(
  deps: LocalSyncDeps & {
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
  },
  canRead: (scope: string) => boolean | Promise<boolean>,
): Promise<ListedScope[]> {
  const aliasNames = [...(deps.aliasScopes?.() ?? [])];
  const resolver = createLocalResolver(deps, {
    query: createRecordQuery(deps.db),
    olderVersions: createOlderVersions(deps, { enabled: () => false }),
    aliasScopes: () => aliasNames,
    aliasTargets: deps.aliasTargets,
  });
  const known = new Set(
    (
      await deps.db.query<{ connector: string }>(
        "SELECT connector FROM connections",
      )
    ).map((row) => row.connector),
  );
  const streams = await deps.db.query<{ connector: string; stream: string }>(
    "SELECT DISTINCT c.connector, s.stream FROM connections c JOIN stream_state s ON s.connection_id = c.connection_id ORDER BY c.connector, s.stream",
  );
  const candidates = new Set(
    streams.map((row) => `pdpp.${row.connector}.${row.stream}`),
  );
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
  for (const scope of [...candidates].sort()) {
    if (!(await canRead(scope))) continue;
    const decision = await resolver.resolve({
      scope,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    if (decision.kind !== "view" && decision.kind !== "local_pending") continue;
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
      `SELECT COUNT(*) AS records, MAX(${seenStamp("r.").o}) AS updated_at FROM records r JOIN connections c ON c.connection_id = r.connection_id WHERE c.connector = ? AND c.ns = ? AND r.stream IN (${placeholders})`,
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
      records: logicalStreamScopeParts(scope) ? (records?.records ?? 0) : null,
      updatedAt: times.length === 0 ? null : Math.max(...times),
    });
  }
  return out;
}
