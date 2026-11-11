import {
  logicalStreamScopeParts,
  streamReadScope,
} from "../stream-sync-read/routing.js";
import type { LocalSyncDeps } from "./deps.js";
import type { RecordQuery } from "./query.js";
import type {
  AliasTargets,
  LocalAliasRecord,
  LocalAliasTarget,
} from "./resolve.js";

/**
 * The rule that decides which connection and head a read serves, shared by
 * the resolver and the scope listing so the two cannot disagree. Everything
 * here reads local state only: no registry, no blob, no apply.
 */
export type Connection = {
  connection_id: string;
  connector: string;
  ns: string;
  generation: number;
  control_state: string;
  deleted_at: number | null;
};
export type Stream = {
  connection_id: string;
  installed_version: number;
  stream: string;
  profile_key: string | null;
  profile_version: string | null;
  primary_key: string;
  complete: number;
  last_delete_version: number;
  head_version: number;
  head_generation: number | null;
  head_data_hash: string | null;
  head_blob: string | null;
  version: number | null;
  generation: number | null;
  version_blob: string | null;
  version_complete: number | null;
  observed_at: number | null;
  kind: string | null;
};
export type Target = {
  readonly connector: string;
  readonly streams: readonly string[];
  readonly alias?: LocalAliasTarget;
};
export type Candidate = {
  target: Target;
  connection: Connection;
  streams: Stream[];
  registered: number;
};

/**
 * The name rule: which connector streams a scope name reads. A logical
 * stream name (`pdpp.<connector>.<stream>`) names one stream of one
 * connector; a name the host admits as a legacy alias names what the host
 * binds it to; any other name reads nothing. The resolver, the scope listing
 * and the history routes all answer from this one rule, so a name that one
 * lists is a name the others serve.
 */
export function targetsForScope(
  scope: string,
  aliasNames: ReadonlySet<string>,
  aliasTargets: AliasTargets | undefined,
): readonly Target[] {
  const logical = logicalStreamScopeParts(streamReadScope(scope) ?? "");
  if (logical) {
    return [{ connector: logical.connector, streams: [logical.stream] }];
  }
  if (!aliasNames.has(scope)) return [];
  return (aliasTargets?.(scope) ?? []).map((alias) => ({
    connector: alias.connector,
    streams: alias.streams,
    alias,
  }));
}

/** The stream whose head a read of `target` serves: its parent, if windowed. */
export const servedStreamOf = (target: Target): string =>
  target.alias?.servedStream ?? target.streams[0]!;

/** Every connection of one connector, by namespace. */
export function connectionsOf(
  deps: Pick<LocalSyncDeps, "db">,
  connector: string,
): Promise<Connection[]> {
  return deps.db.query<Connection>(
    `SELECT connection_id, connector, ns, generation, control_state, deleted_at
     FROM connections WHERE connector = ? ORDER BY ns`,
    [connector],
  );
}

export const tombstoned = (s: Stream) =>
  s.last_delete_version > 0 && s.head_version <= s.last_delete_version;
export const live = (s: Stream, c: Connection) =>
  c.control_state === "active" &&
  c.deleted_at === null &&
  s.head_version > s.last_delete_version &&
  s.head_generation === c.generation &&
  s.generation === c.generation &&
  s.version === s.head_version &&
  s.kind !== "delete" &&
  s.head_blob !== null &&
  s.version_blob === s.head_blob &&
  s.head_data_hash !== null;
export const complete = (s: Stream, c: Connection) =>
  live(s, c) && s.complete === 1 && s.version_complete === 1;

/**
 * Every stream of one connection (or of all connections) with its newest
 * complete head above the deletion floor.
 */
export function loadStreams(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId?: string,
): Promise<Stream[]> {
  return deps.db.query<Stream>(
    `SELECT s.connection_id, s.head_version AS installed_version, s.stream, s.profile_key, s.profile_version, s.primary_key,
              coalesce(v.complete, 0) AS complete, s.last_delete_version, coalesce(v.version, s.head_version) AS head_version,
              v.generation AS head_generation, s.head_data_hash, v.head_blob,
              v.version, v.generation, v.head_blob AS version_blob,
              v.complete AS version_complete, v.observed_at, v.kind
       FROM stream_state s
       LEFT JOIN stream_versions v ON v.connection_id = s.connection_id
         AND v.stream = s.stream AND v.version = (
           SELECT max(h.version) FROM stream_versions h
           JOIN connections c ON c.connection_id = h.connection_id
           WHERE h.connection_id = s.connection_id AND h.stream = s.stream
             AND h.generation = c.generation AND h.complete = 1
             AND h.kind != 'delete' AND h.version > s.last_delete_version
         )
       ${connectionId === undefined ? "" : "WHERE s.connection_id = ?"}
       ORDER BY s.connection_id, s.stream`,
    connectionId === undefined ? [] : [connectionId],
  );
}

/**
 * Pick the connection a read of `target` serves, from the active connections
 * of its connector. The newest live head wins, then the lowest namespace. A
 * winner with a deleted stream is `tombstoned`; a winner that lacks a stream
 * or holds an incomplete one serves nothing.
 */
export function selectForTarget(
  target: Target,
  connections: readonly {
    readonly connection: Connection;
    readonly streams: readonly Stream[];
  }[],
): { candidate: Candidate | undefined; tombstoned: boolean } {
  const active: Candidate[] = [];
  for (const { connection, streams: all } of connections) {
    if (connection.control_state !== "active" || connection.deleted_at !== null)
      continue;
    const rank = all
      .filter((s) => live(s, connection))
      .map((s) => s.observed_at ?? 0);
    active.push({
      target,
      connection,
      streams: target.streams.flatMap((name) => {
        const s = all.find((s) => s.stream === name);
        return s ? [s] : [];
      }),
      registered: rank.length ? Math.max(...rank) : -Infinity,
    });
  }
  active.sort(
    (a, b) =>
      b.registered - a.registered ||
      a.connection.ns.localeCompare(b.connection.ns),
  );
  const selected = active[0];
  if (!selected) return { candidate: undefined, tombstoned: false };
  if (selected.streams.some(tombstoned)) {
    return { candidate: undefined, tombstoned: true };
  }
  const served =
    selected.streams.length === target.streams.length &&
    selected.streams.every((s) => complete(s, selected.connection));
  return { candidate: served ? selected : undefined, tombstoned: false };
}

/** Across the targets of one scope, the newest head wins, then the connector. */
export function chooseCandidate(
  candidates: readonly Candidate[],
): Candidate | undefined {
  return [...candidates].sort(
    (a, b) =>
      b.registered - a.registered ||
      a.target.connector.localeCompare(b.target.connector),
  )[0];
}

export const ARRAY_BUDGET = 64 * 1024 * 1024;
const encoder = new TextEncoder();

/**
 * Project the installed records of an alias scope, or say why it has no body.
 * Reads the local database only; `query` may be wrapped by the caller to
 * substitute retained heads.
 */
export async function projectAlias(
  binding: LocalAliasTarget,
  candidate: Candidate,
  query: RecordQuery,
  now: string,
): Promise<
  | { readonly kind: "ok"; readonly payload: unknown }
  | { readonly kind: "no_data" }
  | { readonly kind: "too_large"; readonly bytes: number }
> {
  // Check all input heads, before reading even one record or creating a body.
  if (
    candidate.streams.some((s) => s.profile_key !== candidate.target.connector)
  ) {
    return { kind: "no_data" };
  }
  if (binding.windowed) {
    const probe = binding.project([], now);
    if (!probe.ok && probe.error.kind.includes("profile")) {
      return { kind: "no_data" };
    }
  }
  const records: LocalAliasRecord[] = [];
  let bytes = 0;
  for (const stream of candidate.target.streams) {
    for await (const record of query.streamRecords(
      candidate.connection.connection_id,
      stream,
    )) {
      bytes += encoder.encode(record.body).byteLength;
      if (bytes > ARRAY_BUDGET) return { kind: "too_large", bytes };
      records.push({
        stream,
        data: JSON.parse(record.body) as Record<string, unknown>,
      });
    }
  }
  const projected = binding.project(records, now);
  return projected.ok
    ? { kind: "ok", payload: projected.payload }
    : { kind: "no_data" };
}
