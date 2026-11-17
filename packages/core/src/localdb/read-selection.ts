import {
  logicalStreamScopeParts,
  streamReadScope,
} from "../stream-sync-read/routing.js";
import type { SqlReader } from "./driver.js";
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
/**
 * A first load in progress, as `stream_partial` holds it: the head being
 * applied and how many of its parts are applied. Present only between a first
 * load's first part and its completion; the completion removes it.
 */
export type PartialLoad = {
  readonly version: number;
  readonly generation: number;
  readonly dataHash: string;
  readonly headBlob: string;
  readonly observedAt: number;
  readonly partsApplied: number;
  readonly partsTotal: number;
  readonly recordsTotal: number;
  /** The apply stopped before the last part, and why (a short slug). */
  readonly failed: string | null;
};
export type Stream = {
  /** Set by `loadStreams`; absent on a stream that has no first load running. */
  partial?: PartialLoad | null;
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
  /**
   * The streams this candidate serves from a first load in progress. Empty:
   * every stream is complete, which is the only case when `progressive` is off.
   */
  partialStreams?: readonly string[];
};

/** What a read of one stream can serve now. */
export type Readability = "complete" | "partial" | "none";

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

/** Whether `target` serves without `stream`: the alias names it outside `requiredStreams`. */
export const isOptionalStream = (target: Target, stream: string): boolean =>
  target.alias?.requiredStreams !== undefined &&
  !target.alias.requiredStreams.includes(stream);

/** The stream whose head a read of `target` serves: its parent, if windowed. */
export const servedStreamOf = (target: Target): string =>
  target.alias?.servedStream ?? target.streams[0]!;

/** Every connection of one connector, by namespace. */
export function connectionsOf(
  deps: { readonly db: SqlReader },
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
/**
 * Tombstoned for a read. A first load of a head newer than the deletion floor
 * is not: its stream state still carries the floor of the delete it follows,
 * with no head installed yet.
 */
export const tombstonedForRead = (
  s: Stream,
  c: Connection,
  progressive: boolean,
) => tombstoned(s) && !(progressive && partialReadable(s, c));
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
 * A first load whose applied parts a reader may show: the connection is
 * readable, the head being applied belongs to its generation and is newer than
 * the deletion floor, and no complete head serves instead. Rows of the load
 * are of that one head alone: apply drops the rows of any other head in the
 * commit that begins a head's load (see `apply.ts`).
 */
export const partialReadable = (s: Stream, c: Connection) =>
  c.control_state === "active" &&
  c.deleted_at === null &&
  s.partial != null &&
  s.partial.generation === c.generation &&
  s.partial.version > s.last_delete_version;

/**
 * Complete when the head is complete and live, as always. Partial only for a
 * progressive read of a stream with a first load in progress. A stream with
 * neither serves nothing.
 */
export const readability = (
  s: Stream,
  c: Connection,
  progressive: boolean,
): Readability =>
  complete(s, c)
    ? "complete"
    : progressive && partialReadable(s, c)
      ? "partial"
      : "none";

/**
 * Every stream of one connection (or of all connections) with its newest
 * complete head above the deletion floor.
 */
export async function loadStreams(
  deps: { readonly db: SqlReader },
  connectionId?: string,
): Promise<Stream[]> {
  const rows = await deps.db.query<
    Omit<Stream, "partial"> & {
      partial_version: number | null;
      partial_generation: number | null;
      partial_data_hash: string | null;
      partial_head_blob: string | null;
      partial_observed_at: number | null;
      partial_parts_applied: number | null;
      partial_parts_total: number | null;
      partial_records_total: number | null;
      partial_failed: number | null;
      partial_last_error: string | null;
    }
  >(
    `SELECT s.connection_id, s.head_version AS installed_version, s.stream, s.profile_key, s.profile_version, s.primary_key,
              coalesce(v.complete, 0) AS complete, s.last_delete_version, coalesce(v.version, s.head_version) AS head_version,
              v.generation AS head_generation, s.head_data_hash, v.head_blob,
              v.version, v.generation, v.head_blob AS version_blob,
              v.complete AS version_complete, v.observed_at, v.kind,
              p.version AS partial_version, p.generation AS partial_generation, p.data_hash AS partial_data_hash,
              p.head_blob AS partial_head_blob, p.observed_at AS partial_observed_at,
              p.parts_applied AS partial_parts_applied, p.parts_total AS partial_parts_total,
              p.records_total AS partial_records_total,
              p.failed AS partial_failed, p.last_error AS partial_last_error
       FROM stream_state s
       LEFT JOIN stream_versions v ON v.connection_id = s.connection_id
         AND v.stream = s.stream AND v.version = (
           SELECT max(h.version) FROM stream_versions h
           JOIN connections c ON c.connection_id = h.connection_id
           WHERE h.connection_id = s.connection_id AND h.stream = s.stream
             AND h.generation = c.generation AND h.complete = 1
             AND h.kind != 'delete' AND h.version > s.last_delete_version
         )
       LEFT JOIN stream_partial p ON p.connection_id = s.connection_id AND p.stream = s.stream
       ${connectionId === undefined ? "" : "WHERE s.connection_id = ?"}
       ORDER BY s.connection_id, s.stream`,
    connectionId === undefined ? [] : [connectionId],
  );
  return rows.map((row): Stream => {
    const {
      partial_version,
      partial_generation,
      partial_data_hash,
      partial_head_blob,
      partial_observed_at,
      partial_parts_applied,
      partial_parts_total,
      partial_records_total,
      partial_failed,
      partial_last_error,
      ...stream
    } = row;
    return partial_version === null
      ? stream
      : {
          ...stream,
          partial: {
            version: partial_version,
            generation: partial_generation!,
            dataHash: partial_data_hash!,
            headBlob: partial_head_blob!,
            observedAt: partial_observed_at!,
            partsApplied: partial_parts_applied!,
            partsTotal: partial_parts_total!,
            recordsTotal: partial_records_total!,
            failed:
              partial_failed === 1 ? (partial_last_error ?? "unknown") : null,
          },
        };
  });
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
  options: { readonly progressive?: boolean } = {},
): { candidate: Candidate | undefined; tombstoned: boolean } {
  // A first load's applied parts are served for a logical stream only: an
  // alias projects the whole head, which a partial head cannot give.
  const progressive = options.progressive === true && !target.alias;
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
  if (
    selected.streams.some((s) =>
      tombstonedForRead(s, selected.connection, progressive),
    )
  ) {
    return { candidate: undefined, tombstoned: true };
  }
  if (
    target.streams.some(
      (name) =>
        !isOptionalStream(target, name) &&
        !selected.streams.some((s) => s.stream === name),
    )
  )
    return { candidate: undefined, tombstoned: false };
  const states = selected.streams.map((s) =>
    readability(s, selected.connection, progressive),
  );
  if (states.includes("none"))
    return { candidate: undefined, tombstoned: false };
  if (!progressive) return { candidate: selected, tombstoned: false };
  return {
    candidate: {
      ...selected,
      partialStreams: selected.streams
        .filter((_, i) => states[i] === "partial")
        .map((s) => s.stream),
    },
    tombstoned: false,
  };
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
