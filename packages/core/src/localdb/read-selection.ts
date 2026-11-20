import {
  logicalStreamScopeParts,
  streamReadScope,
} from "../stream-sync-read/routing.js";
import type { SqlReader } from "./driver.js";
import type { AliasTargets, LocalAliasTarget } from "./resolve.js";

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
const isOptionalStream = (target: Target, stream: string): boolean =>
  target.alias?.requiredStreams !== undefined &&
  !target.alias.requiredStreams.includes(stream);

/**
 * The held streams of `target` that a read serves, and gates on. A stream the
 * alias serves without counts only while it is complete: absent, deleted or
 * incomplete, it is left out as if never installed, and neither gates the read
 * nor contributes rows. Every other stream is kept for the gates, and
 * `missingRequired` says one of them is not held at all.
 */
export function servedStreams(
  target: Target,
  held: readonly Stream[],
  connection: Connection,
): { streams: Stream[]; missingRequired: boolean } {
  const streams = held.filter(
    (s) => !isOptionalStream(target, s.stream) || complete(s, connection),
  );
  return {
    streams,
    missingRequired: target.streams.some(
      (name) =>
        !isOptionalStream(target, name) &&
        !streams.some((s) => s.stream === name),
    ),
  };
}

/** The stream whose head a read of `target` serves: its parent, if windowed. */
export const servedStreamOf = (target: Target): string =>
  target.alias?.servedStream ?? target.streams[0]!;

/** Effective control state while a connector deletion is pending. */
export const effectiveControl = (connection: string): string =>
  `CASE WHEN EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = ${connection}.connector)
    THEN 'deleted' ELSE ${connection}.control_state END`;

/** Every connection of one connector, by namespace. */
export function connectionsOf(
  deps: { readonly db: SqlReader },
  connector: string,
): Promise<Connection[]> {
  return deps.db.query<Connection>(
    `SELECT connection_id, connector, ns, generation, ${effectiveControl("c")} AS control_state, deleted_at
     FROM connections c WHERE connector = ? ORDER BY ns`,
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
/** Deletion evidence for one connection and target, independent of its rank. */
export function tombstonedForTarget(
  target: Target,
  connection: Connection,
  streams: readonly Stream[],
  progressive: boolean,
): boolean {
  const served = servedStreams(
    target,
    streams.filter((s) => target.streams.includes(s.stream)),
    connection,
  );
  return served.streams.some((s) =>
    tombstonedForRead(s, connection, progressive && !target.alias),
  );
}
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

/** An alias needs an actual required stream, even if every optional head is present. */
export function invalidAliasBinding(binding: LocalAliasTarget): boolean {
  return !(binding.requiredStreams ?? binding.streams).some((stream) =>
    binding.streams.includes(stream),
  );
}

/**
 * Pick the connection a read of `target` serves, from its active connections.
 * Prefer complete candidates, then the newest readable head among the binding's
 * target streams, then the lowest namespace. Required streams participate;
 * optional streams participate only when complete, as they do in the served
 * body. Unrelated streams never affect rank. Keep one connection for the whole
 * target: a winner with a deleted required stream is `tombstoned`; missing or
 * incomplete required streams serve nothing. Progressive logical reads retain
 * their first-load readability gates.
 */
export function selectForTarget(
  target: Target,
  connections: readonly {
    readonly connection: Connection;
    readonly streams: readonly Stream[];
  }[],
  options: { readonly progressive?: boolean } = {},
):
  | { candidate: Candidate | undefined; tombstoned: boolean; kind?: "selected" }
  | { kind: "invalid_binding"; candidate: undefined; tombstoned: false } {
  if (target.alias && invalidAliasBinding(target.alias))
    return { kind: "invalid_binding", candidate: undefined, tombstoned: false };
  // A first load's applied parts are served for a logical stream only: an
  // alias projects the whole head, which a partial head cannot give.
  const progressive = options.progressive === true && !target.alias;
  const active: (Candidate & { readonly missingRequired: boolean })[] = [];
  for (const { connection, streams: all } of connections) {
    if (connection.control_state !== "active" || connection.deleted_at !== null)
      continue;
    const served = servedStreams(
      target,
      target.streams.flatMap((name) => {
        const s = all.find((s) => s.stream === name);
        return s ? [s] : [];
      }),
      connection,
    );
    // Deletion is per connection; a tombstone removes only its own connection's copy.
    const rank = served.streams.flatMap((s) =>
      live(s, connection)
        ? [s.observed_at ?? 0]
        : progressive && partialReadable(s, connection)
          ? [s.partial!.observedAt]
          : [],
    );
    active.push({
      target,
      connection,
      streams: served.streams,
      missingRequired: served.missingRequired,
      registered: rank.length ? Math.max(...rank) : -Infinity,
    });
  }
  active.sort(
    (a, b) =>
      compareCompleteness(a, b) ||
      b.registered - a.registered ||
      a.connection.ns.localeCompare(b.connection.ns),
  );
  const selected = active[0];
  if (!selected) return { candidate: undefined, tombstoned: false };
  if (
    tombstonedForTarget(
      target,
      selected.connection,
      selected.streams,
      progressive,
    )
  ) {
    return { candidate: undefined, tombstoned: true };
  }
  if (selected.missingRequired) {
    return { candidate: undefined, tombstoned: false };
  }
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

/** Missing or unreadable required streams do not count as a complete copy. */
const completeCandidate = (candidate: Candidate): boolean =>
  candidate.target.streams.length > 0 &&
  candidate.target.streams.every(
    (name) =>
      isOptionalStream(candidate.target, name) ||
      candidate.streams.some(
        (s) => s.stream === name && complete(s, candidate.connection),
      ),
  );

/** Complete copies precede first loads at every candidate selection level. */
const compareCompleteness = (a: Candidate, b: Candidate): number =>
  Number(completeCandidate(b)) - Number(completeCandidate(a));

/** Across one scope's targets: completeness, newest head, then connector. */
export function chooseCandidate(
  candidates: readonly Candidate[],
): Candidate | undefined {
  return [...candidates].sort(
    (a, b) =>
      compareCompleteness(a, b) ||
      b.registered - a.registered ||
      a.target.connector.localeCompare(b.target.connector),
  )[0];
}
