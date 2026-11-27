import { sha256 } from "@noble/hashes/sha2";
import type { StreamSyncReadStatus } from "../stream-sync-read/service.js";
import { logicalStreamScopeParts } from "../stream-sync-read/routing.js";
import type { StreamSyncFiles } from "../stream-sync/ports.js";
import type { LocalSyncDeps } from "./deps.js";
import { readerOf } from "./driver.js";
import { WINDOW_CLOSED_REASON } from "./import-ledger.js";
import { SEEN_O } from "./merge.js";
import { streamDigest } from "./stream-digest.js";
import { checkAlias, type AliasCheck } from "./alias-projection.js";
import { readAliasEpochs } from "./alias-view.js";
import { createRecordQuery } from "./query.js";
import {
  chooseCandidate,
  effectiveControl,
  loadStreams,
  selectForTarget,
  servedStreamOf,
  targetsForScope,
  type Candidate,
  type Connection as SelectionConnection,
  type Stream,
  type Target,
} from "./read-selection.js";
import type { AliasScopes, AliasTargets } from "./resolve.js";

/** Reads of one alias body a listing makes before it calls the alias changing. */
const ALIAS_LISTING_TRIES = 3;

/** One listed scope of `GET /v1/data` (D.2). */
export interface ListedScope {
  readonly scope: string;
  readonly connector: string;
  readonly ns: string;
  readonly records: number | null;
  /** Epoch ms of the newest observation of the scope's records or head; null when none. */
  readonly updatedAt: number | null;
  /**
   * `updatedAt` as an ISO-8601 string: the list contract's field, which the
   * legacy summaries carry and clients read. Absent when `updatedAt` is null.
   */
  readonly latestCollectedAt?: string;
  /**
   * Set only on a legacy alias scope: the logical `pdpp.<connector>.<stream>`
   * scope it repeats. Readers that want one entry per stream skip entries
   * that carry it; the alias stays listed because grants and reads use it.
   */
  readonly aliasOf?: string;
  /**
   * `"indexing"` only on an owner listing that includes loads in progress: the
   * scope is served from a first load that has not finished, so a read of it
   * returns the rows applied so far (`X-Stream-Sync-Partial` says how many).
   * Absent means ready, as on every other listing that carries the field.
   */
  /** `incomplete`: installed and owner-readable, without collection-completeness proof. */
  readonly dataStatus?: "indexing" | "incomplete";
}

function collectedAt(updatedAt: number | null): { latestCollectedAt?: string } {
  if (updatedAt === null) return {};
  const date = new Date(updatedAt);
  // A stored stamp outside the Date range must not fail the whole list.
  return Number.isNaN(date.getTime())
    ? {}
    : { latestCollectedAt: date.toISOString() };
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
    /**
     * The owner's listing: a scope whose first load is still running is
     * listed, marked `dataStatus: "indexing"`, from the moment the load names its stream,
     * as a read of it by the owner serves the rows applied so far. Only a host
     * that serves progressive loads lists them; a grantee's listing never does.
     */
    readonly includeLoading?: boolean;
    /** Owner inspection of installed incomplete logical streams; never grant listings. */
    readonly includeIncomplete?: boolean;
  }): Promise<readonly ListedScope[]>;
  /**
   * `audit` adds what two devices are compared by: a digest of each live,
   * complete stream's records and the seed exclusions of the import ledger.
   * It reads every live row of every stream (cost linear in the rows, and in
   * their body size), so it is for a diagnostic that asks, not for a poll.
   */
  status(options?: { readonly audit?: boolean }): Promise<StreamSyncReadStatus>;
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

/** Reads of one connection's state and digests before the audit gives up on it. */
const AUDIT_ATTEMPTS = 4;

type Count = { records: number; stampedAt: number | null };

export function createLocalListing(
  deps: LocalSyncDeps & {
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
    /**
     * The host's alias spool, as the resolver has it: the check of a body
     * decides as its read does (see `checkAlias`).
     */
    readonly aliasSpool?: StreamSyncFiles;
  },
): LocalListing {
  // Listing and status only read: they take the read connection, so they do
  // not wait for a long import or publish batch on the writer.
  const reads = { db: readerOf(deps.db) };
  const connections = () =>
    reads.db.query<Connection>(
      `SELECT connection_id, connector, ns, generation,
       ${effectiveControl("connections")} AS control_state
       FROM connections ORDER BY connector, ns, connection_id`,
    );

  /**
   * Everything `listScopes` needs short of `canRead`, read from local state:
   * five queries however many scopes there are. Nothing here depends on the
   * caller's authority, so overlapping callers share one.
   */
  async function readSnapshot(
    progressive: boolean,
    includeIncomplete: boolean,
  ): Promise<readonly Entry[]> {
    const rows = await reads.db.query<SelectionConnection>(
      `SELECT connection_id, connector, ns, generation,
       ${effectiveControl("connections")} AS control_state, deleted_at
       FROM connections ORDER BY connector, ns, connection_id`,
    );
    const streams = await loadStreams(reads);
    const ownerStreams = includeIncomplete
      ? await loadStreams(reads, undefined, true)
      : streams;
    const stamps = await reads.db.query<{
      connection_id: string;
      stream: string;
      records: number;
      stamped_at: number | null;
    }>(
      `SELECT connection_id, stream, COUNT(*) AS records, MAX(${SEEN_O}) AS stamped_at FROM records r
       ${progressive ? "WHERE NOT EXISTS (SELECT 1 FROM partial_hidden h WHERE h.connection_id=r.connection_id AND h.stream=r.stream AND h.pk_hash=r.pk_hash)" : ""}
       GROUP BY connection_id, stream`,
    );
    const heads = await reads.db.query<{
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
    const ownerStreamsOf = new Map<string, Stream[]>();
    for (const stream of ownerStreams) {
      const list = ownerStreamsOf.get(stream.connection_id) ?? [];
      list.push(stream);
      ownerStreamsOf.set(stream.connection_id, list);
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
    const targets = (scope: string): readonly Target[] =>
      targetsForScope(scope, aliasNames, deps.aliasTargets);
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
      let invalidBinding = false;
      for (const target of targets(scope)) {
        const picked = selectForTarget(
          target,
          (byConnector.get(target.connector) ?? []).map((connection) => ({
            connection,
            streams:
              (target.alias ? streamsOf : ownerStreamsOf).get(
                connection.connection_id,
              ) ?? [],
          })),
          { progressive, includeIncomplete },
        );
        if (picked.kind === "invalid_binding") {
          invalidBinding = true;
          break;
        }
        if (picked.candidate) picks.push(picked.candidate);
      }
      const chosen = invalidBinding ? undefined : chooseCandidate(picks);
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
      for (const { stream } of chosen.streams) {
        const total = recordTotals.get(key(owner, stream));
        records += total?.records ?? 0;
        if (total?.stampedAt != null) times.push(total.stampedAt);
        const head = headTimes.get(key(owner, stream));
        if (head !== undefined) times.push(head);
      }
      const updatedAt = times.length === 0 ? null : Math.max(...times);
      let projection: Promise<boolean> | undefined;
      entries.push({
        scope,
        listed: {
          scope,
          connector: owner.connector,
          ns: owner.ns,
          records: logicalStreamScopeParts(scope) ? records : null,
          updatedAt,
          ...collectedAt(updatedAt),
          ...(chosen.incompleteStreams?.length
            ? { dataStatus: "incomplete" as const }
            : {}),
          ...(chosen.partialStreams?.length
            ? { dataStatus: "indexing" as const }
            : {}),
          ...(target.alias
            ? {
                aliasOf: `pdpp.${owner.connector}.${servedStreamOf(target)}`,
              }
            : {}),
        },
        bodyBuilds: () => (projection ??= aliasBodyBuilds(target, chosen)),
      });
    }
    return entries;
  }

  /**
   * Can a read build this alias body from the records installed now? A read
   * that finds its rows changed under it (`moved`) is asked again, with the
   * change marks read anew, and answers from the rows as they then stand.
   */
  async function aliasBodyBuilds(
    target: Target,
    chosen: Candidate,
  ): Promise<boolean> {
    if (!target.alias) return true;
    let projected: AliasCheck;
    for (let attempt = 0; ; attempt++) {
      projected = await checkAlias(
        target.alias,
        chosen,
        createRecordQuery(reads.db),
        new Date(deps.now()).toISOString(),
        {
          db: deps.db,
          memory: deps.blobs,
          spool: deps.aliasSpool,
          // Listing only reads: a pin that cleared the marks would write, and
          // wait for the writer behind a long batch.
          epochs: await readAliasEpochs(
            deps.db,
            chosen.connection.connection_id,
            chosen.streams.map((s) => s.stream),
          ),
        },
      );
      if (projected.kind !== "moved" || attempt + 1 >= ALIAS_LISTING_TRIES) {
        return projected.kind === "ok";
      }
    }
  }

  /** What a stream's head says about it, given its connection's control state. */
  const streamFacts = (row: Connection, state: StreamState) => {
    const tombstoned =
      state.last_delete_version > 0 &&
      state.head_version <= state.last_delete_version;
    const live =
      row.control_state === "active" &&
      state.head_generation === row.generation &&
      state.head_version > state.last_delete_version &&
      state.head_blob !== null;
    return { tombstoned, live, complete: live && state.complete === 1 };
  };

  /** The stream's digest; `null` when a stored hash is not a SHA-256 hex digest. */
  async function digestOf(connectionId: string, stream: string) {
    try {
      return (await streamDigest(reads.db, connectionId, stream)).fingerprint;
    } catch (error) {
      if (
        error instanceof Error &&
        error.message === "invalid_import_fingerprint_rows"
      ) {
        deps.logger.warn(
          { stream },
          "localdb status: a stored record hash is malformed; no digest",
        );
        return null;
      }
      throw error;
    }
  }

  /** The connection's change counter (`view_versions`): it moves on every write a read can see. */
  async function viewVersion(connectionId: string): Promise<number> {
    const [row] = await reads.db.query<{ version: number }>(
      "SELECT version FROM view_versions WHERE connection_id = ?",
      [connectionId],
    );
    return row?.version ?? 0;
  }

  /** The stream rows of one connection, each with its live record count. */
  const stateSql = `SELECT s.*, (SELECT COUNT(*) FROM records r WHERE r.connection_id = s.connection_id AND r.stream = s.stream) AS records FROM stream_state s`;

  /**
   * One connection's state and the digests of its complete streams, from one
   * state of the database. Each digest reads the stream's rows page by page
   * with a write able to commit between pages, and the state is read before
   * them: read alone, they could be of two different states. So the
   * connection's change counter is read before and after, and a read that saw
   * a write is read again. A connection that keeps changing through every
   * attempt reports no digest (`null`: not comparable) beside the state of its
   * last read, and is logged.
   */
  async function auditedConnection(connectionId: string): Promise<{
    readonly row: Connection;
    readonly states: readonly StreamState[];
    readonly digests: ReadonlyMap<string, string | null>;
  } | null> {
    let last: { row: Connection; states: readonly StreamState[] } | null = null;
    for (let attempt = 0; attempt < AUDIT_ATTEMPTS; attempt++) {
      const before = await viewVersion(connectionId);
      const [row] = await reads.db.query<Connection>(
        `SELECT connection_id, connector, ns, generation,
         ${effectiveControl("connections")} AS control_state
         FROM connections WHERE connection_id = ?`,
        [connectionId],
      );
      if (!row) return null;
      const states = await reads.db.query<StreamState>(
        `${stateSql} WHERE s.connection_id = ? ORDER BY s.stream`,
        [connectionId],
      );
      const digests = new Map<string, string | null>();
      for (const state of states)
        if (streamFacts(row, state).complete)
          digests.set(state.stream, await digestOf(connectionId, state.stream));
      if ((await viewVersion(connectionId)) === before)
        return { row, states, digests };
      last = { row, states };
    }
    deps.logger.warn(
      { attempts: AUDIT_ATTEMPTS },
      "localdb status: a connection kept changing during the audit; no digest",
    );
    return last && { ...last, digests: new Map() };
  }

  // Overlapping calls share one read of local state; the next call after it
  // settles starts a new one, so nothing is served from a cache.
  const inflight = new Map<string, Promise<readonly Entry[]>>();
  const snapshot = (progressive: boolean, includeIncomplete: boolean) => {
    const key = `${progressive}:${includeIncomplete}`;
    const running =
      inflight.get(key) ??
      readSnapshot(progressive, includeIncomplete).finally(() => {
        if (inflight.get(key) === running) inflight.delete(key);
      });
    inflight.set(key, running);
    return running;
  };

  return {
    async listScopes({ canRead, includeLoading, includeIncomplete }) {
      const out: ListedScope[] = [];
      const progressive =
        includeLoading === true && deps.progressiveFirstLoad === true;
      for (const entry of await snapshot(
        progressive,
        includeIncomplete === true,
      )) {
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

    async status(options) {
      const audit = options?.audit === true;
      // Control and heads must come from one snapshot before reporting
      // completeness. The left join retains connections without heads.
      const joined = audit
        ? []
        : await reads.db.query<
            Connection & Omit<StreamState, "stream"> & { stream: string | null }
          >(
            `SELECT connections.connection_id, connections.connector,
               connections.ns, connections.generation,
               ${effectiveControl("connections")} AS control_state,
               s.stream, s.complete, s.head_version, s.head_generation,
               s.head_blob, s.last_delete_version,
               (SELECT COUNT(*) FROM records r
                WHERE r.connection_id = s.connection_id AND r.stream = s.stream)
                AS records
             FROM connections LEFT JOIN stream_state s
               ON s.connection_id = connections.connection_id
             ORDER BY connections.connector, connections.ns,
               connections.connection_id, s.stream`,
          );
      const rows = audit
        ? await connections()
        : [...new Map(joined.map((row) => [row.connection_id, row])).values()];
      const states = new Map<string, StreamState[]>();
      for (const row of joined) {
        if (row.stream === null) continue;
        const state = { ...row, stream: row.stream };
        const connectionStates = states.get(row.connection_id);
        if (connectionStates) connectionStates.push(state);
        else states.set(row.connection_id, [state]);
      }
      // A first load in progress, for the owner's diagnostics. Only when the
      // host serves them: with the flag off a stream with no complete head
      // reports as it always did.
      const partials = new Map<
        string,
        NonNullable<
          StreamSyncReadStatus["connections"][number]["streams"][string]["partial"]
        >
      >();
      if (deps.progressiveFirstLoad === true) {
        for (const p of await reads.db.query<{
          connection_id: string;
          stream: string;
          version: number;
          generation: number;
          parts_applied: number;
          parts_total: number;
          records_total: number;
          failed: number;
          last_error: string | null;
        }>(
          "SELECT connection_id, stream, version, generation, parts_applied, parts_total, records_total, failed, last_error FROM stream_partial",
        )) {
          const owner = rows.find((c) => c.connection_id === p.connection_id);
          if (
            owner?.control_state === "active" &&
            owner.generation === p.generation
          )
            partials.set(JSON.stringify([p.connection_id, p.stream]), {
              version: p.version,
              partsApplied: p.parts_applied,
              partsTotal: p.parts_total,
              recordsTotal: p.records_total,
              ...(p.failed === 1
                ? { failed: { code: p.last_error ?? "unknown" } }
                : {}),
            });
        }
      }
      const result: StreamSyncReadStatus["connections"][number][] = [];
      for (const listed of rows) {
        const audited = audit
          ? await auditedConnection(listed.connection_id)
          : null;
        // A connection deleted since the listing has no state left to audit.
        if (audit && !audited) continue;
        const row = audited?.row ?? listed;
        const streams: Record<
          string,
          StreamSyncReadStatus["connections"][number]["streams"][string]
        > = {};
        for (const state of audited?.states ??
          states.get(row.connection_id) ??
          []) {
          const { tombstoned, live, complete } = streamFacts(row, state);
          streams[state.stream] = {
            tombstoned,
            live,
            complete,
            version: live ? state.head_version : null,
            records: live ? state.records : null,
            ...(audited
              ? { digest: audited.digests.get(state.stream) ?? null }
              : {}),
            ...(partials.has(
              JSON.stringify([row.connection_id, state.stream]),
            ) && !(live && state.complete === 1)
              ? {
                  partial: partials.get(
                    JSON.stringify([row.connection_id, state.stream]),
                  )!,
                }
              : {}),
          };
        }
        result.push({
          connector: row.connector,
          ns: row.ns,
          control: row.control_state,
          // A reconnect resets stream versions, so only the generation tells
          // it from the connection it replaced. The audit output omits it.
          ...(audit ? {} : { generation: row.generation }),
          streams,
        });
      }
      // An open local database is the listing source. Import issues are not
      // persisted by this schema; historical-read counters belong to the caller.
      return {
        listed: true,
        connections: result,
        issues: [],
        ...(audit
          ? {
              importExclusions: (
                await reads.db.query<{ reason: string; streams: number }>(
                  "SELECT COALESCE(reason, 'unknown') AS reason, COUNT(*) AS streams FROM import_ledger WHERE state = 'excluded' AND reason IS NOT ? GROUP BY 1 ORDER BY 1",
                  [WINDOW_CLOSED_REASON],
                )
              ).map(({ reason, streams }) => ({ reason, streams })),
            }
          : {}),
      };
    },

    async cacheKey() {
      // Include every column, not only a control version or the newest head:
      // local edits, deletions and changes to unselected connections count too.
      const controls = await reads.db.query(
        "SELECT * FROM connections ORDER BY connection_id",
      );
      const heads = await reads.db.query(
        "SELECT * FROM stream_state ORDER BY connection_id, stream",
      );
      const intents = await reads.db.query(
        "SELECT connector FROM delete_intents ORDER BY connector",
      );
      const digest = sha256(
        new TextEncoder().encode(JSON.stringify([controls, heads, intents])),
      );
      return Array.from(digest, (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
    },
  };
}
