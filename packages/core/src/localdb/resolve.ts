import {
  logScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  type ReadDecision,
  type ResolveInput,
} from "../stream-sync-read/service.js";
import { streamReadScope } from "../stream-sync-read/routing.js";
import { RegistryUnavailableBeforeWriteError } from "../stream-sync/ports.js";
import {
  ensureRegisteredRead,
  registeredReadPosition,
} from "./registered-read.js";
import { applyConnection } from "./apply.js";
import { nextApplied } from "./apply-progress.js";
import type { LocalSyncDeps } from "./deps.js";
import { readerOf } from "./driver.js";
import { pinAliasStreams } from "./alias-view.js";
import { projectAlias } from "./alias-projection.js";
import { completeBody, pinStream } from "./complete-read.js";
import { partialBody } from "./partial-read.js";
import type { AliasRecordQuery, RecordQuery } from "./query.js";
import {
  chooseCandidate,
  invalidAliasBinding,
  complete,
  connectionsOf,
  loadStreams,
  readability,
  selectForTarget,
  servedStreamOf,
  servedStreams,
  targetsForScope,
  tombstoned,
  tombstonedForRead,
  tombstonedForTarget,
  type Candidate,
  type Connection,
  type Stream,
  type Target,
} from "./read-selection.js";

/**
 * D.1: serve the latest complete head above the deletion floor. When the
 * installed image is incomplete, fetch the retained complete head instead.
 * This current-read fallback is independent of optional historical reads.
 */
export interface LocalResolver {
  resolve(input: ResolveInput): Promise<ReadDecision>;
}

/** The host alone knows legacy aliases and how to project their records. */
export interface LocalAliasTarget {
  readonly connector: string;
  readonly streams: readonly string[];
  /**
   * The streams a read must find installed and complete. The rest of
   * `streams` are read when present and left out when absent. Absent: every
   * stream of `streams` is required.
   */
  readonly requiredStreams?: readonly string[];
  readonly servedStream?: string;
  readonly windowed?: boolean;
  /**
   * How a read of this alias pages its projection, when the binding builds one
   * output element per parent row (the host's `LegacyProjectionWindow`). Absent:
   * the read projects every row in one call.
   */
  readonly window?: AliasWindow;
  /**
   * `fetched` names the streams the read served, whether or not they had
   * rows: a stream left out of it was never read.
   */
  readonly project: (
    records: readonly LocalAliasRecord[],
    now: string,
    fetched: readonly string[],
  ) =>
    | {
        readonly ok: true;
        readonly payload: unknown;
        /** Rows the payload leaves out or serves short of detail. */
        readonly diagnostics?: readonly AliasDiagnostic[];
      }
    | { readonly ok: false; readonly error: { readonly kind: string } };
}
/**
 * A binding whose payload holds one element of `arrayKey` for each row of
 * `parentStream`, built from that row, the `childStream` rows whose `childKey`
 * holds its `parentKey`, and whole copies of the other streams. The payload's
 * other keys are the same however the parents are cut into windows, except
 * `sumKeys`, which add up. `parentOrder` is the order of the array.
 */
export interface AliasWindow {
  readonly parentStream: string;
  /** The one field of the parent's primary key that its children name. */
  readonly parentKey: string;
  readonly childStream: string;
  readonly childKey: string;
  readonly arrayKey: string;
  readonly sumKeys: readonly string[];
  readonly parentOrder: (
    a: Record<string, unknown>,
    b: Record<string, unknown>,
  ) => number;
}
/**
 * A projection's report on its own payload. Only `records_dropped` and
 * `records_partial` make a read incomplete; the rest are carried unread.
 */
export interface AliasDiagnostic {
  readonly kind: string;
  readonly stream?: string;
  readonly count?: number;
  readonly reasons?: readonly string[];
}
/** What a refused-as-incomplete read names: one entry per affected stream. */
export interface IncompleteAliasDiagnostic {
  readonly stream: string;
  readonly kind: "dropped" | "partial";
  readonly detail: string;
}
export interface LocalAliasRecord {
  readonly stream: string;
  readonly data: Record<string, unknown>;
}
/** Names admitted by the host; absent means no legacy aliases. */
export type AliasScopes = () => Iterable<string>;
/** The host supplies projection knowledge separately from name discovery. */
export type AliasTargets = (scope: string) => readonly LocalAliasTarget[];
const encoder = new TextEncoder();
const noData = (): ReadDecision => ({ kind: "unavailable", reason: "no_data" });
const deleted = (): ReadDecision => ({
  kind: "unavailable",
  reason: "deleted",
});
function cursorFor(c: Candidate): string {
  const json = JSON.stringify({
    c: c.connection.connector,
    ns: c.connection.ns,
    s: Object.fromEntries(
      c.streams.map((s) => [
        s.stream,
        {
          // A stream served from its first load is pinned at the head it
          // loads; any other stream at the log position its records are at.
          b: c.partialStreams?.includes(s.stream)
            ? s.partial!.version
            : s.installed_version,
          h: JSON.stringify([s.primary_key, s.profile_key, s.profile_version]),
        },
      ]),
    ),
  });
  let binary = "";
  for (const byte of encoder.encode(json)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function validCursor(text: string): boolean {
  try {
    const bytes = Uint8Array.from(
      atob(text.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );
    const value = JSON.parse(new TextDecoder().decode(bytes)) as {
      c?: unknown;
      ns?: unknown;
      s?: unknown;
    };
    return (
      typeof value.c === "string" &&
      typeof value.ns === "string" &&
      value.s !== null &&
      typeof value.s === "object" &&
      !Array.isArray(value.s) &&
      Object.values(value.s).every((pin: unknown) => {
        if (pin === null || typeof pin !== "object") return false;
        const p = pin as { b?: unknown; h?: unknown };
        return Number.isSafeInteger(p.b) && typeof p.h === "string";
      })
    );
  } catch {
    return false;
  }
}

/**
 * `onCancel` runs first when the reader cancels: a generator ends only after
 * the `next()` it is running, so a body that waits for memory is told to stop
 * waiting before it is asked to return.
 */
function bodyStream(
  chunks: AsyncIterable<string>,
  onCancel?: () => void,
): ReadableStream<Uint8Array> {
  const iterator = chunks[Symbol.asyncIterator]();
  return new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) controller.close();
        else controller.enqueue(encoder.encode(next.value));
      } catch (error) {
        controller.error(error);
      }
    },
    async cancel() {
      onCancel?.();
      await iterator.return?.(undefined);
    },
  });
}

async function* envelope(
  scope: string,
  observedAt: number,
  payload: AsyncIterable<string>,
): AsyncGenerator<string> {
  yield `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(new Date(observedAt).toISOString())},"data":`;
  yield* payload;
  yield "}";
}

/**
 * An alias read decided under the connection's queue: its heads and epochs are
 * pinned and its headers are known. `finish` projects it and makes the view,
 * and runs after the queue is released.
 */
interface PinnedAlias {
  readonly finish: () => Promise<ReadDecision>;
}

/**
 * What a resolver is made of. Legacy aliases are read through a query that
 * also answers sizes and records by key hash (`AliasRecordQuery`): `aliasQuery`,
 * or `query` itself when it is one, as `createRecordQuery` makes it (the shape
 * callers had before alias paging). `aliasScopes` and `aliasTargets` come only
 * with such a query: a caller that names aliases and a plain `RecordQuery`
 * would serve none.
 */
export type LocalResolverParts =
  | {
      readonly query: RecordQuery;
      readonly aliasQuery?: undefined;
      readonly aliasScopes?: undefined;
      readonly aliasTargets?: undefined;
    }
  | {
      readonly query: RecordQuery;
      readonly aliasQuery: AliasRecordQuery;
      readonly aliasScopes?: AliasScopes;
      readonly aliasTargets?: AliasTargets;
    }
  | {
      readonly query: AliasRecordQuery;
      readonly aliasQuery?: undefined;
      readonly aliasScopes?: AliasScopes;
      readonly aliasTargets?: AliasTargets;
    };

const isAliasRecordQuery = (query: RecordQuery): query is AliasRecordQuery => {
  const candidate = query as Partial<AliasRecordQuery>;
  return (
    typeof candidate.streamStats === "function" &&
    typeof candidate.recordSizes === "function" &&
    typeof candidate.recordsByHash === "function"
  );
};

export function createLocalResolver(
  deps: LocalSyncDeps,
  parts: LocalResolverParts,
): LocalResolver {
  const aliasQuery =
    parts.aliasQuery ??
    (isAliasRecordQuery(parts.query) ? parts.query : undefined);
  if (!aliasQuery && (parts.aliasScopes || parts.aliasTargets)) {
    // Not reachable from typed code (see `LocalResolverParts`).
    throw new Error(
      "createLocalResolver: aliasScopes and aliasTargets need an aliasQuery to read their records",
    );
  }
  const streams = (connectionId: string): Promise<Stream[]> =>
    loadStreams(deps, connectionId);

  const connections = (connector: string): Promise<Connection[]> =>
    connectionsOf(deps, connector);
  const progressiveFirstLoad = deps.progressiveFirstLoad === true;

  /** What a progressive read of the target can serve from this connection now. */
  async function readableNow(
    connection: Connection,
    target: Target,
  ): Promise<"complete" | "partial" | "none"> {
    const all = await streams(connection.connection_id);
    let partial = false;
    for (const name of target.streams) {
      const s = all.find((s) => s.stream === name);
      if (!s) return "none";
      const state = readability(s, connection, true);
      if (state === "none") return "none";
      if (state === "partial") partial = true;
    }
    return partial ? "partial" : "complete";
  }

  /**
   * Bring one connection up to date for a read. A progressive read waits only
   * until its target is readable: when a first load has applied its first
   * part, the rest keeps applying behind the read. A target that is complete
   * still waits for the apply, which may hold a newer head, as every read does.
   */
  async function applyFor(
    connection: Connection,
    target: Target,
    progressive: boolean,
  ): Promise<void> {
    const id = connection.connection_id;
    const flight = applyConnection(deps, id);
    if (!progressive || target.alias) {
      await flight;
      return;
    }
    let failure: { readonly error: unknown } | undefined;
    let settled = false;
    const done = flight.then(
      () => {
        settled = true;
      },
      (error: unknown) => {
        settled = true;
        failure = { error };
      },
    );
    for (;;) {
      // Taken before the read, so a part that commits in between wakes it.
      const wake = nextApplied(deps, id);
      if (settled) break;
      const state = await readableNow(connection, target);
      if (state === "partial") {
        void done.then(() => {
          if (failure)
            deps.logger.warn(
              { error: String(failure.error) },
              "stream sync: an apply behind a partial read failed; the next read retries",
            );
        });
        return;
      }
      if (state === "complete") break;
      await Promise.race([done, wake]);
    }
    await done;
    if (failure) throw failure.error;
  }

  /**
   * A view of a first load in progress. It takes no queue slot: the apply
   * holds the slot until the whole stream is applied, and a read that waited
   * for it would be the read this exists to avoid. Its body checks its head
   * on every page instead (see `partialBody`). `undefined`: the stream
   * completed meanwhile, so the complete path serves it.
   */
  async function buildPartial(
    input: ResolveInput,
    candidate: Candidate,
  ): Promise<ReadDecision | undefined> {
    const [connection] = (await connections(candidate.target.connector)).filter(
      (c) => c.connection_id === candidate.connection.connection_id,
    );
    if (!connection) return noData();
    if (
      connection.control_state === "deleted" ||
      connection.deleted_at !== null
    )
      return deleted();
    if (connection.control_state === "foreign") return { kind: "key_mismatch" };
    const all = await streams(connection.connection_id);
    const { streams: served } = servedStreams(
      candidate.target,
      candidate.target.streams.flatMap((name) => {
        const s = all.find((s) => s.stream === name);
        return s ? [s] : [];
      }),
      connection,
    );
    if (served.some((s) => tombstonedForRead(s, connection, true)))
      return deleted();
    const states = served.map((s) => readability(s, connection, true));
    if (states.includes("none")) return noData();
    if (!states.includes("partial")) return undefined;
    // A logical stream is one stream: an alias is never served partial.
    const stream = served[0]!;
    const load = stream.partial!;
    const current = { ...candidate, connection, streams: [stream] };
    const cursor = cursorFor({ ...current, partialStreams: [stream.stream] });
    if (input.cursor !== null && input.cursor !== cursor)
      return { kind: "cursor_stale" };
    return {
      kind: "view",
      connector: connection.connector,
      ns: connection.ns,
      cursor,
      served: {
        scope: streamScope(connection.connector, connection.ns, stream.stream),
        version: load.version,
      },
      partial: {
        partsApplied: load.partsApplied,
        partsTotal: load.partsTotal,
        recordsTotal: load.recordsTotal,
        ...(load.failed === null ? {} : { failed: { code: load.failed } }),
      },
      body: bodyStream(
        envelope(
          input.scope,
          load.observedAt,
          partialBody(readerOf(deps.db), {
            connectionId: connection.connection_id,
            generation: load.generation,
            stream: stream.stream,
            version: load.version,
            dataHash: load.dataHash,
          }),
        ),
      ),
    };
  }

  /**
   * A complete read, decided while it holds the connection's queue and
   * finished once its headers are decided: the body holds nothing. A body of
   * the database pages through the stream and checks its head on every page
   * (see `completeBody`).
   *
   * A projected alias is not projected here. Its heads and epochs are pinned
   * under the queue, and `build` returns what finishes the read: the caller
   * calls it after the queue is released (see `PinnedAlias`).
   */
  async function build(
    input: ResolveInput,
    candidate: Candidate,
  ): Promise<ReadDecision | PinnedAlias> {
    // A body of the database is pinned before the head is read: see
    // `pinStream`. An alias is projected after the queue is released (a paged
    // one, window by window; any other, whole), so it pins every stream it
    // reads.
    const alias = candidate.target.alias;
    const pin = alias
      ? 0
      : await pinStream(
          deps.db,
          candidate.connection.connection_id,
          candidate.target.streams[0]!,
        );
    const epochs = alias
      ? await pinAliasStreams(
          deps.db,
          candidate.connection.connection_id,
          candidate.target.streams,
        )
      : undefined;
    const [connection] = (await connections(candidate.target.connector)).filter(
      (c) => c.connection_id === candidate.connection.connection_id,
    );
    if (!connection) return noData();
    if (
      connection.control_state === "deleted" ||
      connection.deleted_at !== null
    ) {
      return deleted();
    }
    if (connection.control_state === "foreign") return { kind: "key_mismatch" };
    const all = await streams(connection.connection_id);
    const { streams: installed, missingRequired } = servedStreams(
      candidate.target,
      candidate.target.streams.flatMap((name) => {
        const s = all.find((s) => s.stream === name);
        return s ? [s] : [];
      }),
      connection,
    );
    if (installed.some(tombstoned)) return deleted();
    if (missingRequired || installed.some((s) => !complete(s, connection)))
      return noData();
    const current = { ...candidate, connection, streams: installed };
    const cursor = cursorFor(current);
    if (input.cursor !== null && input.cursor !== cursor)
      return { kind: "cursor_stale" };

    const position = input.requireRegistered
      ? await registeredReadPosition(
          deps,
          connection.connection_id,
          installed.map((s) => s.stream),
        )
      : null;
    if (input.requireRegistered && position === null)
      return { kind: "read_not_registered" };

    const servedStream = servedStreamOf(candidate.target);
    const head = installed.find((s) => s.stream === servedStream)!;
    const view = (
      payload: AsyncIterable<string>,
      onCancel?: () => void,
    ): ReadDecision => ({
      kind: "view",
      connector: connection.connector,
      ns: connection.ns,
      cursor,
      served: {
        scope:
          position === null
            ? streamScope(connection.connector, connection.ns, servedStream)
            : logScope(connection.connector, connection.ns),
        version: position ?? head.installed_version,
      },
      body: bodyStream(
        envelope(
          input.scope,
          Math.max(...installed.map((s) => s.observed_at ?? 0)),
          payload,
        ),
        onCancel,
      ),
    });
    const binding = candidate.target.alias;
    if (!binding) {
      const only = installed[0]!;
      return view(
        completeBody(
          readerOf(deps.db),
          {
            connectionId: connection.connection_id,
            generation: connection.generation,
            stream: only.stream,
            // The stream's installed head: the identity every page checks.
            version: only.installed_version,
            dataHash: only.head_data_hash!,
          },
          pin,
        ),
      );
    }
    if (!aliasQuery) throw new Error("an alias target without an aliasQuery");
    return {
      finish: async () => {
        // Ends the waits of this read's alias body: the request's own signal,
        // or the reader cancelling the body (see `bodyStream`).
        const stop = new AbortController();
        const signal = input.signal
          ? AbortSignal.any([input.signal, stop.signal])
          : stop.signal;
        let projected: Awaited<ReturnType<typeof projectAlias>>;
        try {
          projected = await projectAlias(
            binding,
            current,
            aliasQuery,
            new Date(deps.now()).toISOString(),
            { db: deps.db, memory: deps.blobs, epochs, signal },
          );
        } catch (error) {
          // The request ended while the check waited for memory.
          if (input.signal?.aborted) return { kind: "read_aborted" };
          throw error;
        }
        if (projected.kind === "invalid_binding") return projected;
        if (projected.kind === "incomplete") {
          return { kind: "incomplete", diagnostics: projected.diagnostics };
        }
        // The rows changed while the read was checked: ask again.
        if (projected.kind === "moved") {
          return { kind: "busy", retryAfterSeconds: 5 };
        }
        if (projected.kind === "no_data") return noData();
        return view(projected.body(), () => stop.abort());
      },
    };
  }

  return {
    async resolve(input) {
      if (
        input.connection !== null &&
        !/^(?:[0-9a-f]{16})?$/.test(input.connection)
      ) {
        return { kind: "invalid_connection" };
      }
      if (input.cursor !== null && !validCursor(input.cursor))
        return { kind: "invalid_cursor" };
      const scope = streamReadScope(input.scope) ?? input.scope;
      const targets = targetsForScope(
        scope,
        new Set(parts.aliasScopes?.() ?? []),
        parts.aliasTargets,
      );
      if (
        targets.some(
          (target) => target.alias && invalidAliasBinding(target.alias),
        )
      )
        return { kind: "invalid_binding" };
      // A stream that is still loading is served to its owner alone.
      const progressive = progressiveFirstLoad && input.isOwnerView;
      const candidates: Candidate[] = [];
      let sawDeleted = false;
      let sawTombstoned = false;
      let sawForeign = false;
      let sawConnection = false;
      let sawActive = false;
      let applyUnavailable = false;
      const initial: Candidate[] = [];
      for (const target of targets) {
        // Apply sees the persisted state so it can mark pending deletes before
        // selection hides them. Selection below still uses effective control.
        const beforeApply = await deps.db.query<
          Connection & { pending_delete: number }
        >(
          `SELECT c.connection_id, c.connector, c.ns, c.generation, c.control_state, c.deleted_at,
                  EXISTS (SELECT 1 FROM delete_intents d WHERE d.connector = c.connector) AS pending_delete
           FROM connections c WHERE c.connector = ? ORDER BY c.ns`,
          [target.connector],
        );
        const refused = new Set<string>();
        // applyConnection is the single-flight boundary and verifies keys before
        // installing rows. No rejected/foreign head is eligible for a DB read.
        for (const c of beforeApply) {
          if (
            c.control_state === "active" &&
            c.deleted_at === null &&
            (input.connection === null || input.connection === c.ns)
          ) {
            try {
              if (c.pending_delete)
                await applyConnection(deps, c.connection_id);
              else await applyFor(c, target, progressive);
            } catch (error) {
              if (!(error instanceof RegistryUnavailableBeforeWriteError))
                throw error;
              refused.add(c.connection_id);
            }
          }
        }
        let rows = await connections(target.connector);
        if (input.connection !== null)
          rows = rows.filter((c) => c.ns === input.connection);
        sawConnection ||= rows.length > 0;
        sawDeleted ||= rows.some(
          (c) => c.control_state === "deleted" || c.deleted_at !== null,
        );
        sawForeign ||= rows.some((c) => c.control_state === "foreign");
        sawActive ||= rows.some(
          (c) => c.control_state === "active" && c.deleted_at === null,
        );
        const loaded: { connection: Connection; streams: Stream[] }[] = [];
        for (const connection of rows) {
          if (
            connection.deleted_at !== null ||
            (connection.control_state !== "active" &&
              !(
                input.requireRegistered && connection.control_state === "absent"
              ))
          )
            continue;
          const available = await streams(connection.connection_id);
          if (connection.control_state === "active")
            loaded.push({ connection, streams: available });
          if (input.requireRegistered) {
            const pending = servedStreams(
              target,
              available.filter((s) => target.streams.includes(s.stream)),
              connection,
            );
            if (!pending.missingRequired && pending.streams.length > 0)
              initial.push({
                target,
                connection,
                streams: pending.streams,
                registered: -Infinity,
              });
          }
        }
        const picked = selectForTarget(target, loaded, { progressive });
        if (picked.kind === "invalid_binding") return picked;
        if (picked.tombstoned) sawTombstoned = true;
        // A winner's tombstone says nothing about another connection whose
        // pending apply could change the selection.
        if (
          loaded.some(
            ({ connection, streams }) =>
              refused.has(connection.connection_id) &&
              !tombstonedForTarget(target, connection, streams, progressive),
          )
        )
          applyUnavailable = true;
        if (picked.candidate) candidates.push(picked.candidate);
      }
      const ranked = chooseCandidate(candidates);
      // First publication has no readable head to rank yet. Bootstrap only
      // an unambiguous connection after ordinary selection found no body.
      // A readable winner always keeps its existing rank and identity.
      const chosen =
        ranked ??
        (!sawTombstoned && !applyUnavailable && initial.length === 1
          ? initial[0]
          : undefined);
      if (!chosen) {
        if (applyUnavailable)
          return input.requireRegistered
            ? { kind: "read_not_registered" }
            : { kind: "busy", retryAfterSeconds: 5 };
        if (sawTombstoned) return deleted();
        if (sawDeleted) return deleted();
        if (sawForeign && !sawActive) return { kind: "key_mismatch" };
        if (input.cursor !== null) return { kind: "cursor_stale" };
        if (input.connection !== null && !sawConnection) {
          return { kind: "unavailable", reason: "connection_not_found" };
        }
        return noData();
      }
      if (
        input.requireRegistered &&
        !(await ensureRegisteredRead(
          deps,
          chosen.connection.connection_id,
          chosen.streams.map((s) => s.stream),
          input.signal,
        ))
      )
        return {
          kind: input.signal?.aborted ? "read_aborted" : "read_not_registered",
        };
      if (chosen.partialStreams?.length) {
        const partial = await buildPartial({ ...input, scope }, chosen);
        if (partial) return partial;
      }
      // The queue is held to decide the headers and no longer: a body held it
      // until its reader finished or cancelled, which a reader that stopped
      // pulling never did, and every apply and read of the connection waited.
      // The body checks its head itself, on every page.
      const decide = async (): Promise<ReadDecision> => {
        const built = await deps.queue.run(
          chosen.connection.connection_id,
          "end",
          () => build({ ...input, scope }, chosen),
        );
        // An alias is projected outside the queue: its check may wait for
        // memory that a paused client holds, and the queue must not wait with
        // it. Its statements carry the pinned view, so a write that lands
        // after the queue is released ends the read as `busy`.
        return "finish" in built ? built.finish() : built;
      };
      const decision = await decide();
      // A collector can commit between the early coverage check and build.
      // Publish outside the queue and reselect the body once in that case.
      if (decision.kind === "read_not_registered" && input.requireRegistered) {
        const registered = await ensureRegisteredRead(
          deps,
          chosen.connection.connection_id,
          chosen.target.streams,
          input.signal,
        );
        if (input.signal?.aborted) return { kind: "read_aborted" };
        if (registered) return decide();
      }
      return decision;
    },
  };
}
