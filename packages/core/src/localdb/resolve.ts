import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  type ReadDecision,
  type ResolveInput,
} from "../stream-sync-read/service.js";
import { streamReadScope } from "../stream-sync-read/routing.js";
import { applyConnection } from "./apply.js";
import { nextApplied } from "./apply-progress.js";
import type { LocalSyncDeps } from "./deps.js";
import { readerOf } from "./driver.js";
import { completeBody, pinStream } from "./complete-read.js";
import { partialBody } from "./partial-read.js";
import type { RecordQuery } from "./query.js";
import {
  chooseCandidate,
  complete,
  connectionsOf,
  loadStreams,
  projectAlias,
  readability,
  selectForTarget,
  servedStreamOf,
  servedStreams,
  targetsForScope,
  tombstoned,
  tombstonedForRead,
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
   * `fetched` names the streams the read served, whether or not they had
   * rows: a stream left out of it was never read.
   */
  readonly project: (
    records: readonly LocalAliasRecord[],
    now: string,
    fetched: readonly string[],
  ) =>
    | { readonly ok: true; readonly payload: unknown }
    | { readonly ok: false; readonly error: { readonly kind: string } };
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

function bodyStream(chunks: AsyncIterable<string>): ReadableStream<Uint8Array> {
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

async function* single(text: string): AsyncGenerator<string> {
  yield text;
}

export function createLocalResolver(
  deps: LocalSyncDeps,
  parts: {
    readonly query: RecordQuery;
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
  },
): LocalResolver {
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
    const selected = candidate.target.streams.map((name) =>
      all.find((s) => s.stream === name),
    );
    if (selected.some((s) => s && tombstonedForRead(s, connection, true)))
      return deleted();
    const states = selected.map((s) =>
      s ? readability(s, connection, true) : "none",
    );
    if (states.includes("none")) return noData();
    if (!states.includes("partial")) return undefined;
    // A logical stream is one stream: an alias is never served partial.
    const stream = selected[0]!;
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
   * (see `completeBody`); one from a retained head or a projected alias is
   * built in memory here, so nothing it reads can change.
   */
  async function build(
    input: ResolveInput,
    candidate: Candidate,
  ): Promise<ReadDecision> {
    // A body of the database is pinned before the head is read: see
    // `pinStream`. An alias is built in memory below and needs no pin.
    const pin = candidate.target.alias
      ? 0
      : await pinStream(
          deps.db,
          candidate.connection.connection_id,
          candidate.target.streams[0]!,
        );
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

    let payload: AsyncIterable<string>;
    const binding = candidate.target.alias;
    if (!binding) {
      const only = installed[0]!;
      payload = completeBody(
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
      );
    } else {
      const projected = await projectAlias(
        binding,
        current,
        parts.query,
        new Date(deps.now()).toISOString(),
      );
      if (projected.kind === "too_large") {
        return { kind: "too_large", bytes: projected.bytes };
      }
      if (projected.kind === "no_data") return noData();
      payload = single(JSON.stringify(projected.payload));
    }
    const servedStream = servedStreamOf(candidate.target);
    const head = installed.find((s) => s.stream === servedStream)!;
    return {
      kind: "view",
      connector: connection.connector,
      ns: connection.ns,
      cursor,
      served: {
        scope: streamScope(connection.connector, connection.ns, servedStream),
        version: head.installed_version,
      },
      body: bodyStream(
        envelope(
          input.scope,
          Math.max(...installed.map((s) => s.observed_at ?? 0)),
          payload,
        ),
      ),
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
      // A stream that is still loading is served to its owner alone.
      const progressive = progressiveFirstLoad && input.isOwnerView;
      const candidates: Candidate[] = [];
      let sawDeleted = false;
      let sawForeign = false;
      let sawConnection = false;
      let sawActive = false;
      for (const target of targets) {
        let rows = await connections(target.connector);
        // applyConnection is the single-flight boundary and verifies keys before
        // installing rows. No rejected/foreign head is eligible for a DB read.
        for (const c of rows) {
          if (
            c.control_state === "active" &&
            c.deleted_at === null &&
            (input.connection === null || input.connection === c.ns)
          ) {
            await applyFor(c, target, progressive);
          }
        }
        rows = await connections(target.connector);
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
            connection.control_state !== "active" ||
            connection.deleted_at !== null
          )
            continue;
          loaded.push({
            connection,
            streams: await streams(connection.connection_id),
          });
        }
        const picked = selectForTarget(target, loaded, { progressive });
        if (picked.tombstoned) sawDeleted = true;
        if (picked.candidate) candidates.push(picked.candidate);
      }
      const chosen = chooseCandidate(candidates);
      if (!chosen) {
        if (sawDeleted) return deleted();
        if (sawForeign && !sawActive) return { kind: "key_mismatch" };
        if (input.cursor !== null) return { kind: "cursor_stale" };
        if (input.connection !== null && !sawConnection) {
          return { kind: "unavailable", reason: "connection_not_found" };
        }
        return noData();
      }
      if (chosen.partialStreams?.length) {
        const partial = await buildPartial({ ...input, scope }, chosen);
        if (partial) return partial;
      }
      // The queue is held to decide the headers and no longer: a body held it
      // until its reader finished or cancelled, which a reader that stopped
      // pulling never did, and every apply and read of the connection waited.
      // The body checks its head itself, on every page.
      return deps.queue.run(chosen.connection.connection_id, "end", () =>
        build({ ...input, scope }, chosen),
      );
    },
  };
}
