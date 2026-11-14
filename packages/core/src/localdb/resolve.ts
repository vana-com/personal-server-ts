import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  type ReadDecision,
  type ResolveInput,
} from "../stream-sync-read/service.js";
import { streamReadScope } from "../stream-sync-read/routing.js";
import { applyConnection } from "./apply.js";
import type { LocalSyncDeps } from "./deps.js";
import { createOlderVersions, type OlderVersions } from "./older-versions.js";
import type { RecordQuery } from "./query.js";
import {
  chooseCandidate,
  complete,
  connectionsOf,
  loadStreams,
  projectAlias,
  selectForTarget,
  servedStreamOf,
  targetsForScope,
  tombstoned,
  type Candidate,
  type Connection,
  type Stream,
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
  readonly servedStream?: string;
  readonly windowed?: boolean;
  readonly project: (
    records: readonly LocalAliasRecord[],
    now: string,
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
          b: s.head_version,
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

function bodyStream(
  chunks: AsyncIterable<string>,
  release: () => void,
): ReadableStream<Uint8Array> {
  const iterator = chunks[Symbol.asyncIterator]();
  let finished = false;
  const finish = () => {
    if (!finished) {
      finished = true;
      release();
    }
  };
  return new ReadableStream({
    async pull(controller) {
      try {
        const next = await iterator.next();
        if (next.done) {
          controller.close();
          finish();
        } else controller.enqueue(encoder.encode(next.value));
      } catch (error) {
        controller.error(error);
        finish();
      }
    },
    async cancel() {
      try {
        await iterator.return?.(undefined);
      } finally {
        finish();
      }
    },
  });
}

async function* rawPayload(
  query: RecordQuery,
  connectionId: string,
  stream: string,
): AsyncGenerator<string> {
  yield '{"records":[';
  let first = true;
  for await (const record of query.streamRecords(connectionId, stream)) {
    yield (first ? "" : ",") + record.body;
    first = false;
  }
  yield "]}";
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
    readonly olderVersions: OlderVersions;
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
  },
): LocalResolver {
  const completeReads = createOlderVersions(deps, { enabled: () => true });
  const streams = (connectionId: string): Promise<Stream[]> =>
    loadStreams(deps, connectionId);

  const connections = (connector: string): Promise<Connection[]> =>
    connectionsOf(deps, connector);

  async function build(
    input: ResolveInput,
    candidate: Candidate,
    release: () => void,
  ): Promise<ReadDecision> {
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
    const selected = candidate.target.streams.map((name) =>
      all.find((s) => s.stream === name),
    );
    if (selected.some((s) => s && tombstoned(s))) return deleted();
    if (selected.some((s) => !s || !complete(s, connection))) return noData();
    const installed = selected as Stream[];
    const current = { ...candidate, connection, streams: installed };
    const cursor = cursorFor(current);
    if (input.cursor !== null && input.cursor !== cursor)
      return { kind: "cursor_stale" };

    const fallback = new Map<string, readonly Record<string, unknown>[]>();
    for (const stream of installed) {
      if (stream.head_version === stream.installed_version) continue;
      const body = await completeReads.read(
        streamScope(connection.connector, connection.ns, stream.stream),
        { fileId: stream.head_blob! },
      );
      if (body === "gone") return noData();
      fallback.set(
        stream.stream,
        (await new Response(body).json()) as Record<string, unknown>[],
      );
    }
    const readQuery: RecordQuery = {
      ...parts.query,
      async *streamRecords(connectionId, stream) {
        const retained = fallback.get(stream);
        if (!retained) {
          yield* parts.query.streamRecords(connectionId, stream);
          return;
        }
        for (const row of retained)
          yield {
            stream,
            recordKey: "",
            pkHash: "",
            body: JSON.stringify(row),
            emittedAt: 0,
          };
      },
    };
    let payload: AsyncIterable<string>;
    const binding = candidate.target.alias;
    if (!binding) {
      payload = rawPayload(
        readQuery,
        connection.connection_id,
        installed[0]!.stream,
      );
    } else {
      const projected = await projectAlias(
        binding,
        current,
        readQuery,
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
        version: head.head_version,
      },
      body: bodyStream(
        envelope(
          input.scope,
          Math.max(...installed.map((s) => s.observed_at ?? 0)),
          payload,
        ),
        release,
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
            await applyConnection(deps, c.connection_id);
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
        const picked = selectForTarget(target, loaded);
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
      // Keep the queue until EOF/cancel: otherwise a paged body could contain
      // records from a newer apply while its served value names the old head.
      return new Promise<ReadDecision>((resolve, reject) => {
        void deps.queue
          .run(chosen.connection.connection_id, "end", async () => {
            let release!: () => void;
            const done = new Promise<void>((r) => {
              release = r;
            });
            const decision = await build({ ...input, scope }, chosen, release);
            resolve(decision);
            if ("body" in decision) await done;
          })
          .catch(reject);
      });
    },
  };
}
