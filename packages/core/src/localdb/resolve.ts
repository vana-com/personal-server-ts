import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  projectPdppRecordsToLegacyPayload,
  type PdppRecord,
} from "../legacy-projection/index.js";
import {
  readTargets,
  type ReadDecision,
  type ResolveInput,
} from "../stream-sync-read/service.js";
import { streamReadScope } from "../stream-sync-read/routing.js";
import { applyConnection } from "./apply.js";
import type { LocalSyncDeps } from "./deps.js";
import { createOlderVersions, type OlderVersions } from "./older-versions.js";
import type { RecordQuery } from "./query.js";

/**
 * D.1: serve the latest complete head above the deletion floor. When the
 * installed image is incomplete, fetch the retained complete head instead.
 * This current-read fallback is independent of optional historical reads.
 */
export interface LocalResolver {
  resolve(input: ResolveInput): Promise<ReadDecision>;
}

type Target = ReturnType<typeof readTargets>[number];
type Connection = {
  connection_id: string;
  connector: string;
  ns: string;
  generation: number;
  control_state: string;
  deleted_at: number | null;
};
type Stream = {
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
type Candidate = {
  target: Target;
  connection: Connection;
  streams: Stream[];
  registered: number;
};

const encoder = new TextEncoder();
const ARRAY_BUDGET = 64 * 1024 * 1024;
const noData = (): ReadDecision => ({ kind: "unavailable", reason: "no_data" });
const deleted = (): ReadDecision => ({
  kind: "unavailable",
  reason: "deleted",
});
const tombstoned = (s: Stream) =>
  s.last_delete_version > 0 && s.head_version <= s.last_delete_version;
const live = (s: Stream, c: Connection) =>
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
const complete = (s: Stream, c: Connection) =>
  live(s, c) && s.complete === 1 && s.version_complete === 1;

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
  parts: { readonly query: RecordQuery; readonly olderVersions: OlderVersions },
): LocalResolver {
  const completeReads = createOlderVersions(deps, { enabled: () => true });
  async function streams(connectionId: string): Promise<Stream[]> {
    return deps.db.query<Stream>(
      `SELECT s.head_version AS installed_version, s.stream, s.profile_key, s.profile_version, s.primary_key,
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
       WHERE s.connection_id = ? ORDER BY s.stream`,
      [connectionId],
    );
  }

  async function connections(connector: string): Promise<Connection[]> {
    return deps.db.query<Connection>(
      `SELECT connection_id, connector, ns, generation, control_state, deleted_at
       FROM connections WHERE connector = ? ORDER BY ns`,
      [connector],
    );
  }

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
    const binding = candidate.target.binding;
    if (!binding) {
      payload = rawPayload(
        readQuery,
        connection.connection_id,
        installed[0]!.stream,
      );
    } else {
      // Check all input heads, before reading even one record or creating a body.
      if (installed.some((s) => s.profile_key !== candidate.target.connector)) {
        return noData();
      }
      const options = {
        fetchedStreams: [...candidate.target.streams],
        profileKey: candidate.target.connector,
        orderByPrimaryKey: true,
        now: new Date(deps.now()).toISOString(),
      };
      if (binding.window) {
        const probe = projectPdppRecordsToLegacyPayload(
          input.scope,
          [],
          options,
        );
        if (!probe.ok && String(probe.error.kind).includes("profile"))
          return noData();
      }
      const records: PdppRecord[] = [];
      let bytes = 0;
      for (const stream of candidate.target.streams) {
        for await (const record of readQuery.streamRecords(
          connection.connection_id,
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
      const projected = projectPdppRecordsToLegacyPayload(
        input.scope,
        records,
        options,
      );
      if (!projected.ok) return noData();
      payload = single(JSON.stringify(projected.payload));
    }
    const servedStream =
      binding?.window?.parentStream ?? candidate.target.streams[0]!;
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
      const targets = readTargets(scope);
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
        const active: Candidate[] = [];
        for (const c of rows.filter(
          (c) => c.control_state === "active" && c.deleted_at === null,
        )) {
          const all = await streams(c.connection_id);
          const rank = all
            .filter((s) => live(s, c))
            .map((s) => s.observed_at ?? 0);
          active.push({
            target,
            connection: c,
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
        if (!selected) continue;
        if (selected.streams.some(tombstoned)) {
          sawDeleted = true;
          continue;
        }
        if (
          selected.streams.length === target.streams.length &&
          selected.streams.every((s) => complete(s, selected.connection))
        ) {
          candidates.push(selected);
        }
      }
      candidates.sort(
        (a, b) =>
          b.registered - a.registered ||
          a.target.connector.localeCompare(b.target.connector),
      );
      const chosen = candidates[0];
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
