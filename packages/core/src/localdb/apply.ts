import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalJson,
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  decodePart,
  deriveKeyCheck,
  framesOfParts,
  headBlobName,
  isPlainObject,
  parseScope,
  partBlobName,
  pkHash,
  streamScope,
  toHex,
  verifyHead,
  type ControlHashes,
  type Head,
  type HeadPart,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { ConnectionQueue, LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { applyDelete, mergeIncoming, withOrigin } from "./merge.js";
import { purgeConnection } from "./purge.js";

/** What one apply did, for the caller's status line. */
export interface ApplyResult {
  readonly stream: string;
  readonly outcome: "applied" | "noop" | "purged" | "gone";
  readonly partsDownloaded: number;
  readonly partsKept: number;
}

type Connection = {
  connector: string;
  ns: string;
  generation: number;
  control_version: number;
};
type State = {
  primary_key: string;
  last_delete_version: number;
  head_version: number;
  head_generation: number | null;
  head_data_hash: string | null;
  head_format: number | null;
};
type SavedPart = {
  prefix: string;
  seq: number;
  part_hash: string;
  bytes: number;
  count: number;
};
const sha = async (bytes: Uint8Array) => sha256(bytes);
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);
const result = (
  stream: string,
  outcome: ApplyResult["outcome"],
): ApplyResult => ({ stream, outcome, partsDownloaded: 0, partsKept: 0 });

// The queue's apply single-flight is connection-wide. Accumulate requests in
// that same flight so two different applyStream calls cannot lose a stream.
type Flight = {
  all: boolean;
  streams: Set<string>;
  promise: Promise<readonly ApplyResult[]>;
};
const flights = new WeakMap<ConnectionQueue, Map<string, Flight>>();
function request(deps: LocalSyncDeps, id: string, stream?: string) {
  let pending = flights.get(deps.queue);
  if (!pending) {
    pending = new Map();
    flights.set(deps.queue, pending);
  }
  const running = pending.get(id);
  if (running) {
    if (stream === undefined) running.all = true;
    else running.streams.add(stream);
    return running.promise;
  }
  const flight: Flight = {
    all: stream === undefined,
    streams: new Set(stream === undefined ? [] : [stream]),
    promise: Promise.resolve([]),
  };
  pending.set(id, flight);
  flight.promise = deps.queue
    .run(id, "apply", async () => {
      // Purge is a nested operation; this job already holds this connection.
      const locked: LocalSyncDeps = {
        ...deps,
        queue: {
          run: (other, kind, work) =>
            other === id ? work() : deps.queue.run(other, kind, work),
        },
      };
      const [connection] = await deps.db.query<Connection>(
        "SELECT connector, ns, generation, control_version FROM connections WHERE connection_id = ?",
        [id],
      );
      if (!connection) return [...flight.streams].map((s) => result(s, "gone"));
      if (
        (
          await deps.db.query(
            "SELECT 1 FROM delete_intents WHERE connector=?",
            [connection.connector],
          )
        ).length
      ) {
        await purgeConnection(locked, id, {
          controlVersion: connection.control_version,
        });
        if (flight.all)
          for (const row of await deps.db.query<{ stream: string }>(
            "SELECT stream FROM stream_state WHERE connection_id=?",
            [id],
          ))
            flight.streams.add(row.stream);
        return [...flight.streams].map((s) => result(s, "purged"));
      }
      const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
      const hashes = await controlHashes(keccak, keyCheck);
      const initial = await control(locked, id, connection, hashes);
      if (initial.kind !== "active") {
        if (flight.all)
          for (const row of await deps.db.query<{ stream: string }>(
            "SELECT stream FROM stream_state WHERE connection_id=?",
            [id],
          ))
            flight.streams.add(row.stream);
        return [...flight.streams].map((s) =>
          result(s, initial.kind === "deleted" ? "purged" : "gone"),
        );
      }
      const answers = new Map<string, ApplyResult>();
      let listed = false;
      while (true) {
        if (flight.all && !listed) {
          for (const row of await deps.registry.listStreamRows(
            connection.connector,
          )) {
            const scope = parseScope(row.scope);
            if (
              scope?.kind === "stream" &&
              scope.connector === connection.connector &&
              scope.ns === connection.ns
            )
              flight.streams.add(scope.stream);
          }
          listed = true;
        }
        const next = [...flight.streams].find((s) => !answers.has(s));
        if (next === undefined) break;
        answers.set(
          next,
          await applyOne(locked, id, connection, next, keyCheck, hashes),
        );
      }
      return [...answers.values()];
    })
    .finally(() => {
      if (pending.get(id) === flight) pending.delete(id);
    });
  return flight.promise;
}

/** Apply one stream; concurrent requests share the connection's apply job. */
export async function applyStream(
  deps: LocalSyncDeps,
  connectionId: string,
  stream: string,
): Promise<ApplyResult> {
  return (
    (await request(deps, connectionId, stream)).find(
      (r) => r.stream === stream,
    ) ?? result(stream, "gone")
  );
}

/** Apply every registry stream, including empty-parts repair after unwrite. */
export function applyConnection(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<readonly ApplyResult[]> {
  return request(deps, connectionId);
}

// A prefix range is safe to retain only when ALL its parts still match. Part
// boundaries are record boundaries, not key-range boundaries (and long frames
// span parts), so retaining a range for just one matching part would keep deletes.
function range(prefix: string): { lo: string; hi: string } {
  const n = prefix === "" ? 0 : parseInt(prefix, 2);
  const bits = BigInt(256 - prefix.length);
  return {
    lo: (BigInt(n) << bits).toString(16).padStart(64, "0"),
    hi:
      n + 1 === 2 ** prefix.length
        ? "g"
        : (BigInt(n + 1) << bits).toString(16).padStart(64, "0"),
  };
}

async function control(
  deps: LocalSyncDeps,
  id: string,
  connection: Connection,
  hashes: ControlHashes,
) {
  const read = await deps.registry.read(
    controlScope(connection.connector, connection.ns),
  );
  const state = classifyControl(read, hashes);
  if (state.kind === "deleted")
    await purgeConnection(deps, id, { controlVersion: state.version });
  if (state.kind === "active") {
    const old = await deps.db.query<{ generation: number }>(
      `SELECT head_generation AS generation FROM stream_state WHERE connection_id = ? AND head_generation IS NOT NULL AND head_generation <> ? LIMIT 1`,
      [id, state.generation],
    );
    if (connection.generation !== state.generation || old.length > 0) {
      await purgeConnection(deps, id, { controlVersion: state.generation - 1 });
      await deps.db.batch([
        {
          sql: `UPDATE stream_state SET head_version=0, head_generation=NULL, head_data_hash=NULL, head_blob=NULL, complete=0, last_delete_version=0, floor_version=NULL, floor_o=NULL, floor_r=NULL WHERE connection_id=?`,
          params: [id],
        },
      ]);
      connection.generation = state.generation;
    }
  }
  // Absence cannot clear a local-only delete; only an observed active row can.
  await deps.db.batch([
    {
      sql: `UPDATE connections SET control_state=?, control_version=?, generation=? WHERE connection_id=?
        AND NOT (control_state='deleted' AND ?='absent')`,
      params: [
        state.kind,
        read.found ? read.version : 0,
        state.kind === "active" ? state.generation : connection.generation,
        id,
        state.kind,
      ],
    },
  ]);
  return state;
}

async function applyOne(
  deps: LocalSyncDeps,
  id: string,
  connection: Connection,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
): Promise<ApplyResult> {
  const active = await control(deps, id, connection, hashes);
  if (active.kind !== "active")
    return result(stream, active.kind === "deleted" ? "purged" : "gone");
  const scope = streamScope(connection.connector, connection.ns, stream);
  const read = await deps.registry.read(scope);
  const classification = classifyStreamRow(read, hashes);
  if (!read.found || classification === "absent") return result(stream, "gone");
  if (classification === "tombstoned") {
    await deps.db.batch(
      withOrigin("purge", [
        {
          sql: "DELETE FROM records WHERE connection_id=? AND stream=?",
          params: [id, stream],
        },
        {
          sql: "DELETE FROM run_rows WHERE stream=? AND run_id IN (SELECT run_id FROM runs WHERE connection_id=?)",
          params: [stream, id],
        },
        {
          sql: "DELETE FROM head_parts WHERE connection_id=? AND stream=?",
          params: [id, stream],
        },
        {
          sql: "UPDATE stream_state SET complete=0, head_version=0, head_blob=NULL, head_data_hash=NULL, last_delete_version=? WHERE connection_id=? AND stream=?",
          params: [read.version, id, stream],
        },
      ]),
    );
    return result(stream, "purged");
  }
  const [state] = await deps.db.query<State>(
    `SELECT s.primary_key,s.last_delete_version,s.head_version,s.head_generation,s.head_data_hash,v.head_format FROM stream_state s LEFT JOIN stream_versions v ON v.connection_id=s.connection_id AND v.stream=s.stream AND v.version=s.head_version AND v.generation=s.head_generation WHERE s.connection_id=? AND s.stream=?`,
    [id, stream],
  );
  if (state && read.version <= state.last_delete_version)
    return result(stream, "gone");
  const saved = await deps.db.query<SavedPart>(
    "SELECT prefix,seq,part_hash,bytes,count FROM head_parts WHERE connection_id=? AND stream=? ORDER BY prefix,seq",
    [id, stream],
  );
  if (
    state?.head_version === read.version &&
    state.head_data_hash === read.dataHash &&
    state.head_generation === active.generation &&
    saved.length > 0
  )
    return result(stream, "noop");
  const blob = headBlobName(read.dataHash);
  const cipher = await deps.blobs.get(`${scope}/${blob}`);
  if (cipher === null) throw new Error("apply: missing head blob");
  const verified = await verifyHead(
    keccak,
    await deps.keys.decrypt(scope, cipher),
    {
      dataHash: read.dataHash,
      connector: connection.connector,
      ns: connection.ns,
      stream,
      keyCheck,
    },
  );
  if (verified.kind !== "ok")
    throw new Error(`apply: invalid head (${verified.kind})`);
  const { head } = verified;
  if (head.generation !== active.generation) return result(stream, "gone");
  const op = deps.newOp();
  let downloaded = 0;
  let kept = 0;
  const grouped = new Map<string, HeadPart[]>();
  for (const part of head.parts) {
    const group = grouped.get(part.prefix) ?? [];
    group.push(part);
    grouped.set(part.prefix, group);
  }
  const load = async (part: HeadPart) => {
    const bytes = await deps.blobs.get(
      `${scope}/${partBlobName(head.generation, part.hash)}`,
    );
    if (bytes === null) throw new Error("apply: missing part blob");
    downloaded++;
    return deps.keys.decrypt(scope, bytes);
  };
  try {
    for (const [prefix, parts] of grouped) {
      const previous = saved.filter((p) => p.prefix === prefix);
      if (
        state?.head_generation === head.generation &&
        state.primary_key === JSON.stringify(head.primaryKey) &&
        state.head_format === head.format &&
        previous.length === parts.length &&
        parts.every(
          (p, i) =>
            previous[i]!.seq === i &&
            previous[i]!.part_hash === p.hash &&
            previous[i]!.bytes === p.bytes &&
            previous[i]!.count === p.count,
        )
      ) {
        const { lo, hi } = range(prefix);
        await deps.db.batch([
          {
            sql: "INSERT INTO temp.keep_ranges (op,lo,hi) VALUES (?,?,?)",
            params: [op, lo, hi],
          },
        ]);
        kept += parts.length;
        continue;
      }
      if (head.format === 1) {
        for (const part of parts) {
          const lines = await decodePart(
            sha,
            await load(part),
            part,
            head.primaryKey,
          );
          const rows: SqlStatement[] = [];
          for (const { line } of lines)
            rows.push(
              ...(await stage(op, stream, head, line.v, line.o, line.r, null)),
            );
          await deps.db.batch(
            withOrigin("remote", [...rows, ...mergeIncoming(op, id)]),
          );
        }
      } else {
        // framesOfParts verifies hashes, counts, key order, prefix membership and
        // continuations. Only one part and one SQL record body are held at a time.
        let rows: SqlStatement[] = [];
        let records = 0;
        let end = parts[0];
        for await (const frame of framesOfParts(sha, parts, load, {
          generation: head.format >= 4 ? "v3" : "v2",
        })) {
          const digest = sha256.create();
          const decoder = new TextDecoder("utf-8", { fatal: true });
          let body = "";
          for await (const piece of frame.body()) {
            digest.update(piece);
            body += decoder.decode(piece, { stream: true });
          }
          body += decoder.decode();
          if (toHex(digest.digest()) !== frame.envelope.h)
            throw new Error("apply: invalid body hash");
          let value: unknown;
          try {
            value = JSON.parse(body);
          } catch {
            throw new Error("apply: invalid record JSON");
          }
          if (
            !isPlainObject(value) ||
            canonicalJson(value) !== body ||
            (await pkHash(sha, value, head.primaryKey)) !== frame.envelope.k
          )
            throw new Error("apply: invalid record");
          rows.push(
            ...(await stage(
              op,
              stream,
              head,
              value,
              frame.envelope.o,
              frame.envelope.r,
              frame.envelope.f ?? null,
            )),
          );
          records++;
          // A long frame is its own part run; otherwise commit at the end of
          // the part, before the reader loads another part.
          if (frame.parts[0] !== end) {
            end = frame.parts[0];
          }
          if (records === end!.count || frame.parts.length > 1) {
            await deps.db.batch(
              withOrigin("remote", [...rows, ...mergeIncoming(op, id)]),
            );
            rows = [];
            records = 0;
            end =
              parts[parts.indexOf(frame.parts[frame.parts.length - 1]!) + 1];
          }
        }
        if (rows.length > 0) throw new Error("apply: incomplete part");
      }
    }
    const stillActive = await control(deps, id, connection, hashes);
    if (
      stillActive.kind !== "active" ||
      stillActive.generation !== active.generation
    )
      return result(stream, stillActive.kind === "deleted" ? "purged" : "gone");
    const latest = await deps.registry.read(scope);
    if (
      !latest.found ||
      latest.version !== read.version ||
      latest.dataHash !== read.dataHash ||
      classifyStreamRow(latest, hashes) !== "present"
    )
      throw new Error("apply: stream changed during download");
    const statements: SqlStatement[] = [
      {
        sql: `INSERT OR IGNORE INTO stream_state (connection_id,stream,primary_key,semantics,incremental) VALUES (?,?,?,'mutable_state',1)`,
        params: [id, stream, JSON.stringify(head.primaryKey)],
      },
      ...applyDelete(op, id, stream),
      {
        sql: `UPDATE stream_state SET primary_key=?,profile_key=?,profile_version=?,complete=?,head_version=?,head_generation=?,head_data_hash=?,head_blob=?,last_delete_version=? WHERE connection_id=? AND stream=?`,
        params: [
          JSON.stringify(head.primaryKey),
          head.profile.key,
          head.profile.version,
          head.complete ? 1 : 0,
          read.version,
          head.generation,
          read.dataHash,
          blob,
          Math.max(
            state?.last_delete_version ?? 0,
            head.lastDeleteVersion ?? 0,
          ),
          id,
          stream,
        ],
      },
      {
        sql: "DELETE FROM head_parts WHERE connection_id=? AND stream=?",
        params: [id, stream],
      },
      {
        sql: `INSERT OR REPLACE INTO stream_versions (connection_id,stream,version,generation,head_blob,head_format,record_count,observed_at,complete,kind) VALUES (?,?,?,?,?,?,?,?,?,'applied')`,
        params: [
          id,
          stream,
          read.version,
          head.generation,
          blob,
          head.format,
          head.recordCount,
          head.observedAt,
          head.complete ? 1 : 0,
        ],
      },
    ];
    for (const [prefix, parts] of grouped)
      parts.forEach((part, seq) =>
        statements.push({
          sql: "INSERT INTO head_parts (connection_id,stream,prefix,seq,part_hash,bytes,count) VALUES (?,?,?,?,?,?,?)",
          params: [id, stream, prefix, seq, part.hash, part.bytes, part.count],
        }),
      );
    await deps.db.batch(withOrigin("remote", statements));
    return {
      stream,
      outcome: "applied",
      partsDownloaded: downloaded,
      partsKept: kept,
    };
  } finally {
    await deps.db.batch(
      ["incoming", "apply_keys", "keep_ranges"].map((table) => ({
        sql: `DELETE FROM temp.${table} WHERE op=?`,
        params: [op],
      })),
    );
  }
}

async function stage(
  op: string,
  stream: string,
  head: Head,
  value: JsonObject,
  o: number,
  r: string,
  f: number | null,
): Promise<SqlStatement[]> {
  const body = canonicalJson(value);
  const key = await pkHash(sha, value, head.primaryKey);
  return [
    {
      sql: `INSERT INTO temp.incoming (op,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256,first_o) VALUES (?,?,?,?,?,?,?,?,?)`,
      params: [
        op,
        stream,
        key,
        computeRecordKeyFromData(value, [...head.primaryKey]),
        o,
        r,
        body,
        toHex(sha256(new TextEncoder().encode(body))),
        f,
      ],
    },
    {
      sql: "INSERT OR IGNORE INTO temp.apply_keys (op,pk_hash) VALUES (?,?)",
      params: [op, key],
    },
  ];
}
