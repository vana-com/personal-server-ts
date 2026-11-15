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
  isLogStream,
  omissionCutoff,
  parseScope,
  partBlobName,
  pkHash,
  streamScope,
  toHex,
  verifyHead,
  type ControlHashes,
  type ControlRead,
  type Head,
  type HeadPart,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeRecordKeyFromData } from "../storage/pdpp-records/record-key.js";
import type { ConnectionQueue, LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";
import { announceApplied } from "./apply-progress.js";
import { applyDelete, mergeIncoming, withOrigin } from "./merge.js";
import {
  endsEarlierLifetime,
  hydrateLifetimeBoundary,
  olderLifetimeFence,
} from "./lifetime-boundary.js";
import { applyLog } from "./log-apply.js";
import { purgeConnection } from "./purge.js";
import {
  RegistryUnavailableBeforeWriteError,
  RegistryUnavailableError,
} from "../stream-sync/ports.js";

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
  apply_partial: number;
};
type State = {
  primary_key: string;
  complete: number;
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
/**
 * Apply has no rollback, so before a job's first write it records, in the
 * database, that the connection may be partly applied. The mark is committed
 * ahead of the write: a crash between the two leaves a mark with nothing
 * written, which only asks for a repair. It outlives the job and a restart. An
 * apply of the whole connection that completes clears it.
 */
async function markPartial(deps: LocalSyncDeps, id: string, job: Reuse) {
  if (job.partial) return;
  job.partial = true;
  await deps.db.batch([
    {
      sql: "UPDATE connections SET apply_partial=1 WHERE connection_id=?",
      params: [id],
    },
  ]);
}

async function clearPartial(deps: LocalSyncDeps, id: string, job: Reuse) {
  if (!job.partial) return;
  await deps.db.batch([
    {
      sql: "UPDATE connections SET apply_partial=0 WHERE connection_id=?",
      params: [id],
    },
  ]);
  job.partial = false;
}

const sha = async (bytes: Uint8Array) => sha256(bytes);
const keccak = async (bytes: Uint8Array) => keccak_256(bytes);
const result = (
  stream: string,
  outcome: ApplyResult["outcome"],
): ApplyResult => ({ stream, outcome, partsDownloaded: 0, partsKept: 0 });

// A connection's apply work runs in flights, one at a time. A flight answers
// only the callers admitted before it started: its registry reads are all
// taken after each of those calls began. A caller arriving while a flight runs
// joins the one pending next flight, which starts when this one exits and
// takes its own reads. A caller settles when its own flight ends, so a late
// caller's work or failure never reaches an earlier one, and no stream of
// arrivals can keep a flight open.
type Flight = {
  all: boolean;
  streams: Set<string>;
  /** Closed at the start of the job; later callers join the next flight. */
  closed: boolean;
  promise: Promise<readonly ApplyResult[]>;
};
type Slot = { running: Flight; next?: Flight };
const slots = new WeakMap<ConnectionQueue, Map<string, Slot>>();
function request(deps: LocalSyncDeps, id: string, stream?: string) {
  let byId = slots.get(deps.queue);
  if (!byId) {
    byId = new Map();
    slots.set(deps.queue, byId);
  }
  const join = (flight: Flight) => {
    if (stream === undefined) flight.all = true;
    else flight.streams.add(stream);
    return flight.promise;
  };
  const slot = byId.get(id);
  if (slot) {
    if (!slot.running.closed) return join(slot.running);
    if (slot.next) return join(slot.next);
    const next = newFlight();
    slot.next = next;
    next.promise = slot.running.promise
      .then(
        () => undefined,
        () => undefined,
      )
      .then(() => launch(deps, id, next, byId, slot));
    return join(next);
  }
  const flight = newFlight();
  const created: Slot = { running: flight };
  byId.set(id, created);
  flight.promise = launch(deps, id, flight, byId, created);
  return join(flight);
}
const newFlight = (): Flight => ({
  all: false,
  streams: new Set(),
  closed: false,
  promise: Promise.resolve([]),
});
function launch(
  deps: LocalSyncDeps,
  id: string,
  flight: Flight,
  byId: Map<string, Slot>,
  slot: Slot,
): Promise<readonly ApplyResult[]> {
  return runFlight(deps, id, flight).finally(() => {
    if (slot.next) {
      slot.running = slot.next;
      slot.next = undefined;
    } else if (byId.get(id) === slot) byId.delete(id);
  });
}
function runFlight(deps: LocalSyncDeps, id: string, flight: Flight) {
  const reuse: Reuse = {
    listed: new Map(),
    stale: false,
    partial: false,
    proved: new Set(),
  };
  return runJob(deps, id, flight, reuse).catch((error: unknown) => {
    throw error instanceof RegistryUnavailableError && !reuse.partial
      ? new RegistryUnavailableBeforeWriteError(error)
      : error;
  });
}
function runJob(deps: LocalSyncDeps, id: string, flight: Flight, reuse: Reuse) {
  return deps.queue.run(id, "apply", async () => {
    flight.closed = true;

    // Purge is a nested operation; this job already holds this connection.
    const locked: LocalSyncDeps = {
      ...deps,
      queue: {
        run: (other, kind, work) =>
          other === id ? work() : deps.queue.run(other, kind, work),
      },
    };
    const [connection] = await deps.db.query<Connection>(
      "SELECT connector, ns, generation, apply_partial FROM connections WHERE connection_id = ?",
      [id],
    );
    if (!connection) return [...flight.streams].map((s) => result(s, "gone"));
    reuse.partial = connection.apply_partial === 1;
    if (
      (
        await deps.db.query("SELECT 1 FROM delete_intents WHERE connector=?", [
          connection.connector,
        ])
      ).length
    ) {
      // Only the pinned delete owner may purge this intent. Another device
      // can have reconnected after its pins were captured.
      await deps.db.batch([
        {
          sql: "UPDATE connections SET control_state='deleted',checkpoint=NULL WHERE connection_id=?",
          params: [id],
        },
      ]);
      if (flight.all)
        for (const row of await deps.db.query<{ stream: string }>(
          "SELECT stream FROM stream_state WHERE connection_id=?",
          [id],
        ))
          flight.streams.add(row.stream);
      return [...flight.streams].map((s) => result(s, "gone"));
    }
    const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
    const hashes = await controlHashes(keccak, keyCheck);
    const initial = await control(locked, id, connection, hashes, reuse);
    if (initial.kind !== "active") {
      if (flight.all)
        for (const row of await deps.db.query<{ stream: string }>(
          "SELECT stream FROM stream_state WHERE connection_id=?",
          [id],
        ))
          flight.streams.add(row.stream);
      // A purged connection has nothing left to repair.
      if (initial.kind === "deleted") await clearPartial(deps, id, reuse);
      return [...flight.streams].map((s) =>
        result(s, initial.kind === "deleted" ? "purged" : "gone"),
      );
    }
    const answers = new Map<string, ApplyResult>();
    reuse.control = initial;
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
          ) {
            // The log row is read by `applyLog`, never as a stream head.
            if (isLogStream(scope.stream)) {
              reuse.log = row.read;
              continue;
            }
            flight.streams.add(scope.stream);
            reuse.listed.set(scope.stream, row.read);
          }
        }
        listed = true;
      }
      const next = [...flight.streams].find((s) => !answers.has(s));
      if (next === undefined) break;
      answers.set(
        next,
        await applyOne(locked, id, connection, next, keyCheck, hashes, reuse),
      );
    }
    if (deps.logProtocol && flight.all) {
      // Streams published before the log, then the log on top of them.
      const [now] = await deps.db.query<{
        generation: number;
        control_state: string;
      }>(
        "SELECT generation, control_state FROM connections WHERE connection_id = ?",
        [id],
      );
      if (
        now?.control_state === "active" &&
        now.generation === initial.generation
      )
        await applyLog(locked, id, {
          connector: connection.connector,
          ns: connection.ns,
          generation: initial.generation,
          keyCheck,
          hashes,
          // A listing taken before a stream downloaded may predate a segment.
          read: reuse.stale ? undefined : reuse.log,
        });
    }
    // The mark clears only on proof of repair: a whole-connection apply in
    // which every stream ended in an answer that settled it (see `proved`).
    // A stream that gave up for any reason leaves the mark in place.
    if (flight.all && [...answers.keys()].every((s) => reuse.proved.has(s)))
      await clearPartial(deps, id, reuse);
    return [...answers.values()];
  });
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
  reuse: Reuse,
) {
  const read = await deps.registry.read(
    controlScope(connection.connector, connection.ns),
  );
  const state = classifyControl(read, hashes);
  // A stale active read cannot undo a deletion this device already observed.
  // Check before purging/resetting stream state as well as before the row update.
  const [local] = await deps.db.query<{
    control_state: string;
    control_version: number;
  }>(
    "SELECT control_state,control_version FROM connections WHERE connection_id=?",
    [id],
  );
  if (
    state.kind === "active" &&
    local?.control_state === "deleted" &&
    state.generation <= local.control_version
  )
    return { kind: "deleted" as const, version: local.control_version };
  if (state.kind === "deleted") {
    await markPartial(deps, id, reuse);
    await purgeConnection(deps, id, { controlVersion: state.version });
  }
  if (state.kind === "active") {
    const old = await deps.db.query<{ generation: number }>(
      `SELECT head_generation AS generation FROM stream_state WHERE connection_id = ? AND head_generation IS NOT NULL AND head_generation <> ? LIMIT 1`,
      [id, state.generation],
    );
    if (connection.generation !== state.generation || old.length > 0) {
      await markPartial(deps, id, reuse);
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

/**
 * Freshness contract. Each ApplyResult reflects registry reads taken after
 * the call that requested that stream began. A flight is admitted before its
 * first read, so the control read and listing it holds are fresh for every
 * caller it answers. A stream reuses them only while nothing has downloaded
 * since (a download's duration is the one window long enough to matter), and a
 * stream that would delete local data never does. The base's per-stream entry
 * read made the same promise. A registry snapshot sequence number would make
 * it checkable.
 */
interface Reuse {
  control?: Awaited<ReturnType<typeof control>>;
  listed: Map<string, ControlRead>;
  /** The log row from the listing, when the flight listed. */
  log?: ControlRead;
  /** A stream has downloaded since the job's reads were taken. */
  stale: boolean;
  /**
   * Local data may hold a partial apply: this job has begun a write (a purge,
   * a reset, a stream replaced or tombstoned), or an earlier job did and no
   * apply of the whole connection has completed since
   * (`connections.apply_partial`). The control row's own bookkeeping update
   * does not count: it records what the registry said.
   */
  partial: boolean;
  /**
   * Streams whose answer settled them against an active control of their
   * generation: applied through the final commit, already current, already past
   * a consumed delete, purged, or an earlier lifetime's fence stored. A stream
   * that answered "gone" because its control, row or head moved is not in the
   * set: whatever it merged stays unrepaired. Nothing else clears the mark.
   */
  proved: Set<string>;
}

/**
 * Apply one stream. Work that ends before the download, on reads that predate
 * an earlier stream's download, runs again on fresh reads.
 */
async function applyOne(
  deps: LocalSyncDeps,
  id: string,
  connection: Connection,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
  reuse: Reuse,
): Promise<ApplyResult> {
  return (
    (await applyOneOnce(
      deps,
      id,
      connection,
      stream,
      keyCheck,
      hashes,
      reuse,
      false,
    )) ??
    (await applyOneOnce(
      deps,
      id,
      connection,
      stream,
      keyCheck,
      hashes,
      reuse,
      true,
    ))!
  );
}

/** Returns undefined when reused reads are stale and the stream must rerun. */
async function applyOneOnce(
  deps: LocalSyncDeps,
  id: string,
  connection: Connection,
  stream: string,
  keyCheck: string,
  hashes: ControlHashes,
  reuse: Reuse,
  fresh: boolean,
): Promise<ApplyResult | undefined> {
  const fence = fresh ? undefined : reuse.control;
  const listedRead = fresh ? undefined : reuse.listed.get(stream);
  const reused = fence !== undefined || listedRead !== undefined;
  const rerun = reuse.stale && reused;
  const early = (answer: ApplyResult) => (rerun ? undefined : answer);
  // An answer that settles the stream. Only these let a whole apply clear the
  // half-applied mark.
  const settled = (answer: ApplyResult) => {
    const out = early(answer);
    if (out) reuse.proved.add(stream);
    return out;
  };
  const active = fence ?? (await control(deps, id, connection, hashes, reuse));
  if (active.kind !== "active")
    return active.kind === "deleted"
      ? settled(result(stream, "purged"))
      : early(result(stream, "gone"));
  const scope = streamScope(connection.connector, connection.ns, stream);
  const read = listedRead ?? (await deps.registry.read(scope));
  const classification = classifyStreamRow(read, hashes);
  if (!read.found || classification === "absent")
    return early(result(stream, "gone"));
  const [state] = await deps.db.query<State>(
    `SELECT s.primary_key,s.complete,s.last_delete_version,s.head_version,s.head_generation,s.head_data_hash,v.head_format FROM stream_state s LEFT JOIN stream_versions v ON v.connection_id=s.connection_id AND v.stream=s.stream AND v.version=s.head_version AND v.generation=s.head_generation WHERE s.connection_id=? AND s.stream=?`,
    [id, stream],
  );
  if (classification === "tombstoned") {
    // A tombstone this device already consumed deleted nothing new. Rows a
    // collection staged or committed after that fence are newer than the
    // delete and stay; only a later delete version purges them.
    if (state && read.version <= state.last_delete_version)
      return settled(result(stream, "noop"));
    // A purge is destructive: never decide it on reused reads.
    if (reused) return undefined;
    await markPartial(deps, id, reuse);
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
          sql: "DELETE FROM stream_partial WHERE connection_id=? AND stream=?",
          params: [id, stream],
        },
        {
          sql: "UPDATE stream_state SET complete=0, head_version=0, head_blob=NULL, head_data_hash=NULL, last_delete_version=? WHERE connection_id=? AND stream=?",
          params: [read.version, id, stream],
        },
        {
          sql: "UPDATE connections SET checkpoint=NULL WHERE connection_id=?",
          params: [id],
        },
      ]),
    );
    reuse.proved.add(stream);
    return result(stream, "purged");
  }
  if (state && read.version <= state.last_delete_version)
    return settled(result(stream, "gone"));
  // With the log on, a stream the log wrote reads from a local version above
  // the registry's own stream row (see `applySegmentOperations`): that row is
  // older than what this device holds and replaces nothing. The answer is a
  // version comparison and reads no data, so it proves nothing about rows an
  // earlier failed apply of a newer per-stream head merged: neither this row
  // nor the log holds them. While the connection is marked partial it is not
  // `settled`, the mark stays, and only a read of a head that replaces the
  // stream (or a rebuild) clears it. Dropping the shortcut instead would replay
  // an older head over valid log state.
  if (deps.logProtocol && state && state.head_version > read.version) {
    const answer = result(stream, "noop");
    return reuse.partial ? early(answer) : settled(answer);
  }
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
    return settled(result(stream, "noop"));
  const blob = headBlobName(read.dataHash);
  const cipher = await deps.blobs.get(`${scope}/${blob}`);
  if (cipher === null) {
    if (rerun) return undefined;
    throw new Error("apply: missing head blob");
  }
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
  if (verified.kind !== "ok") {
    if (rerun) return undefined;
    throw new Error(`apply: invalid head (${verified.kind})`);
  }
  const { head } = verified;
  if (head.generation < active.generation) {
    // This writes stream state: never decide it on reused reads.
    if (reused) return undefined;
    await markPartial(deps, id, reuse);
    // A head of an earlier lifetime (a delete marker). It is no content base:
    // keep only its delete fence, so a run that begins now pins it.
    await hydrateLifetimeBoundary(deps, {
      connectionId: id,
      stream,
      generation: active.generation,
      fence: olderLifetimeFence(scope, read, head, active.generation),
      provenEarlier: endsEarlierLifetime(scope, read, active.generation),
      primaryKey: head.primaryKey,
    });
    reuse.proved.add(stream);
    return result(stream, "gone");
  }
  if (head.generation !== active.generation)
    return early(result(stream, "gone"));
  // From here the stream reaches the final rechecks, so the job's earlier
  // reads stay usable for it. They are stale for any stream that ends early.
  reuse.control = undefined;
  reuse.stale = true;
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
  // A stream with no complete head loads progressively, when asked: each
  // part's commit also moves the stream's partial row, so a reader sees the
  // applied parts of this one head (see `stream_partial`).
  const hasCompleteHead =
    state !== undefined &&
    state.complete === 1 &&
    state.head_version > state.last_delete_version &&
    state.head_generation === head.generation;
  // With the log on, a connection that has a log is finished by `applyLog`
  // after its heads: the log can delete or replace rows a head holds. A
  // partial view of a head would show rows the finished result lacks, so such
  // a connection does not load progressively. A connection with no log, and a
  // device with the log off, do.
  const progressive =
    deps.progressiveFirstLoad === true &&
    head.complete &&
    !hasCompleteHead &&
    !(
      deps.logProtocol === true &&
      (reuse.log !== undefined ||
        (
          await deps.db.query(
            "SELECT 1 FROM log_state WHERE connection_id = ?",
            [id],
          )
        ).length > 0)
    );
  const [marker] = progressive
    ? await deps.db.query<{
        version: number;
        generation: number;
        data_hash: string;
      }>(
        "SELECT version,generation,data_hash FROM stream_partial WHERE connection_id=? AND stream=?",
        [id, stream],
      )
    : [];
  const sameHead =
    marker !== undefined &&
    marker.version === read.version &&
    marker.generation === head.generation &&
    marker.data_hash === read.dataHash;
  let began = false;
  // Parts applied, kept parts included. A row of a kept part is of this head.
  let applied = 0;
  // `head_parts` says which parts the local rows of each range were built
  // from. Merged rows make that untrue until the final commit rewrites it, so
  // the first commit that merges rows drops it, in the same batch, whether or
  // not the load is progressive. A failed apply then leaves no claim for the
  // keep and noop shortcuts to trust; the next one reads the stream whole.
  let cached = true;
  const commit = async (rows: SqlStatement[]) => {
    const begin: SqlStatement[] = cached
      ? [
          {
            sql: "DELETE FROM head_parts WHERE connection_id=? AND stream=?",
            params: [id, stream],
          },
        ]
      : [];
    cached = false;
    if (!began) {
      began = true;
      if (!progressive) {
        // Whatever load a marker names ends: this commit writes rows of
        // another head, or of one no reader may show.
        begin.push({
          sql: "DELETE FROM stream_partial WHERE connection_id=? AND stream=?",
          params: [id, stream],
        });
      } else {
        // The stream's row, which a first load has none of yet.
        begin.push({
          sql: `INSERT OR IGNORE INTO stream_state (connection_id,stream,primary_key,semantics,incremental) VALUES (?,?,?,'mutable_state',1)`,
          params: [id, stream, JSON.stringify(head.primaryKey)],
        });
        // A head the load did not begin hides every row the stream holds
        // outside the unchanged parts, in this same transaction as the first
        // part. Nothing is deleted: only the complete state decides which of
        // them go (a row seen again since the head's cutoff, a local change
        // not yet published, a key a later part holds). A part shows its
        // keys by taking them off the list.
        if (!sameHead)
          begin.push(
            {
              sql: "DELETE FROM partial_hidden WHERE connection_id=? AND stream=?",
              params: [id, stream],
            },
            {
              sql: `INSERT INTO partial_hidden (connection_id,stream,pk_hash)
 SELECT connection_id, stream, pk_hash FROM records
  WHERE connection_id = ? AND stream = ?
    AND NOT EXISTS (SELECT 1 FROM temp.keep_ranges k WHERE k.op = ? AND records.pk_hash >= k.lo AND records.pk_hash < k.hi)`,
              params: [id, stream, op],
            },
          );
      }
    }
    if (progressive)
      begin.push({
        // The keys of this part, which `mergeIncoming` then clears.
        sql: `DELETE FROM partial_hidden WHERE connection_id = ? AND stream = ?
   AND pk_hash IN (SELECT pk_hash FROM temp.incoming WHERE op = ?)`,
        params: [id, stream, op],
      });
    await markPartial(deps, id, reuse);
    await deps.db.batch(
      withOrigin("remote", [
        ...rows,
        ...begin,
        ...mergeIncoming(op, id, { promoteSeen: true }),
        ...(progressive
          ? [
              {
                // Never fewer parts than a load of this head already showed.
                sql: `INSERT OR REPLACE INTO stream_partial (connection_id,stream,version,generation,data_hash,head_blob,observed_at,parts_applied,parts_total,records_total)
 VALUES (?,?,?,?,?,?,?,MAX(?,COALESCE((SELECT parts_applied FROM stream_partial WHERE connection_id=? AND stream=? AND version=? AND generation=? AND data_hash=?),0)),?,?)`,
                params: [
                  id,
                  stream,
                  read.version,
                  head.generation,
                  read.dataHash,
                  blob,
                  head.observedAt,
                  applied,
                  id,
                  stream,
                  read.version,
                  head.generation,
                  read.dataHash,
                  head.parts.length,
                  head.recordCount,
                ],
              },
            ]
          : []),
      ]),
    );
    if (progressive) announceApplied(deps, id);
  };
  try {
    // A prefix whose parts all match the saved ones is kept as it is. Decide
    // every prefix first: a first load's drop of other heads' rows spares
    // exactly these ranges.
    const keptPrefixes = new Set<string>();
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
        keptPrefixes.add(prefix);
      }
    }
    applied = kept;
    for (const [prefix, parts] of grouped) {
      if (keptPrefixes.has(prefix)) continue;
      const groupStart = applied;
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
          applied++;
          await commit(rows);
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
            const last = frame.parts[frame.parts.length - 1]!;
            applied = groupStart + parts.indexOf(last) + 1;
            await commit(rows);
            rows = [];
            records = 0;
            end = parts[parts.indexOf(last) + 1];
          }
        }
        if (rows.length > 0) throw new Error("apply: incomplete part");
      }
    }
    const stillActive = await control(deps, id, connection, hashes, reuse);
    reuse.control = stillActive;
    if (
      stillActive.kind !== "active" ||
      stillActive.generation !== active.generation
    ) {
      // A control found deleted purged the connection: that finishes it.
      if (stillActive.kind === "deleted") reuse.proved.add(stream);
      return result(stream, stillActive.kind === "deleted" ? "purged" : "gone");
    }
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
      ...applyDelete(op, id, stream, omissionCutoff(head)),
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
        // The load is complete: the stream serves as a complete head now.
        sql: "DELETE FROM stream_partial WHERE connection_id=? AND stream=?",
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
    await markPartial(deps, id, reuse);
    await deps.db.batch(withOrigin("remote", statements));
    reuse.proved.add(stream);
    return {
      stream,
      outcome: "applied",
      partsDownloaded: downloaded,
      partsKept: kept,
    };
  } catch (error) {
    // The load stopped short of its last part: say so on its row, for a
    // reader to tell this from a load that is still going. The next part
    // clears it. A failure here must not hide the one being thrown.
    if (progressive && began)
      await deps.db
        .batch([
          {
            sql: "UPDATE stream_partial SET failed = 1, last_error = ? WHERE connection_id = ? AND stream = ? AND version = ? AND generation = ? AND data_hash = ?",
            params: [
              failureCode(error),
              id,
              stream,
              read.version,
              head.generation,
              read.dataHash,
            ],
          },
        ])
        .then(
          () => announceApplied(deps, id),
          () => undefined,
        );
    throw error;
  } finally {
    await deps.db.batch(
      ["incoming", "apply_keys", "keep_ranges"].map((table) => ({
        sql: `DELETE FROM temp.${table} WHERE op=?`,
        params: [op],
      })),
    );
  }
}

/**
 * A short, stable name for why an apply stopped, for a reader to show or
 * log: the error's own `code` if it has one, else its message as a slug
 * (`apply: missing part blob` is `missing_part_blob`).
 */
function failureCode(error: unknown): string {
  const code = (error as { code?: unknown } | null)?.code;
  const text =
    typeof code === "string" && code !== ""
      ? code
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    text
      .replace(/^apply:\s*/i, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 64) || "unknown"
  );
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
