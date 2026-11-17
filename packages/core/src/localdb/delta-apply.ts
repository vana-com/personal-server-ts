// Apply a registry change delta without a full cycle's registry reads.
// The cycle takes one owner listing and reads each connection's control row;
// its log row comes from the listing. A delta already carries changed rows.
//
// Decide every connection before applying any. Tombstones save the control
// row and purge; logs of active connections apply through the supplied row.
// A reconnect, unsupported row, partial apply, delete intent, or incomplete
// apply hands back to the cycle. Every successful apply then runs the cycle's
// publisher before settling.
//
// The host owns answer ordering and cursor settlement: SyncManager runs one
// pass at a time and advances since only after this promise (or the fallback
// cycle) completes. A rejected connection must not leave sibling operations
// running after this promise settles.

import {
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  isLogStream,
  parseScope,
  type ControlHashes,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import type {
  DeltaApplyResult,
  RegistryChangeDelta,
  StreamSyncBlobs,
} from "../stream-sync/ports.js";
import {
  knownActiveConnections,
  newConnectionsWithStreams,
  saveControl,
} from "./bootstrap.js";
import { publishLog } from "./log-publish.js";
import type { LocalSyncDeps } from "./deps.js";
import { applyLog } from "./log-apply.js";
import { readLogState } from "./log-state.js";
import { purgeConnection } from "./purge.js";
import { insideQueue } from "./slot.js";

const cycle = (reason: string): DeltaApplyResult => ({
  outcome: "cycle",
  reason,
});

/** The delta's rows of one connection. */
interface ConnectionRows {
  readonly connector: string;
  readonly ns: string;
  control?: ControlRead;
  log?: ControlRead;
}

interface Held {
  connection_id: string;
  generation: number;
  control_state: string;
  apply_partial: number;
}

export async function applyRegistryDelta(
  deps: LocalSyncDeps,
  delta: RegistryChangeDelta,
): Promise<DeltaApplyResult> {
  const started = performance.now();
  if (delta.reset) return cycle("reset");
  if (delta.gone.length > 0) return cycle("a row was removed");
  if (delta.serversChanged) return cycle("a server registration changed");

  const byConnection = new Map<string, ConnectionRows>();
  for (const row of delta.rows) {
    const scope = parseScope(row.scope);
    if (scope === null) continue; // not a stream-sync scope
    const id = controlScope(scope.connector, scope.ns);
    let rows = byConnection.get(id);
    if (!rows) {
      rows = { connector: scope.connector, ns: scope.ns };
      byConnection.set(id, rows);
    }
    if (scope.kind === "control") rows.control = row.read;
    else if (isLogStream(scope.stream)) rows.log = row.read;
    else return cycle("an unsupported stream row changed");
  }
  const connections = await deps.db.query<
    Held & Record<string, string | number>
  >(
    "SELECT connection_id, generation, control_state, apply_partial FROM connections",
  );
  // A partial mark is an apply the cycle owes, whether or not the delta names
  // its connection: the cycle re-applies every partial connection it meets.
  if (connections.some((row) => row.apply_partial !== 0))
    return cycle("a connection has a partial apply");
  if (byConnection.size === 0) return publishAndFinish(deps, started, 0, 0);

  const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
  const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
  const held = new Map(connections.map((row) => [row.connection_id, row]));

  // Decide every connection before any is applied: one that only the cycle
  // can take hands the whole delta back with nothing written.
  const deletes: { id: string; rows: ConnectionRows; read: ControlRead }[] = [];
  const logs: { id: string; rows: ConnectionRows; read: ControlRead }[] = [];
  for (const [id, rows] of byConnection) {
    const local = held.get(id);
    let deleted: boolean;
    if (rows.control) {
      const state = classifyControl(rows.control, hashes);
      if (state.kind === "deleted") deleted = true;
      else if (
        state.kind === "active" &&
        local?.control_state === "active" &&
        // An active row's generation is its version: one lifetime.
        local.generation === state.generation
      )
        deleted = false;
      else return cycle("a connection's control row changed");
    } else deleted = local?.control_state === "deleted";
    if (deleted) {
      if (rows.control) deletes.push({ id, rows, read: rows.control });
      continue;
    }
    if (!rows.log) continue;
    if (local?.control_state !== "active")
      return cycle("a log of a connection not held here");
    if (classifyStreamRow(rows.log, hashes) !== "present")
      return cycle("a log row was deleted");
    logs.push({ id, rows, read: rows.log });
  }

  const timed = timedBlobs(deps.blobs);
  const counted: LocalSyncDeps = { ...deps, blobs: timed.blobs };
  let moved = 0;
  // Connections run concurrently, each under its own queue, as in the cycle.
  // Each reads its state there, so a delete or a reconnect that ran since the
  // read above makes it the cycle's. One that hands back leaves the others
  // applied: an apply is never wrong, only not proven complete.
  const reached = await Promise.allSettled([
    ...deletes.map(({ id, rows, read }) =>
      deps.queue.run(id, "end", () =>
        applyDelete(insideQueue(deps, id), id, rows, read, hashes),
      ),
    ),
    ...logs.map(({ id, rows, read }) =>
      deps.queue.run(id, "end", async () => {
        const generation = held.get(id)!.generation;
        if (
          !(await liveAt(deps, id, generation)) ||
          (await deleteIntent(deps, rows.connector))
        )
          return false;
        const before = (await readLogState(deps, id)).position;
        // This device's own commit can already hold it past the row: the
        // registry has moved past this delta, and the cycle reads where it
        // stands now. (`applyLog` would take the row as a rollback and fail.)
        if (!read.found || before > read.version) return false;
        await applyLog(insideQueue(counted, id), id, {
          connector: rows.connector,
          ns: rows.ns,
          generation,
          keyCheck,
          hashes,
          read,
        });
        const after = (await readLogState(deps, id)).position;
        if (after !== before) moved += 1;
        // The cycle's apply ends at the row it read, with the connection
        // whole; this one must too, or what it did not reach is the cycle's.
        return (
          read.found &&
          after === read.version &&
          (await liveAt(deps, id, generation))
        );
      }),
    ),
  ]);
  // Wait for every connection before the host can start a fallback listing.
  // Successful siblings stay persisted; the cycle repairs any partial one.
  const failed = reached.find((r) => r.status === "rejected");
  if (failed?.status === "rejected") throw failed.reason;
  if (!reached.every((r) => r.status === "fulfilled" && r.value === true))
    return cycle("a connection the delta cannot finish here");
  return publishAndFinish(deps, started, moved, deletes.length, timed);
}

/**
 * A control tombstone, as the cycle meets it: the listing's save of the row,
 * then the purge a deleted control read runs. A delete this device has
 * pending, a partial mark (an apply that ran since the delta was decided can
 * leave one), or a row this device holds a newer control than, is the cycle's.
 */
async function applyDelete(
  locked: LocalSyncDeps,
  id: string,
  rows: ConnectionRows,
  read: ControlRead,
  hashes: ControlHashes,
): Promise<boolean> {
  if (!read.found) return false;
  if (await deleteIntent(locked, rows.connector)) return false;
  if (await partial(locked, id)) return false;
  const saved = await saveControl(
    locked,
    rows.connector,
    rows.ns,
    read,
    hashes,
  );
  if (saved.controlState !== "deleted" || saved.controlVersion !== read.version)
    return false;
  await purgeConnection(locked, id, { controlVersion: read.version });
  return true;
}

async function partial(deps: LocalSyncDeps, id: string) {
  const rows = await deps.db.query(
    "SELECT 1 FROM connections WHERE connection_id = ? AND apply_partial = 1",
    [id],
  );
  return rows.length > 0;
}

/** The connection is active at `generation`, with no partial apply standing. */
async function liveAt(deps: LocalSyncDeps, id: string, generation: number) {
  const [now] = await deps.db.query<{
    generation: number;
    control_state: string;
    apply_partial: number;
  }>(
    "SELECT generation, control_state, apply_partial FROM connections WHERE connection_id = ?",
    [id],
  );
  return (
    now?.control_state === "active" &&
    now.generation === generation &&
    now.apply_partial === 0
  );
}

async function deleteIntent(deps: LocalSyncDeps, connector: string) {
  const rows = await deps.db.query(
    "SELECT 1 FROM delete_intents WHERE connector=?",
    [connector],
  );
  return rows.length > 0;
}

async function publishAndFinish(
  deps: LocalSyncDeps,
  started: number,
  connections: number,
  deleted: number,
  timed?: ReturnType<typeof timedBlobs>,
): Promise<DeltaApplyResult> {
  // Rebase and first-log seeding can create changes without a host wake.
  // Use the publisher itself: it also owns omissions, run metadata, blobs,
  // and writes arriving during apply, including connections absent from delta.
  const publishable = [
    ...(await knownActiveConnections(deps)),
    ...(await newConnectionsWithStreams(deps)),
  ];
  for (const { connectionId } of publishable) {
    const published = await publishLog(deps, connectionId);
    if (
      published === null ||
      published.some((r) => r.outcome === "deferred" || r.outcome === "backoff")
    )
      return cycle("the publisher left work for a full cycle");
  }
  return {
    outcome: "applied",
    connections,
    deleted,
    blobGets: timed?.gets() ?? 0,
    blobMs: timed?.ms() ?? 0,
    applyMs: performance.now() - started,
  };
}

/** The store with its GETs counted and timed; every other member as is. */
function timedBlobs(blobs: StreamSyncBlobs) {
  let gets = 0;
  let ms = 0;
  const get = async (key: string) => {
    const t = performance.now();
    try {
      return await blobs.get(key);
    } finally {
      gets += 1;
      ms += performance.now() - t;
    }
  };
  const wrapped = new Proxy(blobs, {
    get(target, prop) {
      if (prop === "get") return get;
      const value = Reflect.get(target, prop, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { blobs: wrapped, gets: () => gets, ms: () => ms };
}
