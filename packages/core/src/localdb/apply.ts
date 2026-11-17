import {
  classifyControl,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  isLogStream,
  parseScope,
  type ControlHashes,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import type { OwnerRows } from "./bootstrap.js";
import type { ConnectionQueue, LocalSyncDeps } from "./deps.js";
import { applyLog } from "./log-apply.js";
import { purgeConnection } from "./purge.js";
import {
  RegistryUnavailableBeforeWriteError,
  RegistryUnavailableError,
} from "../stream-sync/ports.js";

type Connection = {
  connector: string;
  ns: string;
  generation: number;
  apply_partial: number;
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

// A connection's apply work runs in flights, one at a time. A flight answers
// only the callers admitted before it started: its registry reads are all
// taken after each of those calls began. A caller arriving while a flight runs
// joins the one pending next flight, which starts when this one exits and
// takes its own reads. A caller settles when its own flight ends, so a late
// caller's work or failure never reaches an earlier one, and no stream of
// arrivals can keep a flight open.
type Flight = {
  /** Closed at the start of the job; later callers join the next flight. */
  closed: boolean;
  promise: Promise<void>;
  /**
   * The listing the flight reads its log row from, when every caller of the
   * flight brought this same one (`applyConnection`). A caller with another
   * listing, or none, joins and clears it: the flight then reads the row.
   */
  listed?: OwnerRows;
  /** Control read taken by every caller before joining this flight. */
  observedControl?: ControlRead;
};
type Slot = { running: Flight; next?: Flight };
const slots = new WeakMap<ConnectionQueue, Map<string, Slot>>();
function request(
  deps: LocalSyncDeps,
  id: string,
  listed: OwnerRows | undefined,
  observedControl: ControlRead | undefined,
): Promise<void> {
  let byId = slots.get(deps.queue);
  if (!byId) {
    byId = new Map();
    slots.set(deps.queue, byId);
  }
  const join = (flight: Flight) => {
    if (flight.listed !== listed) flight.listed = undefined;
    if (flight.observedControl !== observedControl)
      flight.observedControl = undefined;
    return flight.promise;
  };
  const slot = byId.get(id);
  if (slot) {
    if (!slot.running.closed) return join(slot.running);
    if (slot.next) return join(slot.next);
    const next = newFlight(listed, observedControl);
    slot.next = next;
    next.promise = slot.running.promise
      .then(
        () => undefined,
        () => undefined,
      )
      .then(() => launch(deps, id, next, byId, slot));
    return next.promise;
  }
  const flight = newFlight(listed, observedControl);
  const created: Slot = { running: flight };
  byId.set(id, created);
  flight.promise = launch(deps, id, flight, byId, created);
  return flight.promise;
}
const newFlight = (
  listed: OwnerRows | undefined,
  observedControl: ControlRead | undefined,
): Flight => ({
  closed: false,
  promise: Promise.resolve(),
  ...(listed ? { listed } : {}),
  ...(observedControl ? { observedControl } : {}),
});
function launch(
  deps: LocalSyncDeps,
  id: string,
  flight: Flight,
  byId: Map<string, Slot>,
  slot: Slot,
): Promise<void> {
  return runFlight(deps, id, flight).finally(() => {
    if (slot.next) {
      slot.running = slot.next;
      slot.next = undefined;
    } else if (byId.get(id) === slot) byId.delete(id);
  });
}
function runFlight(deps: LocalSyncDeps, id: string, flight: Flight) {
  const reuse: Reuse = { partial: false };
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
    if (!connection) return;
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
      return;
    }
    const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
    const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
    const initial = await control(
      locked,
      id,
      connection,
      hashes,
      reuse,
      flight.observedControl,
    );
    if (initial.kind !== "active") {
      // A purged connection has nothing left to repair.
      if (initial.kind === "deleted") await clearPartial(deps, id, reuse);
      return;
    }
    // The connection's data is its log. The cycle's one listing of the owner
    // says where the log stands when every caller of this flight came with
    // it; without it `applyLog` reads the log row.
    await applyLog(locked, id, {
      connector: connection.connector,
      ns: connection.ns,
      generation: initial.generation,
      keyCheck,
      hashes,
      read: flight.listed && logRowOf(flight.listed, connection),
    });
    // A pass that ran to its end has applied the log through the position it
    // read, which is what the mark waits for.
    await clearPartial(deps, id, reuse);
  });
}

/**
 * The connection's log row in a registry listing, or `undefined` when the
 * listing holds none (`applyLog` then reads it itself).
 */
function logRowOf(
  listed: OwnerRows,
  connection: Connection,
): ControlRead | undefined {
  for (const row of listed) {
    const scope = parseScope(row.scope);
    if (
      scope?.kind === "stream" &&
      scope.connector === connection.connector &&
      scope.ns === connection.ns &&
      isLogStream(scope.stream)
    )
      return row.read;
  }
  return undefined;
}

/**
 * Apply the connection's log; concurrent requests share one flight. `listed`
 * is a listing of the owner's rows the caller took for this apply (a sync
 * cycle's); without it the apply reads the connection's log row. A caller
 * already holding the connection slot may pass its control read as well.
 */
export function applyConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  listed?: OwnerRows,
  observedControl?: ControlRead,
): Promise<void> {
  return request(deps, connectionId, listed, observedControl);
}

async function control(
  deps: LocalSyncDeps,
  id: string,
  connection: Connection,
  hashes: ControlHashes,
  reuse: Reuse,
  observedControl?: ControlRead,
) {
  // A cycle's listing already observed control. A local commit/reconnect
  // after that snapshot makes it stale; only that case needs a fresh read.
  if (observedControl) {
    const [basis] = await deps.db.query<{ control_version: number }>(
      "SELECT control_version FROM connections WHERE connection_id=?",
      [id],
    );
    if (
      (observedControl.found ? observedControl.version : 0) <
      (basis?.control_version ?? 0)
    )
      observedControl = undefined;
  }
  const read =
    observedControl ??
    (await deps.registry.read(
      controlScope(connection.connector, connection.ns),
    ));
  const state = classifyControl(read, hashes);
  // A stale active read cannot undo a deletion this device already observed.
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
 * The job's own state. `partial`: local data may hold a partial apply: this
 * job has begun a write (a purge or a reset), or an earlier job did and no
 * apply of the whole connection has completed since
 * (`connections.apply_partial`). The control row's own bookkeeping update does
 * not count: it records what the registry said.
 */
interface Reuse {
  partial: boolean;
}
