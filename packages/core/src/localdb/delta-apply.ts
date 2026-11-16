// Apply a change delta (`RegistryChangeDelta`) without the cycle's registry
// reads.
//
// A full switched cycle reads, per wake, the control listing, each active
// connection's control row, its stream rows, then the log row, before the one
// read that moves data: the log segment. The gateway's delta already carries
// every row that changed after the position this device holds, so for the
// common change (another device committed one log segment) the device can go
// from the wake straight to the segment GET.
//
// This path takes only what it can prove equal to a full cycle and hands
// everything else back (`cycle`). A full cycle at the delta's `since` left
// this device's connections, control rows and stream heads as the registry
// held them then; the delta lists every row changed since. So:
//
//  - a row that is not a stream-sync scope is not read by a switched cycle:
//    skipped;
//  - a log row of a connection this device holds active, already follows by
//    its log, with no delete intent and no partial apply: `applyLog` with the
//    delta's read, exactly the call the cycle ends with. It must reach the
//    row's version, or the cycle runs;
//  - anything else (a control row, a stream head, the log row of a connection
//    not held here, a removed row, a server change, a reset): `cycle`.
//
// Nothing here writes the registry or publishes: pending local changes are
// the cycle's (a local write asks for its own cycle).

import {
  controlHashes,
  deriveKeyCheck,
  isLogStream,
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import type {
  DeltaApplyResult,
  RegistryChangeDelta,
  StreamSyncBlobs,
} from "../stream-sync/ports.js";
import { connectionHasLog } from "./apply.js";
import { knownActiveConnections } from "./bootstrap.js";
import type { ConnectionRow, LocalSyncDeps } from "./deps.js";
import { applyLog } from "./log-apply.js";
import { readLogState } from "./log-state.js";
import { insideQueue } from "./slot.js";

const cycle = (reason: string): DeltaApplyResult => ({
  outcome: "cycle",
  reason,
});

export async function applyRegistryDelta(
  deps: LocalSyncDeps,
  delta: RegistryChangeDelta,
): Promise<DeltaApplyResult> {
  const started = performance.now();
  if (delta.reset) return cycle("reset");
  if (delta.gone.length > 0) return cycle("a row was removed");
  if (delta.serversChanged) return cycle("a server registration changed");

  const active = await knownActiveConnections(deps);
  const logs = new Map<
    string,
    { connection: ConnectionRow; read: ControlRead }
  >();
  for (const row of delta.rows) {
    const scope = parseScope(row.scope);
    if (scope === null) continue; // not a stream-sync scope
    if (scope.kind !== "stream") return cycle("a control row changed");
    if (!isLogStream(scope.stream)) return cycle("a stream head changed");
    const connection = active.find(
      (c) => c.connector === scope.connector && c.ns === scope.ns,
    );
    if (!connection) return cycle("a log of a connection not held here");
    logs.set(connection.connectionId, { connection, read: row.read });
  }

  if (logs.size === 0)
    return {
      outcome: "applied",
      connections: 0,
      blobGets: 0,
      blobMs: 0,
      applyMs: performance.now() - started,
    };

  const timed = timedBlobs(deps.blobs);
  const counted: LocalSyncDeps = { ...deps, blobs: timed.blobs };
  const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
  const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
  let moved = 0;
  // Connections run concurrently, each under its own queue, as in the cycle.
  // Each reads its state there, so a delete or a reconnect that ran since the
  // listing above makes it the cycle's. One that hands back leaves the others
  // applied: an apply is never wrong, only not proven complete.
  const reached = await Promise.all(
    [...logs.values()].map(({ connection, read }) => {
      const id = connection.connectionId;
      return deps.queue.run(id, "apply", async () => {
        const [now] = await deps.db.query<{
          generation: number;
          control_state: string;
          apply_partial: number;
        }>(
          "SELECT generation, control_state, apply_partial FROM connections WHERE connection_id = ?",
          [id],
        );
        if (
          now?.control_state !== "active" ||
          now.generation !== connection.generation ||
          now.apply_partial !== 0 ||
          // A device that does not yet follow this connection by its log
          // starts to in a cycle, which applies the streams under it first.
          !(await connectionHasLog(deps, id)) ||
          (
            await deps.db.query(
              "SELECT 1 FROM delete_intents WHERE connector=?",
              [connection.connector],
            )
          ).length > 0
        )
          return false;
        const before = (await readLogState(deps, id)).position;
        await applyLog(insideQueue(counted, id), id, {
          connector: connection.connector,
          ns: connection.ns,
          generation: connection.generation,
          keyCheck,
          hashes,
          read,
        });
        const after = await readLogState(deps, id);
        if (after.position !== before) moved += 1;
        // The cycle's apply ends at the row it read; this one must too, or
        // what it did not reach is the cycle's.
        return read.found && after.position === read.version;
      });
    }),
  );
  if (!reached.every(Boolean))
    return cycle("a connection the delta cannot finish here");
  return {
    outcome: "applied",
    connections: moved,
    blobGets: timed.gets(),
    blobMs: timed.ms(),
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
