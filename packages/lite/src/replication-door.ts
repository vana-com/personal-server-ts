/**
 * The replication door on PS-Lite (see `core/replication/door.ts`).
 *
 * PS-Lite reaches its storage only through key-value ports, so it cannot
 * install the SQLite fence the Node store uses. Its door is one state-store
 * entry, written when the flag is first on and closed by the first boot with
 * it off. PS-Lite has no replicated store wired yet, so there is no write for
 * a fence to catch. A host-owned store that adds one must fence it.
 */
import type { ReplicationDoorStatus } from "@opendatalabs/personal-server-ts-core/replication/door";
import type { PsLiteStateStore } from "./state.js";

const DOOR_KEY = "replication-door-v1";

/**
 * Pass the door once per boot, before the runtime reads the flag. An entry
 * this build cannot read counts as closed.
 */
export async function resolveLiteReplication(
  store: PsLiteStateStore,
  requested: boolean,
): Promise<ReplicationDoorStatus> {
  const door = await store.get<{ off?: unknown }>(DOOR_KEY);
  if (!requested) {
    if (door === null) return { state: "never" };
    if (door.off !== true) await store.set(DOOR_KEY, { off: true });
    return { state: "off" };
  }
  if (door === null) {
    await store.set(DOOR_KEY, { off: false });
    return { state: "on" };
  }
  return door.off === false
    ? { state: "on" }
    : { state: "refused", refusal: "reenable_refused" };
}
