// A per-stream head admitted beside a log owes the log a replay. The
// obligation and the previous log position are stored with the head batch, so
// a failed or interrupted log pass, a device that held no log position, and a
// registry that rolls back while the head downloads are all decided from
// stored state (docs/formal/log-protocol/HeadCursor.tla, modes durable/memory).
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  applyStream,
} from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const S = sName(0);
const s0 = streamScope(CONNECTOR, "", S);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const rowIds = async (d: Device) =>
  (
    await d.db.query<{ record_key: string }>(
      "SELECT record_key FROM records WHERE stream = ? ORDER BY record_key",
      [S],
    )
  ).map((r) => r.record_key);
const partial = async (d: Device) =>
  (
    await d.db.query<{ apply_partial: number }>(
      "SELECT apply_partial FROM connections WHERE connection_id = ?",
      [CONNECTION_ID],
    )
  )[0]!.apply_partial;

/**
 * Head 1 holds `a0`. Device `a` follows the log and writes `l0`, `l1` (log
 * position 2). Another device then commits head 2 (`z`) while it cannot see
 * the log row: a build that predates the log, or a read just before the log's
 * first write. `hook.get` runs before every blob a device `a` reads.
 */
async function scene() {
  const hook: { get?: (key: string) => Promise<void> } = {};
  const w = await world({ streams: 1, logProtocol: false });
  const legacy = await w.device("legacy", false);
  await legacy.run("run-1", [{ stream: S, id: "a0" }]);
  await legacy.cycle();
  // A device that read head 1 before any log existed: it holds no log position.
  const early = await w.device("early", true);
  await early.cycle();
  const a = await w.device("a", true, {
    beforeGet: async (key) => void (await hook.get?.(key)),
  });
  await a.cycle();
  for (const id of ["l0", "l1"]) {
    await a.run(`run-${id}`, [{ stream: S, id }], {
      full: false,
      covered: [S],
    });
    await a.cycle();
  }
  const log = w.gateway.versions.get(LOG);
  w.gateway.versions.delete(LOG);
  await legacy.run("run-2", [{ stream: S, id: "z" }], {
    full: false,
    covered: [S],
  });
  await legacy.cycle();
  if (log) w.gateway.versions.set(LOG, log);
  expect(await a.position()).toBe(2);
  const reference = await w.device("reference", true);
  await reference.cycle();
  const want = await rowIds(reference);
  expect(want).toEqual(expect.arrayContaining(["a0", "z", "l0", "l1"]));
  return { w, a, early, hook, want, reference };
}

describe("a head admitted beside a log: the replay is owed from stored state", () => {
  it("a device that holds no log position replays the log when one stream applies", async () => {
    const { want, reference, early: fresh } = await scene();
    expect(await fresh.position()).toBe(0);
    await applyStream(fresh.deps, CONNECTION_ID, S);
    expect(await rowIds(fresh)).toEqual(want);
    expect(await fresh.position()).toBe(await reference.position());
    await applyStream(fresh.deps, CONNECTION_ID, S);
    expect(await rowIds(fresh)).toEqual(want);
    expect(await fresh.rows()).toEqual(await reference.rows());
  }, 60_000);

  it("a log pass that fails after the head batch is owed again by the same call, and whole-connection apply then settles the partial mark", async () => {
    const { a, hook, want } = await scene();
    hook.get = async (key) => {
      if (key.startsWith(`${LOG}/`)) throw new Error("log read failed");
    };
    await expect(applyStream(a.deps, CONNECTION_ID, S)).rejects.toThrow(
      "log read failed",
    );
    // The head is in, the cursor was reset, and nothing replayed yet.
    expect(await a.position()).toBe(0);
    expect(await partial(a)).toBe(1);
    hook.get = undefined;
    await applyStream(a.deps, CONNECTION_ID, S);
    expect(await rowIds(a)).toEqual(want);
    expect(await a.position()).toBe(2);
    // The committed head is a settled stream: the mark clears on a whole apply.
    await applyConnection(a.deps, CONNECTION_ID);
    expect(await partial(a)).toBe(0);
    expect(await rowIds(a)).toEqual(want);
  }, 60_000);

  it("a registry log that rolls back while the head downloads is refused before the head batch", async () => {
    const { w, a, hook, want } = await scene();
    const before = { ids: await rowIds(a), position: await a.position() };
    const consumed = () =>
      a.db.query(
        "SELECT consumed_version, consumed_data_hash FROM stream_state",
      );
    const consumedBefore = await consumed();
    let popped: ReturnType<typeof Array.prototype.pop>;
    hook.get = async (key) => {
      if (key.startsWith(`${s0}/`) && popped === undefined)
        popped = w.gateway.versions.get(LOG)!.pop();
    };
    await expect(applyStream(a.deps, CONNECTION_ID, S)).rejects.toThrow(
      /behind this device/,
    );
    // The head's parts may have merged, but its batch did not run: no
    // omission, the head is not consumed, the cursor is where it was, and the
    // interrupted merge keeps the partial mark.
    expect(await rowIds(a)).toEqual(expect.arrayContaining(before.ids));
    expect(await consumed()).toEqual(consumedBefore);
    expect(await a.position()).toBe(before.position);
    expect(await partial(a)).toBe(1);
    // The registry regains its position: the apply goes through.
    hook.get = undefined;
    w.gateway.versions.get(LOG)!.push(popped!);
    await applyStream(a.deps, CONNECTION_ID, S);
    expect(await rowIds(a)).toEqual(want);
    expect(await a.position()).toBe(2);
  }, 60_000);

  it("a rollback after the head batch is refused by the stored position, and a restored registry replays", async () => {
    const { w, a, hook, want } = await scene();
    hook.get = async (key) => {
      if (key.startsWith(`${LOG}/`)) throw new Error("log read failed");
    };
    await expect(applyStream(a.deps, CONNECTION_ID, S)).rejects.toThrow(
      "log read failed",
    );
    hook.get = undefined;
    const rows = await a.rows();
    const popped = w.gateway.versions.get(LOG)!.pop();
    await expect(applyStream(a.deps, CONNECTION_ID, S)).rejects.toThrow(
      /behind this device/,
    );
    await expect(applyConnection(a.deps, CONNECTION_ID)).rejects.toThrow(
      /behind this device/,
    );
    expect(await a.rows()).toEqual(rows);
    expect(await a.position()).toBe(0);
    w.gateway.versions.get(LOG)!.push(popped!);
    await applyStream(a.deps, CONNECTION_ID, S);
    expect(await rowIds(a)).toEqual(want);
    expect(await a.position()).toBe(2);
  }, 60_000);
});
