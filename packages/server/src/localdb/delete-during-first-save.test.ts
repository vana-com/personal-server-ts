/**
 * A delete that begins while a connection's first save is committing. The
 * first save writes the control row and the first log segment in one request,
 * and holds the connection's queue until the reply. The delete must not plan
 * over a registry that does not have the control row yet: it would find
 * nothing to fence, answer "fenced", and let the commit land afterwards.
 */
import { afterEach, expect, it } from "vitest";
import {
  controlScope,
  logScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { closeWorldDrivers, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("a delete requested during a first save's commit fences the control row that commit writes", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("first", [{ stream: "s0", id: "x" }], { connector: "fresh" });
  let release!: () => void;
  let entered!: () => void;
  const held = new Promise<void>((r) => (release = r));
  const inBatch = new Promise<void>((r) => (entered = r));
  w.gateway.beforeBatch = async () => {
    w.gateway.beforeBatch = undefined;
    entered();
    await held;
  };
  const cycle = a.cycle().catch((e: unknown) => e);
  await inBatch;
  const deleted = a.sync.deleter.requestConnectionDelete("fresh");
  // Let the delete reach the registry (or wait behind the commit) before the
  // commit lands.
  await new Promise((r) => setTimeout(r, 50));
  release();
  const answer = await deleted;
  await cycle;

  const control = w.gateway.versions.get(controlScope("fresh", ""))!;
  expect(answer.fenced).toBe(true);
  // The commit created the control row at version 1; the delete tombstoned it.
  expect(control).toHaveLength(2);
  expect(control[1]!.dataHash).not.toBe(control[0]!.dataHash);
  expect(w.gateway.versions.get(logScope("fresh", ""))).toHaveLength(1);
  // Another device never sees the connection's data.
  await b.cycle();
  expect(await b.records()).toEqual([]);
});
