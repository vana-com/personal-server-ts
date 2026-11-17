/**
 * A connection this device knows locally but never saved to the registry, then
 * deleted. The delete answers "fenced" with nothing to fence. The connection
 * stays deleted: the next cycle must not create its control row from the
 * registry's absence, and only an explicit connect starts it again.
 */
import { afterEach, expect, it } from "vitest";
import {
  controlScope,
  logScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { closeWorldDrivers, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

async function deletedBeforeFirstSave() {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("first", [{ stream: "s0", id: "x" }], { connector: "fresh" });
  const answer = await a.sync.deleter.requestConnectionDelete("fresh");
  expect(answer.fenced).toBe(true);
  return { w, a, b };
}
const localState = (a: { db: { query: <T>(sql: string) => Promise<T[]> } }) =>
  a.db.query<{ control_state: string }>(
    "SELECT control_state FROM connections",
  );

it("a deleted connection that was never saved publishes nothing and writes no control row", async () => {
  const { w, a } = await deletedBeforeFirstSave();
  await a.cycle();
  expect(w.gateway.versions.get(controlScope("fresh", ""))).toBeUndefined();
  expect(w.gateway.versions.get(logScope("fresh", ""))).toBeUndefined();
  expect(await localState(a)).toEqual([{ control_state: "deleted" }]);
});

it("a run after that delete, with no explicit connect, never reaches another device", async () => {
  const { w, a, b } = await deletedBeforeFirstSave();
  await a.cycle();
  await a
    .run("later", [{ stream: "s0", id: "y" }], { connector: "fresh" })
    .catch(() => undefined);
  await a.cycle();
  await b.cycle();
  expect(await b.records()).toEqual([]);
  expect(w.gateway.versions.get(logScope("fresh", ""))).toBeUndefined();
});

it("an explicit connect after that delete publishes again", async () => {
  const { w, a, b } = await deletedBeforeFirstSave();
  await a.cycle();
  await a.run("again", [{ stream: "s0", id: "z" }], {
    connector: "fresh",
    connect: true,
  });
  await a.cycle();
  await b.cycle();
  expect(w.gateway.versions.get(logScope("fresh", ""))).toBeDefined();
  expect((await b.records()).join("|")).toContain("s0/");
});
