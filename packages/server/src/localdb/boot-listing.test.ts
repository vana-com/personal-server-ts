import { afterEach, expect, it } from "vitest";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import {
  closeWorldDrivers,
  CONNECTION_ID,
  CONTROL,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("starts the head GET from the owner's listing without another registry read", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("seed", [{ stream: sName(0), id: "first" }]);
  await peer.cycle();
  let atHead!: () => void;
  const headStarted = new Promise<void>((resolve) => {
    atHead = resolve;
  });
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const here = await w.device("here", {
    beforeGet: async () => {
      atHead();
      await held;
    },
  });
  const events: string[] = [];
  const list = here.deps.registry.listOwnerRows.bind(here.deps.registry);
  here.deps.registry.listOwnerRows = async () => {
    const rows = await list();
    events.push("listed");
    return rows;
  };
  const read = here.deps.registry.read.bind(here.deps.registry);
  here.deps.registry.read = async (scope) => {
    events.push(`read:${scope}`);
    return read(scope);
  };
  const pull = here.sync.apply();
  try {
    await headStarted;
    expect(events).toEqual(["listed"]);
  } finally {
    release();
    await pull;
  }
  expect(await here.rows()).toEqual(await peer.rows());
});

it("a listed active control cannot revive a deletion already observed locally", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("seed", [{ stream: sName(0), id: "first" }]);
  await peer.cycle();
  const here = await w.device("here");
  await here.cycle();
  const listed = await here.deps.registry.listOwnerRows();
  const control = listed.find((row) => row.scope === CONTROL)!.read;
  expect(control.found).toBe(true);
  await here.db.batch([
    {
      sql: "UPDATE connections SET control_state='deleted',control_version=? WHERE connection_id=?",
      params: [control.found ? control.version : 1, CONNECTION_ID],
    },
  ]);
  const gets = here.gets.length;
  await applyConnection(here.deps, CONNECTION_ID, listed);
  expect(here.gets).toHaveLength(gets);
  expect(
    await here.db.query(
      "SELECT control_state FROM connections WHERE connection_id=?",
      [CONNECTION_ID],
    ),
  ).toEqual([{ control_state: "deleted" }]);
});
