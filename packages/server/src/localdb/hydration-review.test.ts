import { afterEach, expect, it } from "vitest";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("hydrates only after every connection succeeds", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("first", [{ stream: sName(0), id: "first" }]);
  await peer.run("second", [{ stream: sName(0), id: "second" }], {
    connector: "second-connector",
  });
  await peer.cycle();
  let fail = true;
  const here = await w.device("here", {
    beforeGet: async (key) => {
      if (fail && key.includes("pdpp.fixture"))
        throw new Error("download failed");
    },
  });
  const first = await here.sync.cycle();
  expect(first.connections).toHaveLength(2);
  expect(
    first.connections.some((c) => c.error?.includes("download failed")),
  ).toBe(true);
  expect((await here.sync.listing.status()).accountHydrated).toBe(false);
  fail = false;
  const second = await here.sync.cycle();
  expect(second.connections.every((c) => c.error === null)).toBe(true);
  expect(await here.rows()).toEqual(await peer.rows());
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
});

it("starts unhydrated when a runtime reopens the same database", async () => {
  const w = await world({ streams: 1 });
  const here = await w.device("here");
  await here.sync.cycle();
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
  const reopened = createLocalSync(here.deps, { resolveArtifact: () => null });
  expect((await reopened.listing.status()).accountHydrated).toBe(false);
});

it("keeps hydration false while a full download is held and a scoped retry runs", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("seed", [{ stream: sName(0), id: "first" }]);
  await peer.run("other", [{ stream: sName(0), id: "other" }], {
    connector: "second-connector",
  });
  await peer.cycle();
  let arrive!: () => void;
  let release!: () => void;
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const here = await w.device("here", {
    beforeGet: async (key) => {
      if (key.includes("pdpp.fixture")) {
        arrive();
        await held;
      }
    },
  });
  const full = here.sync.cycle();
  let publishing: Promise<unknown> | undefined;
  try {
    await arrived;
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
    expect(
      (await here.sync.cycle({ connections: ["pdpp.second-connector~"] }))
        .connections,
    ).toHaveLength(1);
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
    publishing = here.sync.publish();
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
  } finally {
    release();
    await full;
    await publishing;
  }
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
  expect(
    (await here.sync.cycle({ connections: ["pdpp.second-connector~"] }))
      .connections,
  ).toHaveLength(1);
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
});
