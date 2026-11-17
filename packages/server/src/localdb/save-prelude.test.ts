import { afterEach, expect, it } from "vitest";
import { closeWorldDrivers, CONNECTOR, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("merges a full collection from a stale local log basis without deleting the other device's unseen rows", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("seed", [{ stream: "s0", id: "seed" }]);
  await a.cycle();
  await b.cycle();
  await b.run("remote", [{ stream: "s0", id: "remote" }], { full: false });
  await b.cycle();
  await a.run("local", [{ stream: "s0", id: "local" }], { connect: true });
  await a.sync.publish();
  await b.cycle();
  expect(await a.records()).toEqual([
    's0/local={"id":"local"}',
    's0/remote={"id":"remote"}',
    's0/seed={"id":"seed"}',
  ]);
  expect(await b.records()).toEqual(await a.records());
  expect((await a.sync.intake.publicationStatus("local")).state).toBe(
    "published",
  );
});

it("does not publish a full collection whose control was deleted before its commit", async () => {
  const w = await world({ streams: 1 });
  const b = await w.device("b");
  let deleting = false;
  const a = await w.device("a", {
    beforePut: async () => {
      if (!deleting) return;
      deleting = false;
      await b.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await b.sync.deleter.resumeDeletes()).toEqual([]);
    },
  });
  await a.run("seed", [{ stream: "s0", id: "seed" }]);
  await a.cycle();
  await b.cycle();
  await a.run("local", [{ stream: "s0", id: "local" }], { connect: true });
  deleting = true;
  await a.sync.publish();
  expect((await a.sync.intake.publicationStatus("local")).state).toBe(
    "superseded",
  );
  expect(await a.records()).toEqual([]);
});

it("reconnects a known deletion with fresh admission and never rebinds an old run into the new lifetime", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("seed", [{ stream: "s0", id: "seed" }]);
  await a.cycle();
  await a.run("old", [{ stream: "s0", id: "old" }], { connect: true });
  await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
  await a.run("new", [{ stream: "s0", id: "new" }], { connect: true });
  await a.sync.publish();
  expect((await a.sync.intake.publicationStatus("old")).state).toBe("unknown");
  expect((await a.sync.intake.publicationStatus("new")).state).toBe(
    "published",
  );
  expect(await a.records()).toEqual(['s0/new={"id":"new"}']);
});

it("refuses a stale local control after another device deletes and reconnects", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("seed", [{ stream: "s0", id: "seed" }]);
  await a.cycle();
  await b.cycle();
  await b.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await b.sync.deleter.resumeDeletes()).toEqual([]);
  await b.run("reconnected", [{ stream: "s0", id: "current" }], {
    connect: true,
  });
  await b.sync.publish();
  await a.run("stale", [{ stream: "s0", id: "stale" }], { connect: true });
  await a.sync.publish();
  expect((await a.sync.intake.publicationStatus("stale")).state).not.toBe(
    "published",
  );
  await b.cycle();
  expect(await b.records()).toEqual(['s0/current={"id":"current"}']);
});

it("checks a retry's basis remotely even when this device still holds the old active control", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const b = await w.device("b");
  await a.run("seed", [{ stream: "s0", id: "seed" }]);
  await a.cycle();
  await b.cycle();
  await b.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await b.sync.deleter.resumeDeletes()).toEqual([]);
  await expect(
    a.sync.intake.begin("retry", {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      owner: { address: a.deps.ownerAddress, leaseId: null },
      connect: true,
      expectedControlVersion: 1,
    }),
  ).rejects.toMatchObject({ code: "control_basis_mismatch" });
});

it("does not carry an unbound first save across a remote delete and reconnect during upload", async () => {
  const w = await world({ streams: 1 });
  const b = await w.device("b");
  await b.run("seed", [{ stream: "s0", id: "seed" }]);
  await b.cycle();
  let moved = false;
  const a = await w.device("a", {
    beforePut: async () => {
      if (moved) return;
      moved = true;
      await b.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await b.sync.deleter.resumeDeletes()).toEqual([]);
      await b.run("new", [{ stream: "s0", id: "new" }], { connect: true });
      await b.sync.publish();
    },
  });
  await a.run("first", [{ stream: "s0", id: "old" }], { connect: true });
  await a.sync.publish();
  expect((await a.sync.intake.publicationStatus("first")).state).not.toBe(
    "published",
  );
  await b.cycle();
  expect(await b.records()).toEqual(['s0/new={"id":"new"}']);
});
