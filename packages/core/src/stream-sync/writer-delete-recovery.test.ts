import { expect, it, vi } from "vitest";
import { ask, body } from "../stream-sync-read/service-fixture.js";
import {
  Rig,
  CONNECTOR,
  type RunSpec,
} from "../stream-sync-read/writer-rig.js";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { AmbiguousRegistryReplyError, RegistryRefusedError } from "./ports.js";

const spec = (runId: string, otherDevice = false): RunSpec => ({
  runId,
  otherDevice,
  key: "id",
  version: "1.0.0",
  rows: [{ id: runId }],
  full: true,
});
async function read(r: Rig) {
  const decision = await r.service.resolve(ask("pdpp.acme.items"));
  if (decision.kind !== "view" && decision.kind !== "local_pending")
    throw new Error(decision.kind);
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    ids: envelope.data.records.map((x: { id: string }) => x.id).sort(),
  };
}
it("P2 reclaims seed-only skips and reads a view (mutant: drop terminal state)", async () => {
  const r = new Rig({
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
  });
  await r.open();
  await r.writer.deleteStreams(CONNECTOR, ["seed"]);
  await r.collect(spec("live"));
  await r.publish();
  await r.restart();
  for (let i = 0; i < 3; i++) {
    await r.sync();
    await read(r);
    await r.publish();
  }
  expect(r.files.paths().filter((p) => p.startsWith("runs/live/"))).toEqual([]);
  expect(await read(r)).toEqual({ kind: "view", ids: ["live"] });
});
it.each(["missing", "unreadable"])(
  "P3/P5 %s head never blocks declare or delete (mutant: restore throwing load)",
  async (failure) => {
    const r = new Rig();
    await r.open();
    await r.collect(spec("base"));
    await r.publish();
    for (const k of r.blobMap.keys())
      if (k.includes("/h-")) {
        if (failure === "missing") r.blobMap.delete(k);
        else r.blobMap.set(k, new Uint8Array([0, 1, 2]));
      }
    await r.collect(spec("next"));
    await r.writer.deleteStreams(CONNECTOR, ["items"]);
    expect(await r.registeredVersion()).toBe(2);
  },
);
it("P6 same-device delete drops only seed records (mutant: keep seed with live records)", async () => {
  const r = new Rig({ key: "id", version: "1.0.0", rows: [{ id: "old" }] });
  await r.open();
  await r.writer.deleteStreams(CONNECTOR, ["items"]);
  await r.collect(spec("live"));
  await r.publish();
  await r.sync();
  expect((await read(r)).ids).toEqual(["live"]);
  expect((await r.writer.seedStatus(CONNECTOR)).receipts).toEqual({
    items: "skipped",
  });
});
it("discard clears checkpoint and restarts full (mutants: no checkpoint clear; no restart callback)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  expect(
    (await r.writer.issueStart(CONNECTOR, false)).checkpoint,
  ).not.toBeNull();
  await r.collect(spec("stale"));
  await r.other.deleteStreams(CONNECTOR, ["items"]);
  await r.publish();
  expect((await r.writer.issueStart(CONNECTOR, false)).checkpoint).toBeNull();
  expect(r.restarts).toEqual([CONNECTOR]);
});
it("observed tombstones stamp the next run (mutant: do not forward mirror deletes)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.other.deleteStreams(CONNECTOR, ["items"]);
  await r.sync();
  await r.collect(spec("fresh"));
  expect(
    (await r.publish()).find((s) => s.runId === "fresh")?.outcome?.kind,
  ).toBe("checkpointed");
  expect((await r.registeredHead())?.lastDeleteVersion).toBe(2);
});
it("P7 owner reads drop stale unpublished runs after missed tombstone (mutant: skip the drop)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.collect(spec("stale"));
  await r.other.deleteStreams(CONNECTOR, ["items"]);
  await r.collect(spec("fresh", true));
  await r.sync();
  expect((await read(r)).ids).toEqual(["fresh"]);
});
it("saved delete survives ambiguous reply and restart (mutant: no saved intent)", async () => {
  const r = new Rig();
  await r.open();
  r.gateway.beforePost = async () => {
    r.gateway.beforePost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost");
  };
  await expect(r.writer.deleteStreams(CONNECTOR, ["items"])).rejects.toThrow(
    "reply lost",
  );
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(1);
});
it("delete retries Gateway 409 with backoff (mutant: no backoff)", async () => {
  const r = new Rig();
  await r.open();
  const timer = vi.spyOn(globalThis, "setTimeout");
  try {
    r.gateway.beforePost = async () => {
      r.gateway.beforePost = undefined;
      throw new RegistryRefusedError("conflict", 409);
    };
    await r.writer.deleteStreams(CONNECTOR, ["items"]);
    expect(await r.registeredVersion()).toBe(1);
    expect(timer.mock.calls.some(([, ms]) => ms === 10)).toBe(true);
  } finally {
    timer.mockRestore();
  }
});

it("delete head on an absent stream reads as deleted without control", async () => {
  const r = new Rig();
  await r.open();
  await r.writer.deleteStreams(CONNECTOR, ["items"]);
  await r.sync();
  expect(await r.service.resolve(ask("pdpp.acme.items"))).toMatchObject({
    kind: "unavailable",
    reason: "deleted",
  });
  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    lastDeleteVersion: 1,
    recordCount: 0,
  });
});

it("delete resumes only unfinished streams after a committed ambiguous reply", async () => {
  const r = new Rig();
  await r.open();
  r.gateway.afterPost = async (request) => {
    if (request.scope !== streamScope(CONNECTOR, "", "second")) return;
    r.gateway.afterPost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost after commit");
  };
  await expect(
    r.writer.deleteStreams(CONNECTOR, ["items", "second"]),
  ).rejects.toThrow("reply lost after commit");
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(1);
  expect(await r.registeredHead("second")).toMatchObject({
    recordCount: 0,
    lastDeleteVersion: 1,
  });
  expect(
    await r.gateway.read(streamScope(CONNECTOR, "", "second")),
  ).toMatchObject({ version: 1 });
  const pending = JSON.parse(
    new TextDecoder().decode((await r.files.read("state.json"))!),
  ).streamDeletes;
  expect(Object.keys(pending ?? {})).toEqual([]);
});

it("conflict retries are bounded and retain intent for the next pass", async () => {
  const r = new Rig();
  await r.open();
  let attempts = 0;
  r.gateway.beforePost = async () => {
    attempts++;
    throw new RegistryRefusedError("conflict", 409);
  };
  await expect(r.writer.deleteStreams(CONNECTOR, ["items"])).rejects.toThrow(
    "pending after version conflicts",
  );
  expect(attempts).toBe(8);
  r.gateway.beforePost = undefined;
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(1);
});
