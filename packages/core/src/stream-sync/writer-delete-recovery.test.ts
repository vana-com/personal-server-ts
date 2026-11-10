import { expect, it, vi } from "vitest";
import { ask, body } from "../stream-sync-read/service-fixture.js";
import {
  Rig,
  CONNECTOR,
  type RunSpec,
} from "../stream-sync-read/writer-rig.js";
import {
  controlScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
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
  await r.deleteStreamHeadsOnly();
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
    await r.deleteStreamHeadsOnly();
    expect(await r.registeredVersion()).toBe(2);
  },
);
it("P6 a delete by another device drops only seed records (mutant: keep seed with live records)", async () => {
  const r = new Rig({ key: "id", version: "1.0.0", rows: [{ id: "old" }] });
  await r.open();
  await r.collect(spec("theirs", true));
  await r.deleteStreamHeadsOnly(r.other);
  await r.sync();
  await r.collect(spec("live"));
  await r.publish();
  await r.sync();
  expect((await read(r)).ids).toEqual(["live"]);
  expect((await r.writer.seedStatus(CONNECTOR)).skipped).toEqual([
    { stream: "items", upload: "upload-1" },
  ]);
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
  await r.deleteStreamHeadsOnly(r.other);
  await r.publish();
  expect((await r.writer.issueStart(CONNECTOR, false)).checkpoint).toBeNull();
  expect(r.restarts).toEqual([CONNECTOR]);
});
it("observed tombstones stamp the next run (mutant: do not forward mirror deletes)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.deleteStreamHeadsOnly(r.other);
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
  await r.deleteStreamHeadsOnly(r.other);
  await r.collect({ ...spec("fresh", true), userConnect: true });
  await r.sync();
  expect((await read(r)).ids).toEqual(["fresh"]);
});
async function publishedStreams(r: Rig, ...streams: string[]) {
  await r.open();
  await r.collect({
    ...spec("base"),
    stream: streams[0],
    also: streams.slice(1).map((stream) => ({
      stream,
      key: "id",
      version: "1.0.0",
      rows: [{ id: "base" }],
    })),
  });
  await r.publish();
}
async function controlState(r: Rig) {
  return r.gateway.read(controlScope(CONNECTOR, ""));
}
it("saved delete survives ambiguous reply and restart (mutant: no saved intent)", async () => {
  const r = new Rig();
  await publishedStreams(r, "items");
  r.gateway.beforePost = async () => {
    r.gateway.beforePost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "reply lost",
  );
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(2);
  expect(await r.registeredHead()).toMatchObject({
    lastDeleteVersion: 2,
    recordCount: 0,
  });
  expect(await controlState(r)).toMatchObject({ version: 2 });
});
it("delete retries Gateway 409 with backoff (mutant: no backoff)", async () => {
  const r = new Rig();
  await publishedStreams(r, "items");
  const timer = vi.spyOn(globalThis, "setTimeout");
  try {
    r.gateway.beforePost = async () => {
      r.gateway.beforePost = undefined;
      throw new RegistryRefusedError("conflict", 409);
    };
    await r.writer.deleteConnection(CONNECTOR);
    expect(await r.registeredVersion()).toBe(2);
    expect(timer.mock.calls.some(([, ms]) => ms === 10)).toBe(true);
  } finally {
    timer.mockRestore();
  }
});

it("a stream delete head reads as deleted while the control row is active", async () => {
  const r = new Rig();
  await publishedStreams(r, "items");
  await r.deleteStreamHeadsOnly();
  await r.sync();
  expect(await r.service.resolve(ask("pdpp.acme.items"))).toMatchObject({
    kind: "unavailable",
    reason: "deleted",
  });
  expect(await r.registeredHead()).toMatchObject({
    format: 4,
    lastDeleteVersion: 2,
    recordCount: 0,
  });
  expect(await controlState(r)).toMatchObject({ version: 1, deleted: false });
});

it("delete resumes only unfinished streams after a committed ambiguous reply", async () => {
  const r = new Rig();
  await publishedStreams(r, "items", "second");
  r.gateway.afterPost = async (request) => {
    if (request.scope !== streamScope(CONNECTOR, "", "items")) return;
    r.gateway.afterPost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost after commit");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "reply lost after commit",
  );
  await r.restart();
  await r.publish();
  for (const stream of ["items", "second"]) {
    expect(await r.registeredVersion(stream)).toBe(2);
    expect(await r.registeredHead(stream)).toMatchObject({
      recordCount: 0,
      lastDeleteVersion: 2,
    });
  }
  const state = JSON.parse(
    new TextDecoder().decode((await r.files.read("state.json"))!),
  );
  expect(Object.keys(state.deletes ?? {})).toEqual([]);
});

it("conflict retries are bounded and retain intent for the next pass", async () => {
  const r = new Rig();
  await publishedStreams(r, "items");
  let attempts = 0;
  r.gateway.beforePost = async () => {
    attempts++;
    throw new RegistryRefusedError("conflict", 409);
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "pending after version conflicts",
  );
  expect(attempts).toBe(8);
  r.gateway.beforePost = undefined;
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(2);
});
