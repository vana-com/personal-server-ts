import { ask } from "../stream-sync-read/service-fixture.js";
import { expect, it } from "vitest";
import {
  Rig,
  CONNECTOR,
  type RunSpec,
} from "../stream-sync-read/writer-rig.js";
import {
  canonicalJson,
  digestHead,
  controlHashes,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createStreamSyncKeyPorts, streamSyncHashes } from "./crypto.js";

const spec = (runId: string, otherDevice = false): RunSpec => ({
  runId,
  otherDevice,
  key: "id",
  version: "1.0.0",
  rows: [{ id: runId }],
  full: true,
});
async function tombstone(r: Rig) {
  const scope = streamScope(CONNECTOR, "", "items");
  const row = await r.gateway.read(scope);
  const hashes = await controlHashes(
    streamSyncHashes.keccak256,
    "0000000000000000",
  );
  await r.gateway.post({
    scope,
    ownerAddress: `0x${"11".repeat(20)}`,
    dataHash: hashes.tombstoneData,
    metadataHash: hashes.tombstoneMetadata,
    expectedVersion: String(row.found ? row.version + 1 : 1),
    signature: "0x00",
  });
}
async function discarded(r: Rig, id: string) {
  const statuses = await r.publish();
  expect(statuses.find((s) => s.runId === id)?.outcome).toMatchObject({
    kind: "discarded",
    clearCheckpoints: true,
    restartFull: true,
  });
}
it("double delete refuses (mutant: boolean fence; false/false discard)", async () => {
  const r = new Rig();
  await r.open();
  await tombstone(r);
  await r.collect(spec("learn"));
  await r.publish();
  await r.collect(spec("a"));
  await tombstone(r);
  await discarded(r, "a");
});
it("six steps preserve delete history (mutant: counter copied from base resets at tombstone; compare start-tombstoned only)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.collect(spec("a"));
  await tombstone(r);
  // B first learns the delete, then re-collects.
  await r.collect(spec("learn-b", true));
  await r.collect(spec("b", true));
  await discarded(r, "a");
  expect((await r.registeredHead())?.recordCount).toBe(1);
  expect((await r.registeredHead())?.lastDeleteVersion).toBe(2);
  await tombstone(r);
  await r.collect(spec("c"));
  await discarded(r, "c");
  await r.collect(spec("c-fresh"));
  await r.publish();
  expect((await r.registeredHead())?.lastDeleteVersion).toBe(4);
});
it("low stamp discards once and survives restart (mutants: discard does not update cache; refuse whenever lastDeleteVersion > 0)", async () => {
  const r = new Rig();
  await r.open();
  await tombstone(r);
  await r.collect(spec("low"));
  await discarded(r, "low");
  await r.restart();
  await r.collect(spec("fresh"));
  expect(
    (await r.publish()).find((s) => s.runId === "fresh")?.outcome?.kind,
  ).toBe("checkpointed");
  expect((await r.registeredHead())?.lastDeleteVersion).toBe(1);
});
it("beginRun snapshots before streams are learned (mutant: live cache at first batch)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await tombstone(r);
  await r.writer.beginRun({
    runId: "early",
    connector: CONNECTOR,
    userConnect: false,
    identity: "none",
    checkpointUsed: null,
  });
  await r.collect(spec("learn"));
  await r.publish();
  await r.writer.declareStream("early", "items", {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  await r.writer.append("early", "items", { id: "stale" });
  await r.writer.finishRun("early", { checkpointCandidate: null });
  await discarded(r, "early");
});

it("unknown format is refused without a post (mutant: accept any format)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.collect(spec("future"));
  const head = await r.registeredHead();
  const scope = streamScope(CONNECTOR, "", "items");
  const clear = new TextEncoder().encode(
    canonicalJson({
      ...head,
      generation: String(head!.generation),
      format: 99,
    }),
  );
  const digest = await digestHead(streamSyncHashes.keccak256, clear);
  const keys = createStreamSyncKeyPorts(
    `0x${"1f".repeat(32)}${"2a".repeat(32)}1b`,
  );
  r.blobMap.set(
    `${scope}/${digest.blobName}`,
    await keys.encrypt(scope, clear),
  );
  const row = await r.gateway.read(scope);
  if (!row.found) throw new Error("missing row");
  await r.gateway.post({
    scope,
    ownerAddress: `0x${"11".repeat(20)}`,
    dataHash: digest.dataHash,
    metadataHash: row.metadataHash,
    expectedVersion: String(row.version + 1),
    signature: "0x00",
  });
  const posts = r.gateway.log.length;
  expect(
    (await r.publish()).find((s) => s.runId === "future")?.streams["items"]
      ?.problem,
  ).toBe("unsupported_format");
  expect(r.gateway.log).toHaveLength(posts);
});

it("CAS retry reruns the fence (mutant: check only before first post)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.collect(spec("stale"));
  r.gateway.beforePost = async (request) => {
    if (request.scope !== streamScope(CONNECTOR, "", "items")) return;
    r.gateway.beforePost = undefined;
    await tombstone(r);
  };
  await discarded(r, "stale");
});

it("delete retries a CAS lost to a publish (mutant: Superseded swallowed)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.collect(spec("b", true));
  // The concurrent publish must carry a readable head.
  const headRow = await r.gateway.read(streamScope(CONNECTOR, "", "items"));
  r.gateway.beforePost = async (request) => {
    r.gateway.beforePost = undefined;
    if (!headRow.found) throw new Error("missing head");
    await r.gateway.post({
      ...request,
      dataHash: headRow.dataHash,
      metadataHash: headRow.metadataHash,
    });
  };
  await r.deleteStreamHeadsOnly();
  const row = await r.gateway.read(streamScope(CONNECTOR, "", "items"));
  expect(row).toMatchObject({ found: true, version: 4 });
  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    lastDeleteVersion: 4,
    recordCount: 0,
  });
});
it("seed-only refusal is skipped and next run publishes (mutant: discard whole run)", async () => {
  const r = new Rig({
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
  });
  await r.open();
  // Another device published the stream; the delete erases that row.
  await r.collect({ ...spec("theirs", true), stream: "seed" });
  await r.deleteStreamHeadsOnly(r.other);
  await r.sync();
  await r.collect(spec("live"));
  expect(
    (await r.publish()).find((s) => s.runId === "live")?.outcome?.kind,
  ).not.toBe("discarded");
  expect((await r.writer.seedStatus(CONNECTOR)).receipts).toEqual({
    seed: "skipped",
  });
  expect((await r.registeredHead())?.recordCount).toBe(1);
  await r.collect({ ...spec("next"), stream: "seed" });
  await r.publish();
  expect((await r.registeredHead("seed"))?.recordCount).toBe(1);
});
it("merged seed is dropped while live records publish (mutant: discard whole run)", async () => {
  const r = new Rig({ key: "id", version: "1.0.0", rows: [{ id: "old" }] });
  await r.open();
  await r.collect(spec("theirs", true));
  await r.deleteStreamHeadsOnly(r.other);
  // Observe the delete before the live run starts.
  await r.collect(spec("learn"));
  await r.publish();
  await r.collect(spec("live"));
  await r.publish();
  expect((await r.writer.seedStatus(CONNECTOR)).receipts).toEqual({
    items: "skipped",
  });
  expect((await r.registeredHead())?.recordCount).toBe(1);
});

it("replacing the merge base keeps delete history (mutant: counter copied from chosen base)", async () => {
  const r = new Rig();
  await r.open();
  await tombstone(r);
  await r.collect(spec("learn"));
  await r.publish();
  await r.collect(spec("fresh"));
  await r.publish();
  await r.collect({
    ...spec("replace"),
    key: "uid",
    version: "2.0.0",
    rows: [{ uid: "new" }],
  });
  await r.publish();
  expect((await r.registeredHead())?.lastDeleteVersion).toBe(1);
  expect((await r.registeredHead())?.recordCount).toBe(1);
});

it("tombstoned head reads as deleted through the read service (mutant: omit tombstoned view)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.sync();
  await r.deleteStreamHeadsOnly();
  await r.sync();
  expect(await r.service.resolve(ask("pdpp.acme.items"))).toMatchObject({
    kind: "unavailable",
    reason: "deleted",
  });
});
