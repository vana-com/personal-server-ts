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
