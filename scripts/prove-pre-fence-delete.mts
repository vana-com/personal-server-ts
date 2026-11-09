import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import {
  Rig,
  CONNECTOR,
  T0,
} from "../packages/core/src/stream-sync-read/writer-rig.js";
import {
  ask,
  body,
} from "../packages/core/src/stream-sync-read/service-fixture.js";
const signature = `0x${"1f".repeat(32)}${"2a".repeat(32)}1b`;
const owner = `0x${"11".repeat(20)}`;
// Run manually against built, detached checkouts; this proof is outside CI.
const checkouts = process.argv.slice(2);
assert.equal(
  checkouts.length,
  2,
  "Pass the two built pre-fence worktree paths",
);
for (const checkout of checkouts) {
  const path = resolve(checkout);
  const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: path,
    encoding: "utf8",
  }).trim();
  assert.ok(
    [
      "fde650c3601a79d6a07a97c0dd39d2f1f3182de4",
      "ea9c5bec535b7842eb320d36055328ce906ea49b",
    ].includes(commit),
  );
  const core = await import(
    pathToFileURL(`${path}/packages/core/dist/stream-sync/index.js`).href
  );
  const read = await import(
    pathToFileURL(`${path}/packages/core/dist/stream-sync-read/index.js`).href
  );
  const keys = await import(
    pathToFileURL(`${path}/packages/stream-sync/dist/index.js`).href
  );
  const rig = new Rig();
  await rig.open();
  const writer = new core.StreamSyncWriter({
    ownerAddress: owner,
    registry: rig.gateway,
    blobs: {
      get: async (k) => rig.blobMap.get(k) ?? null,
      put: async (k, b) => {
        rig.blobMap.set(k, b);
      },
    },
    home: core.bindStreamSyncHome({
      ownerAddress: owner,
      network: "test",
      open: () => core.createMemoryStreamSyncFiles(),
    }),
    keys: core.createStreamSyncKeyPorts(signature),
    signer: { signAddData: async () => `0x${"22".repeat(65)}` },
    now: () => T0 + 3600000,
  });
  async function collect(id) {
    await writer.refreshControls();
    await writer.beginRun({
      runId: id,
      connector: CONNECTOR,
      userConnect: false,
      identity: "none",
      checkpointUsed: null,
      observedAt: T0 + (id === "base" ? 0 : 1000),
    });
    await writer.declareStream(id, "items", {
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
    });
    await writer.append(id, "items", { id });
    await writer.finishRun(id, { checkpointCandidate: { cursor: id } });
  }
  const openReader = () =>
    read.StreamSyncReadService.open({
      files: read.createMemoryStreamSyncReadFiles(),
      blobs: { get: async (k) => rig.blobMap.get(k) ?? null },
      keys: awaitableKeys,
      logger: { warn() {}, info() {}, error() {} },
    });
  const awaitableKeys = await read.createStreamSyncReadKeys(
    keys.streamMasterKeyFromSignature(signature),
  );
  await collect("base");
  await writer.publishPending();
  const warm = await openReader();
  await warm.observe(rig.gateway.feed(), { fromStart: true, lastPage: true });
  await warm.importPending();
  await collect("stale");
  await rig.writer.deleteStreams(CONNECTOR, ["items"]);
  const before = rig.gateway.log.length;
  const report = await writer.publishPending();
  assert.equal(
    rig.gateway.log.length,
    before,
    "STOP: real old writer committed a post",
  );
  const pending = report.runs.find((x) => x.runId === "stale");
  assert.equal(pending.streams.items.problem, "unsupported_format");
  const cold = await openReader();
  const readers = [];
  for (const [name, reader] of [
    ["warm", warm],
    ["cold", cold],
  ]) {
    await reader.observe(rig.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    await reader.importPending();
    const decision = await reader.resolve(ask("pdpp.acme.items"));
    const records =
      decision.kind === "view" || decision.kind === "local_pending"
        ? (await body(decision)).data.records
        : [];
    readers.push({
      name,
      kind: decision.kind,
      records,
      issues: reader.status().issues,
    });
  }
  console.log(
    JSON.stringify({
      commit,
      committedPosts: rig.gateway.log.length - before,
      problem: pending.streams.items.problem,
      readers,
    }),
  );
}
