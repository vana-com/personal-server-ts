import { sha256 } from "@noble/hashes/sha2";
import { afterEach, expect, it } from "vitest";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import {
  CONNECTION_ID,
  CONTROL,
  CONNECTOR,
  OWNER,
  closeWorldDrivers,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const request = (connect = false) => ({
  connector: CONNECTOR,
  artifactDigest: CONNECTOR,
  owner: { address: OWNER, leaseId: null },
  connect,
});
const ended = () => endRequest({ lastBatch: 0, live: ["s0"] });

it("invalidates an interrupted attachment upload before delete and reconnect can retry it", async () => {
  const w = await world({ streams: 1 });
  let fail = true;
  const d = await w.device("d1", {
    beforePut: async (key) => {
      if (fail && key.includes("/g1-b-"))
        throw new Error("attachment unavailable");
    },
  });
  await d.run("seed", [{ stream: "s0", id: "seed" }]);
  await publishLog(d.deps, CONNECTION_ID);
  const bytes = new Uint8Array([1, 2, 3]);
  const hash = Buffer.from(sha256(bytes)).toString("hex");
  await d.run("r1", [{ stream: "s0", id: "old", blobId: `sha256:${hash}` }], {
    blob: { hash, bytes },
  });
  await expect(publishLog(d.deps, CONNECTION_ID)).rejects.toThrow(
    "attachment unavailable",
  );
  fail = false;
  await d.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await d.sync.deleter.resumeDeletes()).toEqual([]);
  expect(await d.db.query("SELECT 1 FROM blobs")).toEqual([]);
  await d.sync.intake.begin("r2", request(true));
  await d.sync.intake.batch("r2", {
    batch: 0,
    records: [{ stream: "s0", data: { id: "new" } }],
  });
  await d.sync.intake.end("r2", ended());
  const results = await publishLog(d.deps, CONNECTION_ID);
  expect(results?.flatMap((r) => r.publication?.runIds ?? [])).toEqual(["r2"]);
  expect((await d.sync.intake.publicationStatus("r2")).state).toBe("published");
});

it("keeps R2's refusal when its end follows R1's commit and another publish waits", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d1");
  await d.run("r1", [{ stream: "s0", id: "one" }]);
  await d.sync.intake.begin("r2", request());
  await d.sync.intake.batch("r2", {
    batch: 0,
    records: [{ stream: "s0", data: { id: "two" } }],
  });
  let entered!: () => void;
  const committing = new Promise<void>((r) => {
    entered = r;
  });
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let batches = 0;
  w.gateway.beforeBatch = async () => {
    if (++batches === 1) {
      entered();
      await gate;
    } else w.gateway.failFenceAlways(CONTROL);
  };
  const first = d.sync.publish();
  await committing;
  const end = d.sync.intake.end("r2", ended());
  const second = d.sync.publish();
  release();
  await first;
  await end;
  const report = await second;
  expect(
    report.connections
      .flatMap((c) => c.published)
      .some((r) => r.outcome === "deferred"),
  ).toBe(true);
  expect((await d.sync.intake.publicationStatus("r2")).state).toBe("pending");
});

it("reconciles R1's lost commit before replacing the basis changed by R2's end", async () => {
  const w = await world({ streams: 1 });
  let entered!: () => void;
  const uploading = new Promise<void>((r) => {
    entered = r;
  });
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let held = false;
  const d = await w.device("d1", {
    beforePut: async () => {
      if (!held) {
        held = true;
        entered();
        await gate;
      }
    },
  });
  await d.run("r1", [{ stream: "s0", id: "one" }]);
  const first = publishLog(d.deps, CONNECTION_ID);
  await uploading;
  await d.sync.intake.begin("r2", request());
  await d.sync.intake.batch("r2", {
    batch: 0,
    records: [{ stream: "s0", data: { id: "two" } }],
  });
  w.gateway.beforeBatch = () => {
    w.gateway.dropNextBatchReply = true;
  };
  release();
  await expect(first).rejects.toThrow(/no reply/);
  w.gateway.beforeBatch = undefined;
  await d.sync.intake.end("r2", ended());
  await publishLog(d.deps, CONNECTION_ID);
  expect(await d.position()).toBe(2);
  expect(d.puts.filter((key) => key.includes("/s-"))).toHaveLength(2);
  expect((await d.sync.intake.publicationStatus("r1")).state).toBe("published");
  expect((await d.sync.intake.publicationStatus("r2")).state).toBe("published");
});

it("reports R1 published when a waiting publish succeeds after the first fence refusal", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d1");
  await d.run("seed", [{ stream: "s0", id: "seed" }]);
  await publishLog(d.deps, CONNECTION_ID);
  await d.run("r1", [{ stream: "s0", id: "one" }]);
  let entered!: () => void;
  const committing = new Promise<void>((r) => (entered = r));
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let batches = 0;
  w.gateway.beforeBatch = async () => {
    if (++batches === 1) {
      entered();
      await gate;
      w.gateway.failFenceOnce(CONTROL);
    }
  };
  const first = publishLog(d.deps, CONNECTION_ID);
  await committing;
  const second = publishLog(d.deps, CONNECTION_ID);
  release();
  await first;
  const result = await second;
  expect(await d.sync.intake.publicationStatus("r1")).toMatchObject({
    state: "published",
    streams: [{ publication: { version: 2 } }],
  });
  expect(result?.map((r) => r.outcome)).toEqual(["published"]);
});

it("reports R1 published when reconciliation confirms a lost commit before a refused resend", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d1");
  await d.run("seed", [{ stream: "s0", id: "seed" }]);
  await publishLog(d.deps, CONNECTION_ID);
  await d.run("r1", [{ stream: "s0", id: "one" }]);
  let batches = 0;
  w.gateway.beforeBatch = () => {
    if (++batches === 1) w.gateway.dropNextBatchReply = true;
    else w.gateway.failFenceOnce(CONTROL);
  };
  const result = await publishLog(d.deps, CONNECTION_ID);
  expect(await d.sync.intake.publicationStatus("r1")).toMatchObject({
    state: "published",
    streams: [{ publication: { version: 2 } }],
  });
  expect(result?.map((r) => r.outcome)).toEqual(["published"]);
});
