import { describe, expect, it } from "vitest";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  shardOf,
  streamScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncHashes } from "./crypto.js";
import { bindStreamSyncHome } from "./home.js";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  type StreamSyncRegistry,
  type StreamSyncFaultPoint,
} from "./ports.js";
import { StreamSyncWriter, type StreamSyncWriterOptions } from "./writer.js";
import { createWriterOverlaySource } from "./writer-overlay.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ownerAddress = `0x${"11".repeat(20)}` as const;
const connector = "sample";
const shape = {
  primaryKey: ["id"],
  profile: { key: "sample", version: "1.0.0" },
};

async function fixture() {
  const files = createMemoryStreamSyncFiles(7);
  const rows = new Map<string, ControlRead>();
  const blobs = new Map<string, Uint8Array>();
  let posts = 0;
  let ambiguous = false;
  let fault: StreamSyncFaultPoint | undefined;
  let onPoint: ((point: StreamSyncFaultPoint) => void) | undefined;
  let afterInstalled:
    | ((request: {
        expectedVersion: bigint;
        dataHash: string;
      }) => Promise<void>)
    | undefined;
  const mac = async (m: Uint8Array) =>
    hmac(sha256, new Uint8Array(32).fill(4), m);
  const hashes = await controlHashes(
    streamSyncHashes.keccak256,
    await deriveKeyCheck(mac),
  );
  rows.set(controlScope(connector, ""), {
    found: true,
    version: 1,
    dataHash: hashes.activeData,
    metadataHash: hashes.activeMetadata,
    deleted: false,
  });
  const registry: StreamSyncRegistry = {
    async read(scope) {
      return rows.get(scope) ?? { found: false };
    },
    async listControlRows() {
      return [...rows]
        .filter(([scope]) => scope === controlScope(connector, ""))
        .map(([scope, read]) => ({ scope, read }));
    },
    async post(request) {
      posts++;
      const version = Number(request.expectedVersion);
      const old = rows.get(request.scope);
      if (
        old?.found &&
        old.version >= version &&
        old.dataHash !== request.dataHash
      )
        return { kind: "conflict", latestVersion: String(old.version) };
      rows.set(request.scope, {
        found: true,
        version,
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
        deleted: false,
      });
      await afterInstalled?.(request);
      if (ambiguous) {
        ambiguous = false;
        throw new AmbiguousRegistryReplyError("reply lost");
      }
      return { kind: "committed" };
    },
  };
  const home = bindStreamSyncHome({
    ownerAddress,
    network: "test",
    open: () => files,
  });
  const make = (extra: Partial<StreamSyncWriterOptions> = {}) =>
    new StreamSyncWriter({
      ...extra,
      ownerAddress,
      home,
      registry,
      blobs: {
        async put(k, b) {
          blobs.set(k, b);
        },
        async get(k) {
          return blobs.get(k) ?? null;
        },
      },
      keys: {
        namespaceHmac: mac,
        async encrypt(_s, b) {
          return b;
        },
        async encryptPart(_s, b) {
          return b;
        },
        async decrypt(_s, b) {
          return b;
        },
      },
      signer: {
        async signAddData() {
          return "0x00";
        },
      },
      now: () => 1000,
      fault(point) {
        onPoint?.(point);
        if (point === fault) {
          fault = undefined;
          throw new Error("crash");
        }
      },
    });
  const read = async (id = "r1") =>
    JSON.parse(decoder.decode((await files.read(`runs/${id}/entry.json`))!));
  const edit = async (change: (entry: any) => void, id = "r1") => {
    const entry = await read(id);
    change(entry);
    await files.write(
      `runs/${id}/entry.json`,
      encoder.encode(JSON.stringify(entry)),
    );
  };
  return {
    files,
    rows,
    registry,
    make,
    read,
    edit,
    fault: (p?: StreamSyncFaultPoint) => {
      fault = p;
    },
    ambiguous: () => {
      ambiguous = true;
    },
    posts: () => posts,
    onPoint: (callback: (point: StreamSyncFaultPoint) => void) => {
      onPoint = callback;
    },
    /** Runs after the registry row is installed and before the POST replies. */
    afterInstalled: (callback: NonNullable<typeof afterInstalled>) => {
      afterInstalled = callback;
    },
  };
}
async function collect(
  w: StreamSyncWriter,
  id = "r1",
  records = [{ id: "one" }],
) {
  await w.beginRun({
    runId: id,
    connector,
    userConnect: false,
    observedAt: 1000,
  });
  await w.declareStream(id, "s", shape);
  for (const record of records) await w.append(id, "s", record);
  await w.finishRun(id, { checkpointCandidate: null });
}

describe("writer publish receipts", () => {
  it("stores the ordinary POST receipt atomically with committed", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    f.fault("after_commit_recorded");
    await expect(w.publishPending()).rejects.toThrow("crash");
    const row = f.rows.get(streamScope(connector, "", "s"));
    expect((await f.read()).streams.s.receipt).toEqual({
      registryVersion: 1,
      dataHash: row!.found && row!.dataHash,
      generation: 1,
    });
    expect((await f.read()).entry.streams.s.state).toBe("committed");
  });
  it("stores the exact persisted request receipt after an ambiguous reply", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    f.ambiguous();
    await w.publishPending();
    f.fault("after_commit_recorded");
    await expect(f.make().publishPending()).rejects.toThrow("crash");
    const request = JSON.parse(
      decoder.decode((await f.files.read("runs/r1/request-s0.json"))!),
    );
    expect((await f.read()).streams.s.receipt).toEqual({
      registryVersion: Number(request.expectedVersion),
      dataHash: request.dataHash,
      generation: 1,
    });
  });
  it("stores the existing version and hash for a no-op", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    await collect(w, "r2", []);
    f.fault("after_commit_recorded");
    await expect(w.publishPending()).rejects.toThrow("crash");
    const row = f.rows.get(streamScope(connector, "", "s"));
    expect((await f.read("r2")).streams.s.receipt).toEqual({
      registryVersion: 1,
      dataHash: row!.found && row!.dataHash,
      generation: 1,
    });
    expect((await f.read("r2")).entry.streams.s.state).toBe("noop");
  });
});

describe("writer retained completed runs", () => {
  it("keeps published intake through finish and offline recovery without reposting", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    expect((await f.read()).phase).toBe("done");
    const posts = f.posts();
    const report = await f.make().publishPending();
    expect(report.runs).toEqual([]);
    expect(f.posts()).toBe(posts);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
  });
  it("retains a committed stream when another stream is discarded", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    f.fault("after_commit_recorded");
    await expect(w.publishPending()).rejects.toThrow("crash");
    await f.edit((e) => {
      e.entry.streams.other = { state: "planned" };
      e.streams.other = { ...e.streams.s, index: 1 };
      delete e.streams.other.receipt;
    });
    const hashes = await controlHashes(
      streamSyncHashes.keccak256,
      await deriveKeyCheck(async (m) =>
        hmac(sha256, new Uint8Array(32).fill(4), m),
      ),
    );
    f.rows.set(controlScope(connector, ""), {
      found: true,
      version: 2,
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
      deleted: false,
    });
    await f.make().publishPending();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    expect((await f.read()).entry.streams.other.state).toBe("discarded");
    expect((await f.read()).streams.s.receipt.registryVersion).toBe(1);
  });
  it("retains pre-upgrade done runs without receipts", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await f.edit((e) => {
      e.phase = "done";
      e.entry.streams.s = { state: "committed", generation: 1, complete: true };
    });
    await f.make().publishPending();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
  });
  it("keeps a receipt and rows when checkpoint completion fails", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    f.fault("after_commit_recorded");
    await expect(w.publishPending()).rejects.toThrow("crash");
    f.rows.set(controlScope(connector, ""), {
      found: true,
      version: 3,
      dataHash: `0x${"ab".repeat(32)}`,
      metadataHash: `0x${"cd".repeat(32)}`,
      deleted: false,
    });
    // A crash after commit cannot lose the intake even if the next control read refuses admission.
    await f.make().publishPending();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    expect((await f.read()).streams.s.receipt.registryVersion).toBe(1);
  });
});

describe("writer overlay snapshots", () => {
  it("plans an empty run as a no-op and a run resumed from another namespace as incomplete", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w, "empty", []);
    await w.beginRun({
      runId: "other",
      connector,
      userConnect: false,
      observedAt: 2000,
      identity: "none",
      checkpointUsed: { ns: "0123456789abcdef", generation: 1 },
    });
    await w.declareStream("other", "s", shape);
    await w.append("other", "s", { id: "two" });
    await w.finishRun("other", { checkpointCandidate: null });
    const snapshot = await createWriterOverlaySource(w).snapshot(connector);
    const byId = new Map(snapshot.runs.map((r) => [r.runId, r]));
    expect(byId.get("other")!.streams[0]).toMatchObject({ complete: false });
    // Over a complete head of the runs' generation and shape.
    const head = {
      generation: byId.get("empty")!.generation!,
      primaryKey: shape.primaryKey,
      profile: shape.profile,
      complete: true,
    };
    const steps = snapshot.plan("", "s", head, ["empty", "other"]);
    expect(steps.map((s) => [s.runId, s.decision.kind])).toEqual([
      ["empty", "noop"],
      ["other", "publish"],
    ]);
    expect(steps[0]!.head).toEqual(head);
    expect(steps[1]!.head).toEqual({ ...head, complete: false });
    expect(steps[1]!.rows).toEqual({
      fromHead: true,
      runs: ["other"],
      seed: false,
    });
    snapshot.release();
  });
  it("lists ready offline rows including an unactivated null-generation run", async () => {
    const f = await fixture();
    f.rows.clear();
    const w = f.make();
    await collect(w);
    const source = createWriterOverlaySource(w);
    const snapshot = await source.snapshot(connector);
    expect(snapshot.runs).toHaveLength(1);
    expect(snapshot.runs[0]).toMatchObject({
      ns: "",
      generation: null,
      state: "pending",
      observedAt: 1000,
    });
    expect(
      await Array.fromAsync(snapshot.lines(snapshot.runs[0]!, "s")),
    ).toEqual([{ o: 1000, r: "r1", v: { id: "one" } }]);
    snapshot.release();
    snapshot.release();
    await f.edit((e) => {
      e.entry.ns = null;
    });
    expect((await source.snapshot(connector)).runs).toEqual([]);
  });
  it("persists a verified binding before first admission and never rebinds at read time", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    expect((await f.read()).generation).toBe(1);
    const source = createWriterOverlaySource(f.make());
    const snapshot = await source.snapshot(connector);
    expect(snapshot.runs[0]!.generation).toBe(1);
    snapshot.release();
    await f.edit((e) => {
      e.generation = null;
    });
    const unbound = await source.snapshot(connector);
    expect(unbound.runs[0]!.generation).toBeNull();
    unbound.release();
  });
  it("freezes descriptors while publication advances and rejects foreign snapshot members", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    const source = createWriterOverlaySource(w);
    const before = await source.snapshot(connector);
    await w.publishPending();
    const after = await source.snapshot(connector);
    expect(before.runs[0]!.streams[0]!.state).toBe("pending");
    expect(after.runs[0]!.streams[0]!.state).toBe("published");
    expect(before.runs[0]!.streams[0]!.contentRevision).not.toBe(
      after.runs[0]!.streams[0]!.contentRevision,
    );
    await expect(
      Array.fromAsync(before.lines(after.runs[0]!, "s")),
    ).rejects.toThrow();
    await expect(
      Array.fromAsync(before.lines(before.runs[0]!, "other")),
    ).rejects.toThrow();
    expect(
      await Array.fromAsync(before.lines(before.runs[0]!, "s")),
    ).toHaveLength(1);
    before.release();
    before.release();
    after.release();
    await expect(
      Array.fromAsync(before.lines(before.runs[0]!, "s")),
    ).rejects.toThrow();
  });
  it("excludes collecting, aborted, checkpoint-only, uncovered and owner/key mismatched runs", async () => {
    const f = await fixture();
    const w = f.make();
    const source = createWriterOverlaySource(w);
    await w.beginRun({ runId: "collecting", connector, userConnect: false });
    await w.append("collecting", "s", { id: "one" }, shape);
    expect((await source.snapshot(connector)).runs).toEqual([]);
    await w.abortRun("collecting", "cancelled");
    await w.beginRun({ runId: "checkpoint", connector, userConnect: false });
    await w.append("checkpoint", "s", { id: "one" }, shape);
    await w.saveCheckpointOnly("checkpoint", { s: "cursor" });
    await w.beginRun({ runId: "uncovered", connector, userConnect: false });
    await w.append("uncovered", "s", { id: "one" }, shape);
    await w.finishRun("uncovered", {
      checkpointCandidate: null,
      coveredStreams: [],
    });
    expect((await source.snapshot(connector)).runs).toEqual([]);
    await collect(w);
    await f.edit((e) => {
      e.binding.keyCheck = "wrong";
    });
    expect((await source.snapshot(connector)).runs).toEqual([]);
    await f.edit((e) => {
      e.binding.owner = "wrong";
    });
    expect((await source.snapshot(connector)).runs).toEqual([]);
  });
  it("excludes a whole run on receipt/run generation mismatch without deleting it", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    await f.edit((e) => {
      e.streams.s.receipt.generation = 3;
    });
    expect(
      (await createWriterOverlaySource(f.make()).snapshot(connector)).runs,
    ).toEqual([]);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
  });
  it("preserves spool order and accepts a declared genuinely empty stream", async () => {
    const f = await fixture();
    const w = f.make();
    await collect(w, "r1", [{ id: "one" }, { id: "two" }, { id: "one" }]);
    await collect(w, "empty", []);
    const snap = await createWriterOverlaySource(w).snapshot(connector);
    expect(
      await Array.fromAsync(
        snap.lines(
          snap.runs.find((r) => r.runId === "r1")!,
          "s",
        ),
      ),
    ).toHaveLength(3);
    expect(
      await Array.fromAsync(
        snap.lines(
          snap.runs.find((r) => r.runId === "empty")!,
          "s",
        ),
      ),
    ).toEqual([]);
    snap.release();
  });
  it.each(["missing", "corrupt", "truncated"])(
    "throws on a %s nonempty log",
    async (damage) => {
      const f = await fixture();
      const w = f.make();
      await collect(w);
      const snap = await createWriterOverlaySource(w).snapshot(connector);
      if (damage === "missing") await f.files.remove("runs/r1/spool/s0.log");
      else if (damage === "corrupt")
        await f.files.write("runs/r1/spool/s0.log", encoder.encode("broken\n"));
      else
        await f.files.write(
          "runs/r1/spool/s0.log",
          (await f.files.read("runs/r1/spool/s0.log"))!.slice(0, -2),
        );
      await expect(
        Array.fromAsync(snap.lines(snap.runs[0]!, "s")),
      ).rejects.toThrow();
      snap.release();
    },
  );
});

describe("writer snapshot provenance", () => {
  it("keeps the content revision stable across restart and changes it for a new intake", async () => {
    const f = await fixture();
    const w = f.make();
    await collect(w);
    const first = await createWriterOverlaySource(w).snapshot(connector);
    const revision = first.runs[0]!.streams[0]!.contentRevision;
    first.release();
    const reopened = await createWriterOverlaySource(f.make()).snapshot(
      connector,
    );
    expect(reopened.runs[0]!.streams[0]!.contentRevision).toBe(revision);
    reopened.release();
    await collect(w, "r2");
    const next = await createWriterOverlaySource(w).snapshot(connector);
    expect(
      next.runs.find((r) => r.runId === "r2")!.streams[0]!.contentRevision,
    ).not.toBe(revision);
    next.release();
  });
  it("captures verified active provenance learned between begin and ready", async () => {
    const f = await fixture();
    const w = f.make();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    expect((await f.read()).generation).toBeNull();
    await w.append("r1", "s", { id: "one" }, shape);
    await w.refreshControls();
    await w.finishRun("r1", { checkpointCandidate: null });
    const snap = await createWriterOverlaySource(w).snapshot(connector);
    expect(snap.runs[0]!.generation).toBe(1);
    snap.release();
  });
  it("lists a seed-only stream by metadata only and keeps oversized records", async () => {
    const f = await fixture();
    const w = f.make();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    await w.append(
      "r1",
      "s",
      { id: "huge", value: "x".repeat(8 * 1024 * 1024) },
      shape,
    );
    await w.append("r1", "s", { id: "kept" }, shape);
    await w.finishRun("r1", { checkpointCandidate: null });
    await f.edit((e) => {
      e.streams.seed = { ...e.streams.s, seedOnly: true, index: 1 };
      e.entry.streams.seed = { state: "planned" };
    });
    const snap = await createWriterOverlaySource(w).snapshot(connector);
    expect(snap.runs[0]!.streams.map((s) => s.name)).toEqual(["s", "seed"]);
    expect(
      (await Array.fromAsync(snap.lines(snap.runs[0]!, "s"))).map(
        (l) => l.v.id,
      ),
    ).toEqual(["huge", "kept"].sort());
    // The seed-only stream exposes no rows.
    await expect(
      Array.fromAsync(snap.lines(snap.runs[0]!, "seed")),
    ).rejects.toThrow();
    snap.release();
  });
});

async function coverageOf(f: Awaited<ReturnType<typeof fixture>>) {
  const receipt = (await f.read()).streams.s.receipt;
  return { connector, ns: "", stream: "s", ...receipt };
}

describe("writer durable read acknowledgment", () => {
  it("reclaims a completed run only after matching durable coverage", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const coverage = await coverageOf(f);
    await source.acknowledge(coverage);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
    await source.acknowledge(coverage);
    expect((await source.snapshot(connector)).runs).toEqual([]);
    expect(await f.files.read("results/r1.json")).not.toBeNull();
  });
  it.each([
    { registryVersion: 0 },
    { registryVersion: 2, generation: 3 },
    { dataHash: `0x${"ab".repeat(32)}` },
    { connector: "other" },
    { ns: "other" },
    { stream: "other" },
    { generation: 3 },
  ])("never retires unrelated coverage %j", async (change) => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const coverage = await coverageOf(f);
    await source.acknowledge({ ...coverage, ...change });
    const snap = await source.snapshot(connector);
    expect(snap.runs).toHaveLength(1);
    snap.release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    await source.acknowledge(coverage);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("accepts a later version in the same generation", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    await createWriterOverlaySource(w).acknowledge({
      ...(await coverageOf(f)),
      registryVersion: 2,
      dataHash: `0x${"cd".repeat(32)}`,
    });
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("keeps bytes for two pinned readers until both idempotent releases", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const first = await source.snapshot(connector);
    const second = await source.snapshot(connector);
    await source.acknowledge(await coverageOf(f));
    expect((await source.snapshot(connector)).runs).toEqual([]);
    expect(
      await Array.fromAsync(first.lines(first.runs[0]!, "s")),
    ).toHaveLength(1);
    first.release();
    first.release();
    // A new snapshot waits for queued unpins.
    (await source.snapshot(connector)).release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    expect(
      await Array.fromAsync(second.lines(second.runs[0]!, "s")),
    ).toHaveLength(1);
    second.release();
    (await source.snapshot(connector)).release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("does not retire a generation-mismatched receipt, even during restart recovery", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const coverage = await coverageOf(f);
    await f.edit((e) => {
      e.generation = 3;
    });
    const source = createWriterOverlaySource(f.make());
    await source.acknowledge(coverage);
    expect((await source.snapshot(connector)).runs).toEqual([]);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
  });
  it("never acknowledges an unbound or unattributed run", async () => {
    const f = await fixture();
    const w = f.make();
    await collect(w);
    const source = createWriterOverlaySource(w);
    await source.acknowledge({
      connector,
      ns: "",
      stream: "s",
      generation: 1,
      registryVersion: 1,
      dataHash: `0x${"ee".repeat(32)}`,
    });
    const snap = await source.snapshot(connector);
    expect(snap.runs).toHaveLength(1);
    snap.release();
    await f.edit((e) => {
      e.entry.ns = null;
    });
    await source.acknowledge({
      connector,
      ns: "",
      stream: "s",
      generation: 1,
      registryVersion: 1,
      dataHash: `0x${"ee".repeat(32)}`,
    });
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
  });
  it("retains A's receipt after B fails then is discarded, and reads a pin after acknowledgment", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    await w.append("r1", "s", { id: "a" }, shape);
    await w.append("r1", "z", { id: "b" }, shape);
    await w.finishRun("r1", { checkpointCandidate: null });
    const post = f.registry.post;
    f.registry.post = async (request) => {
      if (request.scope === streamScope(connector, "", "z"))
        throw new RegistryRefusedError("refused", 403);
      return post(request);
    };
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const failed = await source.snapshot(connector);
    expect(failed.runs[0]!.streams.map((s) => s.state)).toEqual([
      "published",
      "failed",
    ]);
    failed.release();
    const hashes = await controlHashes(
      streamSyncHashes.keccak256,
      await deriveKeyCheck(async (m) =>
        hmac(sha256, new Uint8Array(32).fill(4), m),
      ),
    );
    f.rows.set(controlScope(connector, ""), {
      found: true,
      version: 2,
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
      deleted: false,
    });
    await w.publishPending();
    const discarded = await source.snapshot(connector);
    expect(discarded.runs[0]!.streams.map((s) => s.name)).toEqual(["s"]);
    expect(discarded.runs[0]!.streams[0]!.state).toBe("published");
    await source.acknowledge(await coverageOf(f));
    expect(
      (await Array.fromAsync(discarded.lines(discarded.runs[0]!, "s"))).map(
        (l) => l.v.id,
      ),
    ).toEqual(["a"]);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    discarded.release();
    (await source.snapshot(connector)).release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("acknowledging A leaves a failed B readable", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    await w.append("r1", "s", { id: "a" }, shape);
    await w.append("r1", "z", { id: "b" }, shape);
    await w.finishRun("r1", { checkpointCandidate: null });
    const post = f.registry.post;
    f.registry.post = async (request) => {
      if (request.scope === streamScope(connector, "", "z"))
        throw new RegistryRefusedError("refused", 403);
      return post(request);
    };
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    await source.acknowledge(await coverageOf(f));
    const snap = await source.snapshot(connector);
    expect(snap.runs[0]!.streams.map((s) => s.name)).toEqual(["z"]);
    expect(
      (await Array.fromAsync(snap.lines(snap.runs[0]!, "z"))).map(
        (l) => l.v.id,
      ),
    ).toEqual(["b"]);
    snap.release();
    // An acknowledgment is not persisted independently of the reader's store.
    const reopened = await createWriterOverlaySource(f.make()).snapshot(
      connector,
    );
    expect(reopened.runs[0]!.streams.map((s) => s.name)).toEqual(["s", "z"]);
    reopened.release();
  });
});

describe("writer coverage that arrives before the receipt", () => {
  const log = "runs/r1/spool/s0.log";
  async function earlyAck(
    change: Record<string, unknown> = {},
    pinFirst = false,
  ) {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    const source = createWriterOverlaySource(w);
    const pin = pinFirst ? await source.snapshot(connector) : undefined;
    f.afterInstalled(async (request) => {
      await source.acknowledge({
        connector,
        ns: "",
        stream: "s",
        generation: (await f.read()).generation,
        registryVersion: Number(request.expectedVersion),
        dataHash: request.dataHash,
        ...change,
      });
    });
    await w.publishPending();
    return { f, w, source, pin };
  }
  it("reclaims after the receipt lands and the last pin is released", async () => {
    const { f, source, pin } = await earlyAck({}, true);
    expect(await f.files.size(log)).toBeGreaterThan(0);
    pin!.release();
    (await source.snapshot(connector)).release();
    expect(await f.files.size(log)).toBe(0);
  });
  it("reclaims at finish when nothing is pinned", async () => {
    const { f } = await earlyAck();
    expect(await f.files.size(log)).toBe(0);
  });
  it("reclaims a no-op against a head the reader already imported", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    // A newer empty run changes nothing in the head. (An older run is
    // refused out of order; writer-policies.test.ts covers that.)
    await collect(w, "a0");
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    await source.acknowledge({
      connector,
      ns: "",
      stream: "s",
      ...(await f.read("a0")).streams.s.receipt,
    });
    const posts = f.posts();
    await collect(w, "a1", []);
    await w.publishPending();
    expect(f.posts()).toBe(posts);
    expect(await f.files.read("runs/a1/entry.json")).toBeNull();
    expect(await f.files.size("runs/a1/spool/s0.log")).toBe(0);
  });
  it.each([
    { generation: 5 },
    { ns: "other" },
    { stream: "other" },
    { registryVersion: 0 },
  ])("reclaims nothing for early coverage %j", async (change) => {
    const { f } = await earlyAck(change);
    expect(await f.files.size(log)).toBeGreaterThan(0);
  });
});

describe("writer coverage hash spelling", () => {
  const log = "runs/r1/spool/s0.log";
  async function published() {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const coverage = await coverageOf(f);
    return { f, source: createWriterOverlaySource(w), coverage };
  }
  it.each([
    ["lowercase 0x", (h: string) => h],
    ["0x uppercase digits", (h: string) => `0x${h.slice(2).toUpperCase()}`],
    ["0X uppercase digits", (h: string) => `0X${h.slice(2).toUpperCase()}`],
    ["0X lowercase digits", (h: string) => `0X${h.slice(2)}`],
    ["unprefixed", (h: string) => h.slice(2)],
    ["unprefixed uppercase", (h: string) => h.slice(2).toUpperCase()],
  ])("covers a receipt for the %s spelling", async (_name, spell) => {
    const { f, source, coverage } = await published();
    await source.acknowledge({
      ...coverage,
      dataHash: spell(coverage.dataHash),
    });
    expect(await f.files.size(log)).toBe(0);
  });
  it("does not cover a different digest", async () => {
    const { f, source, coverage } = await published();
    await source.acknowledge({ ...coverage, dataHash: `0x${"ab".repeat(32)}` });
    expect(await f.files.size(log)).toBeGreaterThan(0);
  });
  it.each([
    "wrong",
    "0x",
    "0x12",
    `0x${"a".repeat(63)}`,
    `0x${"g".repeat(64)}`,
  ])(
    "rejects malformed hash %j at the acknowledgement boundary",
    async (dataHash) => {
      const { f, source, coverage } = await published();
      await expect(
        source.acknowledge({ ...coverage, dataHash }),
      ).rejects.toThrow();
      expect(await f.files.size(log)).toBeGreaterThan(0);
      await source.acknowledge(coverage);
      expect(await f.files.size(log)).toBe(0);
    },
  );
});

describe("writer cleanup failure", () => {
  it("retries a failed run removal without disabling later overlay reads", async () => {
    const f = await fixture();
    const warnings: Record<string, unknown>[] = [];
    const w = f.make({ logger: { warn: (obj) => warnings.push(obj) } });
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const pin = await source.snapshot(connector);
    const coverage = await coverageOf(f);
    await source.acknowledge(coverage);
    const remove = f.files.remove.bind(f.files);
    let failures = 0;
    f.files.remove = async (path) => {
      if (failures++ === 0) throw new Error("transient cleanup I/O failure");
      return remove(path);
    };
    pin.release();
    const later = await source.snapshot(connector);
    later.release();
    await source.acknowledge(coverage);
    (await source.snapshot(connector)).release();
    expect(failures).toBe(2);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({ runId: "r1" });
    expect(JSON.stringify(warnings)).not.toContain("one");
  });
});

describe("writer crash/read handoff", () => {
  it.each<StreamSyncFaultPoint>([
    "after_control_write",
    "after_parts_upload",
    "after_head_upload",
    "after_request_persisted",
    "after_post_reply",
    "after_commit_recorded",
    "after_checkpoint_saved",
  ])("retains readable rows across a crash at %s", async (point) => {
    const f = await fixture();
    if (point === "after_control_write") f.rows.clear();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    f.fault(point);
    await expect(w.publishPending()).rejects.toThrow("crash");
    const restarted = f.make();
    const source = createWriterOverlaySource(restarted);
    // Recovery and snapshot acquisition must not access the registry or blobs.
    const read = f.registry.read;
    f.registry.read = async () => {
      throw new Error("offline");
    };
    const snapshot = await source.snapshot(connector);
    expect(snapshot.runs).toHaveLength(1);
    expect(
      (await Array.fromAsync(snapshot.lines(snapshot.runs[0]!, "s"))).map(
        (l) => l.v.id,
      ),
    ).toEqual(["one"]);
    snapshot.release();
    f.registry.read = read;
    await restarted.publishPending();
    const coverage = await coverageOf(f);
    const published = await source.snapshot(connector);
    expect(published.runs[0]!.streams[0]!.receipt).toMatchObject({
      registryVersion: 1,
      generation: 1,
    });
    published.release();
    const posts = f.posts();
    await f.make().publishPending();
    expect(f.posts()).toBe(posts);
    await source.acknowledge(coverage);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("keeps a pre-publish snapshot pinned through commit and acknowledgment", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    const source = createWriterOverlaySource(w);
    const snapshot = await source.snapshot(connector);
    await w.publishPending();
    await source.acknowledge(await coverageOf(f));
    expect(snapshot.runs[0]!.streams[0]!.state).toBe("pending");
    expect(
      await Array.fromAsync(snapshot.lines(snapshot.runs[0]!, "s")),
    ).toHaveLength(1);
    snapshot.release();
    (await source.snapshot(connector)).release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
  it("releases a pin after a log failure without double-releasing another reader", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const source = createWriterOverlaySource(w);
    const bad = await source.snapshot(connector);
    const good = await source.snapshot(connector);
    const bytes = (await f.files.read("runs/r1/spool/s0.log"))!;
    await f.files.remove("runs/r1/spool/s0.log");
    await expect(
      Array.fromAsync(bad.lines(bad.runs[0]!, "s")),
    ).rejects.toThrow();
    bad.release();
    bad.release();
    await f.files.write("runs/r1/spool/s0.log", bytes);
    await source.acknowledge(await coverageOf(f));
    expect(await Array.fromAsync(good.lines(good.runs[0]!, "s"))).toHaveLength(
      1,
    );
    good.release();
    (await source.snapshot(connector)).release();
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
});

describe("writer checkpoint outcome retention", () => {
  it("retains published rows and receipt through a no_checkpoint result", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    const initial = f.rows.get(controlScope(connector, ""))!;
    f.onPoint((point) => {
      if (point === "after_commit_recorded" && initial.found)
        f.rows.set(controlScope(connector, ""), { ...initial, version: 3 });
    });
    const report = await w.publishPending();
    expect(report.runs[0]!.outcome?.kind).toBe("no_checkpoint");
    const source = createWriterOverlaySource(f.make());
    const snap = await source.snapshot(connector);
    expect(snap.runs[0]!.streams[0]!.state).toBe("published");
    expect(await Array.fromAsync(snap.lines(snap.runs[0]!, "s"))).toHaveLength(
      1,
    );
    snap.release();
    await source.acknowledge(await coverageOf(f));
    expect(await f.files.size("runs/r1/spool/s0.log")).toBe(0);
  });
});

describe("writer public run status", () => {
  it("reports a retained done run only in finished, never in pending", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const status = await w.status();
    expect(status.pending).toEqual([]);
    expect(status.finished.map((r) => r.runId)).toEqual(["r1"]);
  });
});

describe("writer recovery exclusions", () => {
  it("excludes and removes an abandoned collecting run on local recovery", async () => {
    const f = await fixture();
    const w = f.make();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    await w.append("r1", "s", { id: "partial" }, shape);
    const snap = await createWriterOverlaySource(f.make()).snapshot(connector);
    expect(snap.runs).toEqual([]);
    snap.release();
    expect(await f.files.read("runs/r1/entry.json")).toBeNull();
  });
  it("does not treat null namespace as the identity-less namespace for a receipt", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w);
    await w.publishPending();
    const coverage = await coverageOf(f);
    await f.edit((e) => {
      e.entry.ns = null;
    });
    const source = createWriterOverlaySource(f.make());
    await source.acknowledge(coverage);
    expect(await f.files.size("runs/r1/spool/s0.log")).toBeGreaterThan(0);
    const snap = await source.snapshot(connector);
    expect(snap.runs).toEqual([]);
    snap.release();
  });
});

/**
 * Rewrite a run's intake log as the base version wrote it
 * (`<k> <canonical {"o","r","v"}>`) and its persisted byte counts in the base
 * measure (line bytes + 1 per record), as a device that was ready before the
 * upgrade holds them.
 */
async function downgradeToBaseFormat(
  f: Awaited<ReturnType<typeof fixture>>,
  id = "r1",
): Promise<void> {
  const logPath = `runs/${id}/spool/s0.log`;
  const text = decoder.decode((await f.files.read(logPath))!);
  const counts = new Array<number>(256).fill(0);
  const out: string[] = [];
  for (const line of text.split("\n").filter((l) => l !== "")) {
    const [k, envelope, body] = line.split("\t") as [string, string, string];
    const { o, r } = JSON.parse(envelope) as { o: number; r: string };
    const old = `{"o":${o},"r":${JSON.stringify(r)},"v":${body}}`;
    out.push(`${k} ${old}\n`);
    counts[shardOf(k)]! += encoder.encode(old).length + 1;
  }
  await f.files.write(logPath, encoder.encode(out.join("")));
  await f.files.remove(`runs/${id}/spool/s0`);
  await f.edit((e) => {
    e.streams.s.shardBytes = counts;
  }, id);
}

describe("a run made ready before the upgrade", () => {
  const records = [{ id: "one" }, { id: "two", note: "é" }, { id: "one" }];
  it("is read by the local overlay", async () => {
    const f = await fixture();
    const w = f.make();
    await collect(w, "r1", records);
    await downgradeToBaseFormat(f);
    const source = createWriterOverlaySource(f.make());
    const snapshot = await source.snapshot(connector);
    expect(
      await Array.fromAsync(snapshot.lines(snapshot.runs[0]!, "s")),
    ).toEqual(records.map((v) => ({ o: 1000, r: "r1", v })));
    snapshot.release();
  });
  it("is published, keeping every record", async () => {
    const f = await fixture();
    const w = f.make();
    await w.refreshControls();
    await collect(w, "r1", records);
    await downgradeToBaseFormat(f);
    const restarted = f.make();
    await restarted.refreshControls();
    await restarted.publishPending();
    expect((await f.read()).phase).toBe("done");
    expect(f.posts()).toBe(1);
    const row = f.rows.get(streamScope(connector, "", "s"));
    expect(row).toMatchObject({ found: true, version: 1 });
  });
});
