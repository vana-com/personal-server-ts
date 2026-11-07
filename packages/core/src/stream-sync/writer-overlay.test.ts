import { describe, expect, it } from "vitest";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  streamScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncHashes } from "./crypto.js";
import { bindStreamSyncHome } from "./home.js";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import {
  AmbiguousRegistryReplyError,
  type StreamSyncRegistry,
  type StreamSyncFaultPoint,
} from "./ports.js";
import { StreamSyncWriter } from "./writer.js";
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
  const make = () =>
    new StreamSyncWriter({
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
  it("omits seed-only streams and excluded oversized records", async () => {
    const f = await fixture();
    const w = f.make();
    await w.beginRun({ runId: "r1", connector, userConnect: false });
    expect(
      await w.append(
        "r1",
        "s",
        { id: "huge", value: "x".repeat(8 * 1024 * 1024) },
        shape,
      ),
    ).toBe("too_large");
    await w.append("r1", "s", { id: "kept" }, shape);
    await w.finishRun("r1", { checkpointCandidate: null });
    await f.edit((e) => {
      e.streams.seed = { ...e.streams.s, seedOnly: true, index: 1 };
      e.entry.streams.seed = { state: "planned" };
    });
    const snap = await createWriterOverlaySource(w).snapshot(connector);
    expect(snap.runs[0]!.streams.map((s) => s.name)).toEqual(["s"]);
    expect(
      (await Array.fromAsync(snap.lines(snap.runs[0]!, "s"))).map(
        (l) => l.v.id,
      ),
    ).toEqual(["kept"]);
    snap.release();
  });
});
