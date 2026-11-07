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
