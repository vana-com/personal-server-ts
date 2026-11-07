/**
 * Own-write visibility (all cases `it.skip`: "needs ow-writer source"; the
 * integration lane unskips them once the real writer-backed overlay source
 * exists and `openReader` passes it): data a device collected itself must stay readable on
 * that device while stream-sync reads are on, whatever state its publish is in.
 *
 * Every test uses the real `StreamSyncWriter` and the real
 * `StreamSyncReadService` together, over in-memory files and a registry fake
 * whose publish can fail. The reader is opened the way both hosts open it
 * today (`openReader`): no overlay source. These tests are red until a reader
 * sees its own writer's rows; they must stay red for that reason only (the row
 * is missing from the answer).
 */

import { describe, expect, it } from "vitest";
import {
  AmbiguousRegistryReplyError,
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  createStreamSyncKeyPorts,
  StreamSyncWriter,
  type RegistryPostResult,
  type SignedRegistryPost,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "../stream-sync/index.js";
import {
  parseScope,
  streamMasterKeyFromSignature,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createStreamSyncReadKeys } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import { StreamSyncReadService } from "./service.js";

const OWNER = `0x${"11".repeat(20)}` as const;
// A fixed 65-byte signature: the master key both sides derive from.
const SIGNATURE = `0x${"1f".repeat(32)}${"2a".repeat(32)}1b` as const;
const CONNECTOR = "acme";
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };
const T0 = Date.UTC(2026, 10, 1);
const silent = { info() {}, warn() {}, error() {} };

/** Gateway fake with the exclusive-version rules; `down` makes it unreachable. */
class Gateway implements StreamSyncRegistry {
  private readonly versions = new Map<
    string,
    { dataHash: string; metadataHash: string; at: string }[]
  >();
  down = false;
  /** `refuse`: post throws an ambiguous reply (publish fails, entry stays). */
  failPosts = false;

  private guard(): void {
    if (this.down) throw new Error("gateway unreachable");
  }

  async read(scope: string): Promise<ControlRead> {
    this.guard();
    const rows = this.versions.get(scope);
    if (!rows?.length) return { found: false };
    const head = rows[rows.length - 1]!;
    return {
      found: true,
      version: rows.length,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      deleted: false,
    };
  }

  async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
    this.guard();
    if (this.failPosts) throw new AmbiguousRegistryReplyError("reply lost");
    const rows = this.versions.get(request.scope) ?? [];
    if (Number(request.expectedVersion) !== rows.length + 1) {
      return { kind: "conflict", latestVersion: String(rows.length) };
    }
    rows.push({
      dataHash: request.dataHash,
      metadataHash: request.metadataHash,
      at: new Date(T0 + rows.length * 1000).toISOString(),
    });
    this.versions.set(request.scope, rows);
    return { kind: "committed" };
  }

  async listControlRows() {
    this.guard();
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys()) {
      if (parseScope(scope)?.kind === "control") {
        out.push({ scope, read: await this.read(scope) });
      }
    }
    return out;
  }

  /** What the listing feed shows a reader. */
  feed(): MirrorFeedRow[] {
    return [...this.versions].map(([scope, rows]) => {
      const head = rows[rows.length - 1]!;
      return {
        scope,
        dataHash: head.dataHash,
        metadataHash: head.metadataHash,
        expectedVersion: String(rows.length),
        addedAt: head.at,
        deletedAt: null,
      };
    });
  }
}

/** One device: a real writer and a real reader over one gateway and blob store. */
class Device {
  readonly gateway = new Gateway();
  readonly blobMap = new Map<string, Uint8Array>();
  readonly files = createMemoryStreamSyncFiles();
  readonly readFiles = createMemoryStreamSyncReadFiles();
  /** `put` fails while true: storage is unreachable. */
  storageDown = false;
  readonly writer: StreamSyncWriter;
  private runs = 0;

  constructor() {
    const blobs: StreamSyncBlobs = {
      put: async (key, bytes) => {
        if (this.storageDown) throw new Error("storage unreachable");
        this.blobMap.set(key, bytes.slice());
      },
      get: async (key) => this.blobMap.get(key) ?? null,
    };
    this.writer = new StreamSyncWriter({
      ownerAddress: OWNER,
      registry: this.gateway,
      blobs,
      home: bindStreamSyncHome({
        ownerAddress: OWNER,
        network: "test",
        open: () => this.files,
      }),
      keys: createStreamSyncKeyPorts(SIGNATURE),
      signer: { signAddData: async () => `0x${"22".repeat(65)}` },
      now: () => T0,
    });
  }

  /** The reader as both hosts build it today: no overlay source. */
  async openReader(): Promise<StreamSyncReadService> {
    return StreamSyncReadService.open({
      files: this.readFiles,
      blobs: { get: async (key) => this.blobMap.get(key) ?? null },
      keys: await createStreamSyncReadKeys(
        streamMasterKeyFromSignature(SIGNATURE),
      ),
      logger: silent,
      now: () => new Date(T0 + 3_600_000),
    });
  }

  /** The reader learns the gateway's rows and imports what changed. */
  async syncReader(service: StreamSyncReadService): Promise<void> {
    await service.observe(this.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    await service.importPending();
  }

  /** A finished run of `items`; its publish has not started. */
  async collect(rows: readonly { id: string; v: number }[]): Promise<string> {
    const runId = `run-${(this.runs += 1)}`;
    await this.writer.refreshControls();
    await this.writer.beginRun({
      runId,
      connector: CONNECTOR,
      userConnect: false,
      observedAt: T0 + this.runs * 60_000,
      identity: "none",
      checkpointUsed: null,
    });
    await this.writer.declareStream(runId, "items", SHAPE);
    for (const row of rows) await this.writer.append(runId, "items", row);
    await this.writer.finishRun(runId, {
      checkpointCandidate: { cursor: runId },
    });
    return runId;
  }

  /** Registry version of the stream row; 0 when none. */
  streamVersion(): number {
    const row = this.gateway
      .feed()
      .find((r) => parseScope(r.scope)?.kind === "stream");
    return row ? Number(row.expectedVersion) : 0;
  }

  /** Files left under a run's directory. */
  runFiles(runId: string): number {
    return this.files.paths().filter((p) => p.startsWith(`runs/${runId}/`))
      .length;
  }

  async publish(): Promise<void> {
    await this.writer.publishPending().catch(() => undefined);
  }

  /** Publish run 1 and import it: the older view H1. */
  async importedView(
    service: StreamSyncReadService,
    rows: readonly { id: string; v: number }[],
  ): Promise<void> {
    await this.collect(rows);
    await this.publish();
    await this.syncReader(service);
  }
}

/** A latest read of `pdpp.acme.items`, as the shared handler asks. */
async function latest(service: StreamSyncReadService) {
  const decision = await service.resolve({
    scope: `pdpp.${CONNECTOR}.items`,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view") return { kind: decision.kind, rows: {} };
  const envelope = JSON.parse(await new Response(decision.body).text());
  const rows: Record<string, number> = {};
  for (const r of envelope.data.records) rows[r.id] = r.v;
  return { kind: "view", rows };
}

const H1 = [
  { id: "a", v: 1 },
  { id: "r", v: 1 },
];
const OLD_VIEW = { kind: "view", rows: { a: 1, r: 1 } };

describe("own-write visibility (G1: older imported view)", () => {
  // The older view must be real before the new run starts.
  it("serves the older view before the new run (precondition)", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, H1);
    expect(await latest(service)).toEqual(OLD_VIEW);
  });

  it.skip("shows a new row and a newer value while the publish is pending [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]); // finished, publish not run
    expect(await latest(service)).toEqual({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });

  it.skip("shows the new rows while the publish keeps failing [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    const runId = await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    d.gateway.failPosts = true;
    await d.publish();
    expect(d.streamVersion()).toBe(1); // nothing committed
    expect(d.runFiles(runId)).toBeGreaterThan(0); // spool kept
    expect(await latest(service)).toEqual({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });

  it.skip("shows the new rows while the gateway is unreachable [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    const runId = await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    d.gateway.down = true;
    d.storageDown = true;
    await d.publish();
    expect(d.runFiles(runId)).toBeGreaterThan(0); // spool kept
    expect(await latest(service)).toEqual({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });
});

describe("own-write visibility (G2: no imported head)", () => {
  it.skip("serves a first local stream from its pending rows [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "r", v: 1 }]); // publish pending, nothing imported
    expect(await latest(service)).toEqual({ kind: "view", rows: { r: 1 } });
  });
});

describe("own-write visibility (G3: commit before self-import)", () => {
  it.skip("still shows the new row after a successful publish, before the reader observes it [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    await d.publish(); // committed; the reader has not listed the new row
    expect(d.streamVersion()).toBe(2);
    expect(await latest(service)).toEqual({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });

  it.skip("still shows the new row after the run directory is removed, while offline [needs ow-writer source]", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    const runId = await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    await d.publish();
    // Precondition: the writer retired the spool of the committed run.
    expect(d.streamVersion()).toBe(2);
    expect(d.runFiles(runId)).toBe(0);
    d.gateway.down = true; // the reader cannot list or import its own head
    expect(await latest(service)).toEqual({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });
});
