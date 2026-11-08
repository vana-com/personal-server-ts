/**
 * Own-write visibility: data a device collected itself must stay readable on
 * that device while stream-sync reads are on, whatever state its publish is in.
 *
 * Every test uses the real `StreamSyncWriter` and the real
 * `StreamSyncReadService` together, over in-memory files and a registry fake
 * whose publish can fail. The reader is opened over the writer's own overlay
 * source, the way a host wires it (`openReader`). Memory files are not durable,
 * so the reader never acknowledges coverage here.
 */

import { describe, expect, it } from "vitest";
import {
  AmbiguousRegistryReplyError,
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  createWriterOverlaySource,
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
import {
  controlScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import type { StreamSyncOverlaySnapshotSource } from "./ports.js";
import { StreamSyncReadService } from "./service.js";

const OWNER = `0x${"11".repeat(20)}` as const;
// A fixed 65-byte signature: the master key both sides derive from.
const SIGNATURE = `0x${"1f".repeat(32)}${"2a".repeat(32)}1b` as const;
const CONNECTOR = "acme";
// A 16-hex namespace other than the identity-less one every run uses.
const OTHER_NS = "0123456789abcdef";
const SHAPE = { primaryKey: ["id"], profile: { key: null, version: "1.0.0" } };
const T0 = Date.UTC(2026, 10, 1);
const silent = { info() {}, warn() {}, error() {} };

/** Gateway fake with the exclusive-version rules; `down` makes it unreachable. */
class Gateway implements StreamSyncRegistry {
  private readonly versions = new Map<
    string,
    { dataHash: string; metadataHash: string; at: string; deleted?: boolean }[]
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
      deleted: head.deleted ?? false,
    };
  }

  /** The stream row of `stream` in this connector, by its name. */
  private streamRow(stream: string): string {
    return [...this.versions.keys()].find(
      (s) => parseScope(s)?.kind === "stream" && s.endsWith(`.${stream}`),
    )!;
  }

  /** The control row of this connector. */
  private controlRow(): string {
    return [...this.versions.keys()].find(
      (s) => parseScope(s)?.kind === "control",
    )!;
  }

  /** The next version of `scope`: the head's hashes, deleted or live. */
  private append(scope: string, deleted: boolean): void {
    const rows = this.versions.get(scope)!;
    const head = rows[rows.length - 1]!;
    rows.push({
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      at: new Date(T0 + rows.length * 1000).toISOString(),
      ...(deleted ? { deleted: true } : {}),
    });
  }

  /** The owner deletes `stream`: a deletedAt tombstone as the next version. */
  deleteStream(stream = "items"): void {
    this.append(this.streamRow(stream), true);
  }

  /** The owner deletes the connection: its control row is tombstoned. */
  deleteControl(): void {
    this.append(this.controlRow(), true);
  }

  /**
   * The connection is connected by another device of this owner: its control
   * row (same key-bound hashes) appears here, with no publish on this device.
   */
  adoptControlFrom(other: Gateway): void {
    const scope = [...other.versions.keys()].find(
      (s) => parseScope(s)?.kind === "control",
    )!;
    this.versions.set(
      scope,
      other.versions.get(scope)!.map((row) => ({ ...row })),
    );
  }

  /** The connection is reconnected: its control row is live at a new version. */
  reviveControl(): void {
    this.append(this.controlRow(), false);
  }

  /** A stream row of another namespace, already tombstoned (v1 live, v2 deleted). */
  seedDeletedStream(scope: string): void {
    const at = (n: number) => new Date(T0 + n * 1000).toISOString();
    this.versions.set(scope, [
      {
        dataHash: `0x${"aa".repeat(32)}`,
        metadataHash: `0x${"bb".repeat(32)}`,
        at: at(1),
      },
      {
        dataHash: `0x${"aa".repeat(32)}`,
        metadataHash: `0x${"bb".repeat(32)}`,
        at: at(2),
        deleted: true,
      },
    ]);
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
        deletedAt: head.deleted ? head.at : null,
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

  /**
   * The reader, opened over this device's writer as its overlay source.
   * `durable` says whether its files may acknowledge imports to the writer;
   * `overlay` replaces the writer source (a lossy one, for restart tests).
   */
  async openReader(
    durable = false,
    overlay: StreamSyncOverlaySnapshotSource = createWriterOverlaySource(
      this.writer,
    ),
  ): Promise<StreamSyncReadService> {
    return StreamSyncReadService.open({
      files: this.readFiles,
      blobs: { get: async (key) => this.blobMap.get(key) ?? null },
      keys: await createStreamSyncReadKeys(
        streamMasterKeyFromSignature(SIGNATURE),
      ),
      logger: silent,
      overlay,
      durable,
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
    return this.collectStreams({ items: rows });
  }

  /** A finished run with one stream per key; its publish has not started. */
  async collectStreams(
    streams: Readonly<Record<string, readonly { id: string; v: number }[]>>,
  ): Promise<string> {
    const runId = await this.begin(streams);
    await this.finish(runId);
    return runId;
  }

  /**
   * A run started with its rows appended but not finished, so it is not ready
   * and no publish takes it. Its start state is read now.
   */
  async begin(
    streams: Readonly<Record<string, readonly { id: string; v: number }[]>>,
  ): Promise<string> {
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
    for (const [stream, rows] of Object.entries(streams)) {
      await this.writer.declareStream(runId, stream, SHAPE);
      for (const row of rows) await this.writer.append(runId, stream, row);
    }
    return runId;
  }

  /** Finish a run started by `begin`: it becomes ready, not published. */
  async finish(runId: string): Promise<void> {
    await this.writer.finishRun(runId, {
      checkpointCandidate: { cursor: runId },
    });
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

/**
 * A latest read of `pdpp.acme.items`, as the shared handler asks. `view` and
 * `local_pending` both carry the rows; `origin` is the body's marker.
 */
async function latest(service: StreamSyncReadService, stream = "items") {
  const decision = await service.resolve({
    scope: `pdpp.${CONNECTOR}.${stream}`,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind, rows: {} };
  }
  const envelope = JSON.parse(await new Response(decision.body).text());
  const rows: Record<string, number> = {};
  for (const r of envelope.data.records) rows[r.id] = r.v;
  return {
    kind: decision.kind,
    rows,
    ...(envelope.origin ? { origin: envelope.origin as string } : {}),
  };
}

/** The withheld runs the owner's latest read names (`[]` when none). */
async function withheldOf(service: StreamSyncReadService) {
  const decision = await service.resolve({
    scope: `pdpp.${CONNECTOR}.items`,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view" && decision.kind !== "local_pending") return [];
  const envelope = JSON.parse(await new Response(decision.body).text());
  return envelope.withheld ?? [];
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

  it("shows a new row and a newer value while the publish is pending", async () => {
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

  // DESIGN QUESTION (see the hand-back): once the writer has signed a POST and
  // recorded no answer, the run may have committed, so the reader defers it
  // with `publication_in_flight` (own-writes-state-table.md rule 10). The owner
  // still sees the older view, and the withheld run is named, never dropped.
  // The spec wanted the new rows here; that needs the rule changed first.
  it("withholds the new rows and names the run while the publish outcome is unknown", async () => {
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
      kind: "local_pending",
      rows: { r: 1 },
      origin: "local-pending",
    });
    const decision = await service.resolve({
      scope: `pdpp.${CONNECTOR}.items`,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    expect(decision).toMatchObject({
      kind: "local_pending",
      withheld: [{ runId, reason: "publication_in_flight" }],
    });
    if ("body" in decision) await decision.body.cancel();
  });

  it("shows the new rows while the gateway is unreachable", async () => {
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
    expect(await latest(service)).toMatchObject({ rows: { r: 2, new: 1 } });
  });
});

describe("own-write visibility (G2: no imported head)", () => {
  it("serves a first local stream from its pending rows", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "r", v: 1 }]); // publish pending, nothing imported
    expect(await latest(service)).toEqual({
      kind: "local_pending",
      rows: { r: 1 },
      origin: "local-pending",
    });
  });
});

describe("own-write visibility (G3: commit before self-import)", () => {
  it("still shows the new row after a successful publish, before the reader observes it", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.importedView(service, [{ id: "r", v: 1 }]);
    await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    await d.publish(); // committed; the reader has not listed the new row
    expect(d.streamVersion()).toBe(2);
    expect(await latest(service)).toMatchObject({
      rows: { r: 2, new: 1 },
    });
  });

  it("still shows the new row after the run directory is removed, while offline", async () => {
    const d = new Device();
    // Durable files: the reader's import is acknowledged, so the writer may
    // retire the run. In-memory files are durable enough for one test process.
    const service = await d.openReader(true);
    await d.importedView(service, [{ id: "r", v: 1 }]);
    const runId = await d.collect([
      { id: "r", v: 2 },
      { id: "new", v: 1 },
    ]);
    await d.publish();
    expect(d.streamVersion()).toBe(2);
    // Committed but not imported: the spool stays until the reader covers it.
    expect(d.runFiles(runId)).toBeGreaterThan(0);
    await d.syncReader(service); // imports version 2 and acknowledges it
    expect(d.runFiles(runId)).toBe(0); // the writer retired the spool
    d.gateway.down = true; // the reader cannot list or import its own head
    expect(await latest(service)).toMatchObject({
      kind: "view",
      rows: { r: 2, new: 1 },
    });
  });
});

describe("own-write visibility (G4: restart and acknowledgment)", () => {
  it("reclaims the spool after a restart re-acknowledges an import whose acknowledgment was lost", async () => {
    const d = new Device();
    const writerSource = createWriterOverlaySource(d.writer);
    // The first process imports, but its acknowledgment never reaches the writer.
    const lossy = await d.openReader(true, {
      snapshot: writerSource.snapshot,
      acknowledge: async () => {
        throw new Error("acknowledgment lost");
      },
    });
    const runId = await d.collect([{ id: "r", v: 1 }]);
    await d.publish();
    await d.syncReader(lossy);
    expect(d.streamVersion()).toBe(1);
    expect(d.runFiles(runId)).toBeGreaterThan(0); // still covered by no acknowledgment

    // Restart over the same read files with the real source: startup covers
    // every durable current view, so the writer retires the spool.
    const restarted = await d.openReader(true);
    expect(d.runFiles(runId)).toBe(0);
    expect(await latest(restarted)).toMatchObject({ rows: { r: 1 } });
  });

  // Named mutant: canonicalBytes32 returns its input unchanged (no lowercase).
  // The writer then compares the reader's upper-case digest with its lower-case
  // receipt, finds no coverage, and keeps the spool.
  it("reclaims a run when the reader acknowledges the digest in another letter case", async () => {
    const d = new Device();
    const service = await d.openReader(true, {
      snapshot: createWriterOverlaySource(d.writer).snapshot,
      acknowledge: async (coverage) =>
        d.writer.acknowledgeOverlay({
          ...coverage,
          dataHash: `0x${coverage.dataHash.slice(2).toUpperCase()}`,
        }),
    });
    const runId = await d.collect([{ id: "r", v: 1 }]);
    await d.publish();
    await d.syncReader(service);
    expect(d.streamVersion()).toBe(1);
    expect(d.runFiles(runId)).toBe(0);
  });
});

describe("own-write visibility (deletion floor)", () => {
  // Stream v1 holds run-1 (published). The owner deletes it (v2, observed and
  // imported: the floor is 2). A live row (v3) then replaces the tombstone and
  // the reader has not imported it yet, so no imported view covers run-1.
  async function deletedThenRelive(d: Device, service: StreamSyncReadService) {
    await d.collect([{ id: "a", v: 1 }]);
    await d.publish();
    d.gateway.deleteStream();
    await d.syncReader(service);
  }

  it("does not serve a run published before the deletion (overlay-only)", async () => {
    const d = new Device();
    const service = await d.openReader();
    await deletedThenRelive(d, service);
    await d.collect([{ id: "b", v: 2 }]);
    await d.publish();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(d.streamVersion()).toBe(3);
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
    expect((await latest(service)).rows).not.toHaveProperty("a");
  });

  it("does not serve a run published before the deletion, beside an in-flight run", async () => {
    const d = new Device();
    const service = await d.openReader();
    await deletedThenRelive(d, service);
    await d.collect([{ id: "b", v: 2 }]);
    await d.publish();
    d.gateway.failPosts = true;
    const inFlight = await d.collect([{ id: "c", v: 3 }]);
    await d.publish();
    d.gateway.failPosts = false;
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // The in-flight run's rows stay withheld (publication_in_flight), by design.
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
    expect((await latest(service)).rows).not.toHaveProperty("a");
    expect(await withheldOf(service)).toEqual([
      { runId: inFlight, stream: "items", reason: "publication_in_flight" },
    ]);
  });

  // The floor of one stream must not hide another stream's run. A floor
  // looked up under a fixed stream name hides `other` here and fails.
  it("deleting one stream hides only that stream's run, not a sibling stream's", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collectStreams({
      items: [{ id: "a", v: 1 }],
      other: [{ id: "x", v: 1 }],
    });
    await d.publish();
    d.gateway.deleteStream("items");
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(await latest(service, "other")).toMatchObject({ rows: { x: 1 } });
    expect((await latest(service, "items")).rows).not.toHaveProperty("a");
  });

  // A tombstone under another namespace must not hide this namespace's run. A
  // floor looked up under the wrong ns hides it here and fails.
  it("a deleted stream of another namespace does not hide this namespace's run", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "a", v: 1 }]);
    await d.publish();
    d.gateway.seedDeletedStream(streamScope(CONNECTOR, OTHER_NS, "items"));
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(await latest(service)).toMatchObject({ rows: { a: 1 } });
  });

  // A run collected under connection generation g stays pending when the
  // connection is deleted and reconnected: the reconnect is a new control
  // version, so the run's generation no longer matches and the reader hides it
  // (contributions(), service.ts:644-648). Guard test: it passes without the
  // delete predicate #563 adds (runDeletedSince).
  it("does not serve a run collected before a connection delete, after a reconnect", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "a", v: 1 }]);
    await d.publish();
    await d.collect([{ id: "b", v: 2 }]);
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // Precondition: the pending run is served while the connection is active.
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
    d.gateway.deleteControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    d.gateway.reviveControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // The precondition above shows `b` is served while active, so this absence
    // is the hiding, not an empty read.
    expect((await latest(service)).rows).not.toHaveProperty("b");
  });

  // The same rule for a run whose publish is in flight: its rows are never
  // served, so the check is on the withheld list the owner read names.
  it("does not name an in-flight run collected before a connection delete, after a reconnect", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "a", v: 1 }]);
    await d.publish();
    d.gateway.failPosts = true;
    const inFlight = await d.collect([{ id: "b", v: 2 }]);
    await d.publish();
    d.gateway.failPosts = false;
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // Precondition: the run is in flight under the active connection.
    expect(await withheldOf(service)).toEqual([
      { runId: inFlight, stream: "items", reason: "publication_in_flight" },
    ]);
    d.gateway.deleteControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    d.gateway.reviveControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(await withheldOf(service)).toEqual([]);
    expect((await latest(service)).rows).not.toHaveProperty("b");
  });

  // A run finished while the connection was absent has generation null (the
  // start state is "absent", which admits only generation 1: decide.ts, the
  // absent cell). The connection is then connected by another device, without
  // publishing this run. Served at generation 1, it must not be served after a
  // delete and reconnect to generation 3.
  it("does not serve a run finished before the first connect, once the connection is at generation 3", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collectStreams({ items: [{ id: "b", v: 2 }] });
    const other = new Device();
    await other.collect([{ id: "z", v: 1 }]);
    await other.publish();
    d.gateway.adoptControlFrom(other.gateway);
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // Precondition: absent then active at generation 1 admits the run.
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
    d.gateway.deleteControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    d.gateway.reviveControl();
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    // The connection is back at generation 3, not the run's absent start.
    expect(await d.gateway.read(controlScope(CONNECTOR, ""))).toMatchObject({
      found: true,
      version: 3,
      deleted: false,
    });
    expect((await latest(service)).rows).not.toHaveProperty("b");
  });

  // Twin: the connection stays absent, so the run is admitted and must serve.
  it("serves a run that finished while the connection was absent and is still absent", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collect([{ id: "b", v: 2 }]);
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
  });

  // Twin: absent, then the first connect at generation 1. Admitted, must serve.
  it("serves a run that finished before the first connect, when the connection is at generation 1", async () => {
    const d = new Device();
    const service = await d.openReader();
    await d.collectStreams({ items: [{ id: "b", v: 2 }] });
    const other = new Device();
    await other.collect([{ id: "z", v: 1 }]);
    await other.publish();
    d.gateway.adoptControlFrom(other.gateway);
    await service.observe(d.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    expect(await latest(service)).toMatchObject({ rows: { b: 2 } });
  });
});
