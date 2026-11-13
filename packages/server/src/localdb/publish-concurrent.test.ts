// Publishing the streams of one connection together, bounded.
//
// Fake registry and storage whose calls take a fixed delay, the real SQLite
// driver and the real connection queue: only the wire is simulated. A stream's
// snapshot and commit still take the queue slot one at a time; what overlaps is
// every stream's transfer and the waits between slot turns.
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  publishConnection,
  type LocalSyncDeps,
  type PublishResult,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const CONTROL = controlScope(CONNECTOR, "");

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

type Call = {
  readonly seq: number;
  readonly kind: "read" | "post" | "get" | "put";
  readonly scope: string;
};

type Options = {
  readonly streams: number;
  /** Wait before every registry call. */
  readonly registryMs?: number;
  /** Wait before every blob call. */
  readonly blobMs?: number;
  /** Extra wait before a blob call on a key, by stream index. */
  readonly blobMsFor?: (stream: string) => number;
  /** Called when an upload starts, after it is logged; the upload waits for it. */
  readonly holdPut?: (key: string) => Promise<void>;
  /** Called when a blob read starts, after it is logged; the read waits for it. */
  readonly holdGet?: (key: string) => Promise<void>;
  /** Called when a stream's first encrypt call (its attachment's) starts. */
  readonly holdAttachmentEncrypt?: () => Promise<void>;
  /** Give every stream's record an attachment of its own. */
  readonly attachments?: boolean;
};

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const streamName = (i: number) => `s${i}`;
const streamOfKey = (key: string) => /\.(s\d+)\//.exec(key)?.[1] ?? null;

async function world(options: Options) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  const names = Array.from({ length: options.streams }, (_, i) =>
    streamName(i),
  );
  const calls: Call[] = [];
  const record = (kind: Call["kind"], scope: string) =>
    calls.push({ seq: calls.length, kind, scope });
  const innerRegistry = createMemoryStreamSyncRegistry();
  const registry: StreamSyncRegistry = {
    async read(scope) {
      record("read", scope);
      await sleep(options.registryMs ?? 0);
      return innerRegistry.read(scope);
    },
    async post(request) {
      record("post", request.scope);
      await sleep(options.registryMs ?? 0);
      return innerRegistry.post(request);
    },
    listControlRows: () => innerRegistry.listControlRows(),
    listStreamRows: (connector) => innerRegistry.listStreamRows(connector),
  };
  const innerBlobs = createMemoryStreamSyncBlobs();
  const timedBlobs: StreamSyncBlobs = {
    async get(key) {
      record("get", key);
      await options.holdGet?.(key);
      await sleep(
        (options.blobMs ?? 0) + (options.blobMsFor?.(streamOfKey(key)!) ?? 0),
      );
      return innerBlobs.get(key);
    },
    async put(key, bytes) {
      record("put", key);
      await options.holdPut?.(key);
      await sleep(
        (options.blobMs ?? 0) + (options.blobMsFor?.(streamOfKey(key)!) ?? 0),
      );
      await innerBlobs.put(key, bytes);
    },
  };
  const purges: number[] = [];
  const encrypting = new Set<string>();
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry,
    blobs: timedBlobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (scope, b) => {
        if (options.holdAttachmentEncrypt && !encrypting.has(scope)) {
          encrypting.add(scope);
          await options.holdAttachmentEncrypt();
        }
        return b;
      },
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: {
      info: (_o, message) => {
        if (message === "purge connection") purges.push(calls.length);
      },
      warn: () => {},
    },
    now: () => 1000,
    newOp: () => `op-${++op}`,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: names.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      })),
    }),
    declaredStreams: () => names,
    olderVersionReads: () => true,
  });
  await sync.intake.begin("run-1", {
    connector: CONNECTOR,
    artifactDigest: CONNECTOR,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  const attachment = (stream: string) => {
    const bytes = new TextEncoder().encode(`attachment of ${stream}`);
    return { bytes, sha256: createHash("sha256").update(bytes).digest("hex") };
  };
  await sync.intake.batch("run-1", {
    batch: 0,
    records: names.flatMap((stream) =>
      [1, 2].map((n) => ({
        stream,
        data: {
          id: `${stream}-${n}`,
          ...(options.attachments && n === 1
            ? { blob_ref: { blob_id: `sha256:${attachment(stream).sha256}` } }
            : {}),
        },
      })),
    ),
  });
  if (options.attachments)
    for (const stream of names) {
      const { bytes, sha256 } = attachment(stream);
      await sync.blobs.put({
        runId: "run-1",
        sha256,
        mimeType: "application/octet-stream",
        bytes,
      });
    }
  await sync.intake.end("run-1", {
    outcome: "succeeded",
    coveredStreams: names,
    lastBatch: 0,
  });
  return { deps, db, calls, purges, names, innerRegistry, sync };
}

async function tombstoneControl(
  registry: StreamSyncRegistry,
  version: number,
): Promise<void> {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  await registry.post({
    ownerAddress: OWNER,
    scope: CONTROL,
    dataHash: hashes.tombstoneData,
    metadataHash: hashes.tombstoneMetadata,
    expectedVersion: String(version),
    signature: "0x00",
  });
}

const timeIt = async <T>(fn: () => Promise<T>) => {
  const start = performance.now();
  const value = await fn();
  return { value, ms: performance.now() - start };
};

describe("streams of one connection publish together", () => {
  it("six streams take well under six streams' time", async () => {
    const slow = { streams: 6, registryMs: 3, blobMs: 40 };
    const serial = await world(slow);
    const one = await timeIt(() =>
      publishConnection(serial.deps, CONNECTION_ID, { streamConcurrency: 1 }),
    );
    const together = await world(slow);
    const many = await timeIt(() =>
      publishConnection(together.deps, CONNECTION_ID),
    );
    expect(one.value.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    expect(many.value.map((r) => r.outcome)).toEqual(
      Array(6).fill("published"),
    );
    // Serial: about 6 x 4 blob calls x 40 ms. Together the transfers overlap;
    // only the slot turns (registry calls) stay one after another.
    expect(many.ms).toBeLessThan(one.ms * 0.55);
  });

  it("never runs more streams at once than the option says", async () => {
    const { deps } = await world({ streams: 6, blobMs: 25 });
    const active = new Set<string>();
    let peak = 0;
    const original = deps.blobs;
    const watched: LocalSyncDeps = {
      ...deps,
      blobs: {
        async get(key) {
          const stream = streamOfKey(key)!;
          active.add(stream);
          peak = Math.max(peak, active.size);
          return original.get(key);
        },
        async put(key, bytes) {
          await original.put(key, bytes);
          // A stream's last blob call is its head: it leaves the set.
          if (/\/h-/.test(key)) active.delete(streamOfKey(key)!);
        },
      },
    };
    await publishConnection(watched, CONNECTION_ID, { streamConcurrency: 2 });
    expect(peak).toBeGreaterThan(1);
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("settles the control row once when streams start together", async () => {
    const { deps, calls } = await world({ streams: 6, registryMs: 2 });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    const controlPosts = calls.filter(
      (c) => c.kind === "post" && c.scope === CONTROL,
    );
    expect(controlPosts).toHaveLength(1);
    const control = await deps.registry.read(CONTROL);
    expect(control).toMatchObject({ found: true, version: 1 });
    // And every stream posted its own head exactly once.
    const streamPosts = calls.filter(
      (c) => c.kind === "post" && c.scope !== CONTROL,
    );
    expect(streamPosts).toHaveLength(6);
  });

  it("returns results in stream order whatever order the streams finish in", async () => {
    // s0 is the slowest, s5 the quickest.
    const { deps, names } = await world({
      streams: 6,
      blobMs: 2,
      blobMsFor: (stream) => (5 - Number(stream.slice(1))) * 30,
    });
    const finished: string[] = [];
    const logged: LocalSyncDeps = {
      ...deps,
      logger: {
        warn: deps.logger.warn,
        info: (obj, message) => {
          if (message === "stream sync: stream publish timings")
            finished.push(String(obj.stream));
          deps.logger.info(obj, message);
        },
      },
    };
    const results = await publishConnection(logged, CONNECTION_ID, {
      streamConcurrency: 6,
    });
    expect(results.map((r) => r.stream)).toEqual(names);
    expect(finished).not.toEqual(names);
    expect(finished).toHaveLength(6);
  });

  it("a control row deleted mid-publish purges, and nothing is written after the purge", async () => {
    // Every part upload waits for the test, so four streams sit in transfer.
    const parked: { key: string; release: () => void }[] = [];
    const { deps, calls, purges, innerRegistry } = await world({
      streams: 6,
      holdPut: (key) =>
        /-p-/.test(key)
          ? new Promise<void>((release) => parked.push({ key, release }))
          : Promise.resolve(),
    });
    const publishing = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(() => expect(parked).toHaveLength(4));
    // Another writer deletes the connection. The control row is at version 1.
    await tombstoneControl(innerRegistry, 2);
    // Only the first stream continues: its head upload and commit find it.
    parked[0]!.release();
    await vi.waitFor(() => expect(purges.length).toBeGreaterThan(0));
    const purgedAt = purges[0]!;
    for (const part of parked.slice(1)) part.release();
    const results = await publishing;

    // Today's shape: the results end at the purged stream.
    expect(results.at(-1)).toMatchObject({ outcome: "purged" });
    expect(results.filter((r) => r.outcome === "purged")).toHaveLength(1);
    expect(results.some((r) => r.outcome === "published")).toBe(false);
    // Nothing started after the purge: no upload, no read of a blob, no post.
    const after = calls.slice(purgedAt);
    expect(after.filter((c) => c.kind === "put" || c.kind === "get")).toEqual(
      [],
    );
    expect(after.filter((c) => c.kind === "post")).toEqual([]);
    // No stream head was ever posted: they were all still uploading.
    expect(
      calls.filter((c) => c.kind === "post" && c.scope !== CONTROL),
    ).toEqual([]);
    // The purge ran once.
    expect(purges).toHaveLength(1);
  });

  it("results end at the first purged stream and nothing is written", async () => {
    const { deps, calls, innerRegistry } = await world({ streams: 4 });
    const first = await publishConnection(deps, CONNECTION_ID, {
      streamConcurrency: 1,
    });
    expect(first.every((r) => r.outcome === "published")).toBe(true);
    // New rows in every stream, so every stream has work; then the control
    // row is deleted before the next publish starts.
    const names = ["s0", "s1", "s2", "s3"];
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: names.map((name) => ({
          name,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
        })),
      }),
      declaredStreams: () => names,
      olderVersionReads: () => true,
    });
    await sync.intake.begin("run-2", {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch("run-2", {
      batch: 0,
      records: names.map((stream) => ({
        stream,
        data: { id: `${stream}-new` },
      })),
    });
    await sync.intake.end("run-2", {
      outcome: "succeeded",
      coveredStreams: names,
      lastBatch: 0,
    });
    await tombstoneControl(innerRegistry, 2);
    const before = calls.length;
    const results: readonly PublishResult[] = await publishConnection(
      deps,
      CONNECTION_ID,
      { streamConcurrency: 4 },
    );
    // What the serial loop returned: the stream that found the purge, last.
    expect(results.map((r) => [r.stream, r.outcome])).toEqual([
      ["s0", "purged"],
    ]);
    expect(
      calls.slice(before).filter((c) => c.kind === "put" || c.kind === "post"),
    ).toEqual([]);
  });

  /**
   * Every stream parks past its last purge check: at its head probe, or with its attachment read and encrypted. One is let go
   * and purges the connection (the control row was deleted while all were
   * parked). The rest are then released with the read answering "absent", the
   * answer that sends a stream on to upload.
   */
  async function purgeWhileSiblingsProbe(
    options: Pick<Options, "attachments">,
    hold: "headProbe" | "attachmentEncrypt",
  ) {
    const parked: (() => void)[] = [];
    const park = () => new Promise<void>((release) => parked.push(release));
    const w = await world({
      streams: 4,
      ...options,
      holdGet: (key) =>
        hold === "headProbe" && /\/h-/.test(key) ? park() : Promise.resolve(),
      holdAttachmentEncrypt: hold === "attachmentEncrypt" ? park : undefined,
    });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(parked).toHaveLength(4));
    await tombstoneControl(w.innerRegistry, 2);
    // The first stream goes on, uploads, commits and finds the deleted control row.
    parked[0]!();
    await vi.waitFor(() => expect(w.purges.length).toBeGreaterThan(0));
    const purgedAt = w.purges[0]!;
    for (const release of parked.slice(1)) release();
    const results = await publishing;
    return { ...w, purgedAt, results };
  }

  it("starts no head upload after a sibling purged while its head probe was out", async () => {
    const { calls, purgedAt, results } = await purgeWhileSiblingsProbe(
      {},
      "headProbe",
    );
    expect(results.at(-1)).toMatchObject({ outcome: "purged" });
    expect(calls.slice(purgedAt).filter((c) => c.kind === "put")).toEqual([]);
    expect(calls.slice(purgedAt).filter((c) => c.kind === "post")).toEqual([]);
  });

  it("starts no attachment upload after a sibling purged while its attachment was being encrypted", async () => {
    const { calls, purgedAt, results } = await purgeWhileSiblingsProbe(
      { attachments: true },
      "attachmentEncrypt",
    );
    expect(results.at(-1)).toMatchObject({ outcome: "purged" });
    expect(calls.slice(purgedAt).filter((c) => c.kind === "put")).toEqual([]);
    expect(calls.slice(purgedAt).filter((c) => c.kind === "post")).toEqual([]);
  });

  it("on a failure starts no new stream, drains the running ones and throws the earliest stream's error", async () => {
    // s0 finishes slowly and well. s1 fails late, s2 fails early: the failures
    // arrive in the reverse of stream order. s3 to s5 wait for a free worker.
    const { deps, calls, db } = await world({
      streams: 6,
      holdPut: async (key) => {
        const stream = streamOfKey(key);
        if (stream === "s0") await sleep(150);
        if (stream === "s1") {
          await sleep(80);
          throw new Error("s1 upload failed");
        }
        if (stream === "s2") {
          await sleep(20);
          throw new Error("s2 upload failed");
        }
      },
    });
    await expect(
      publishConnection(deps, CONNECTION_ID, { streamConcurrency: 3 }),
    ).rejects.toThrow("s1 upload failed");
    const seen = calls.length;
    // The running stream was waited for: its head is posted before the rejection.
    expect(
      calls.some((c) => c.kind === "post" && c.scope.endsWith(".s0")),
    ).toBe(true);
    // No stream after the failure ever started.
    expect(calls.some((c) => /\.s[345]\b/.test(c.scope))).toBe(false);
    // And nothing runs on after the rejection.
    await sleep(100);
    expect(calls).toHaveLength(seen);
    // Every stream dropped its spool rows, the failed ones too.
    expect(await db.query("SELECT 1 FROM publish_spool")).toEqual([]);
  });

  it("refuses a stream concurrency that is not a positive whole number", async () => {
    const { deps } = await world({ streams: 1 });
    for (const bad of [0, -1, 1.5, Number.NaN])
      await expect(
        publishConnection(deps, CONNECTION_ID, { streamConcurrency: bad }),
      ).rejects.toThrow(/streamConcurrency/);
  });
});
