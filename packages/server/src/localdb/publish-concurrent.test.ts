// Publishing the streams of one connection together, bounded.
//
// Fake registry and storage whose calls take a fixed delay, the real SQLite
// driver and the real connection queue: only the wire is simulated. A stream's
// snapshot and commit still take the queue slot one at a time; what overlaps is
// every stream's transfer and the waits between slot turns.
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  HEAD_FORMAT,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  streamScope,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  publishConnection,
  purgeConnection,
  type LocalSyncDeps,
  type PublishResult,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  createStorageStreamSyncBlobs,
  StorageDeferredError,
  StorageObjectTooLargeError,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
// The built module, the one `purgeConnection` above runs: the memory of
// uploads is per module instance.
import {
  MissingAttachmentError,
  uploadBlobs,
} from "../../../core/dist/localdb/blobs.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
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
  readonly holdPut?: (key: string, bytes: number) => Promise<void>;
  /** Called when a blob read starts, after it is logged; the read waits for it. */
  readonly holdGet?: (key: string) => Promise<void>;
  /** Called when a stream's first encrypt call (its attachment's) starts. */
  readonly holdAttachmentEncrypt?: () => Promise<void>;
  /** Give every stream's record an attachment of its own. */
  readonly attachments?: boolean;
  /** The store's memory budget, as the blob store exposes it. */
  readonly governor?: StreamSyncBlobs["governor"];
  /** Wraps the in-memory store, for a test that runs the real storage client over it. */
  readonly store?: (inner: StreamSyncBlobs) => StreamSyncBlobs;
  /** Called at every encrypt (a head, an attachment) and encryptPart call. */
  readonly onEncrypt?: (kind: "encrypt" | "encryptPart") => void;
  /** Records per stream; default 2. */
  readonly recordsPerStream?: number;
  /** Pads every record by this many bytes, so a small part target cuts many parts. */
  readonly padBytes?: number;
  /** The part target, in bytes; the default is 4 MiB. */
  readonly partTargetBytes?: number;
  /** Called when the registry is asked to post, before it answers. */
  readonly onPost?: (scope: string) => void;
  /** A database file: the production driver with a separate read connection. Default: in memory. */
  readonly dbPath?: string;
};

const drivers: SqlDriver[] = [];
const scratchDirs: string[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
  for (const dir of scratchDirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

const streamName = (i: number) => `s${i}`;
const streamOfKey = (key: string) => /\.(s\d+)\//.exec(key)?.[1] ?? null;

async function world(options: Options) {
  const db = await openLocalDb(
    openBetterSqlite3(options.dbPath ?? ":memory:"),
    {
      owner: OWNER,
      network: "test",
      deviceId: "d",
    },
  );
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
      options.onPost?.(request.scope);
      await sleep(options.registryMs ?? 0);
      return innerRegistry.post(request);
    },
    listControlRows: () => innerRegistry.listControlRows(),
    listStreamRows: (connector) => innerRegistry.listStreamRows(connector),
    listConnectionRows: (connector, ns) =>
      innerRegistry.listConnectionRows(connector, ns),
  };
  // A budget that never binds: these tests are about streams, not memory. The
  // tests that are about the budget pass a governor of their own.
  const innerBlobs = createMemoryStreamSyncBlobs({
    maxBytesInFlight: 1024 * 1024 * 1024,
  });
  /** Keys storage answers "absent" for, as if removed from outside. */
  const hidden = new Set<string>();
  const guards: { key: string; guard: (() => void) | undefined }[] = [];
  const timedBlobs: StreamSyncBlobs = {
    governor: options.governor ?? innerBlobs.governor,
    async get(key) {
      record("get", key);
      await options.holdGet?.(key);
      await sleep(
        (options.blobMs ?? 0) + (options.blobMsFor?.(streamOfKey(key)!) ?? 0),
      );
      return innerBlobs.get(key);
    },
    // The existence probe is the same request class as a read here.
    async exists(key) {
      record("get", key);
      await options.holdGet?.(key);
      await sleep(
        (options.blobMs ?? 0) + (options.blobMsFor?.(streamOfKey(key)!) ?? 0),
      );
      return !hidden.has(key) && (await innerBlobs.exists(key));
    },
    async put(key, bytes, beforeAttempt) {
      record("put", key);
      guards.push({ key, guard: beforeAttempt });
      await options.holdPut?.(key, bytes.length);
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
    blobs: options.store ? options.store(innerBlobs) : timedBlobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (scope, b) => {
        options.onEncrypt?.("encrypt");
        if (options.holdAttachmentEncrypt && !encrypting.has(scope)) {
          encrypting.add(scope);
          await options.holdAttachmentEncrypt();
        }
        return b;
      },
      encryptPart: async (_s, b) => {
        options.onEncrypt?.("encryptPart");
        return b;
      },
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
    ...(options.partTargetBytes === undefined
      ? {}
      : { partTargetBytes: options.partTargetBytes }),
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
      Array.from(
        { length: options.recordsPerStream ?? 2 },
        (_, i) => i + 1,
      ).map((n) => ({
        stream,
        data: {
          id: `${stream}-${n}`,
          ...(options.padBytes ? { pad: "x".repeat(options.padBytes) } : {}),
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
  await sync.intake.end("run-1", endRequest({ lastBatch: 0, live: names }));
  return {
    deps,
    db,
    calls,
    guards,
    purges,
    names,
    innerRegistry,
    innerBlobs,
    hidden,
    sync,
  };
}

/** A head another device wrote, with no rows, as the stream's row at `version`. */
async function foreignHead(
  w: Awaited<ReturnType<typeof world>>,
  stream: string,
  version: number,
): Promise<void> {
  const scope = streamScope(CONNECTOR, "", stream);
  const keyCheck = await deriveKeyCheck(w.deps.keys.namespaceHmac);
  const head: Head = {
    complete: false,
    connector: CONNECTOR,
    format: HEAD_FORMAT,
    generation: 1,
    keyCheck,
    lastDeleteVersion: 0,
    ns: "",
    observedAt: 1000,
    parts: [],
    primaryKey: ["id"],
    profile: { key: CONNECTOR, version: "1" },
    recordCount: 0,
    replacedAt: 1000,
    stream,
  };
  const bytes = encodeHead(head);
  const { dataHash, blobName } = await digestHead(
    async (b) => keccak_256(b),
    bytes,
  );
  await w.innerBlobs.put(`${scope}/${blobName}`, bytes);
  await w.innerRegistry.post({
    ownerAddress: OWNER,
    scope,
    dataHash,
    metadataHash: `0x${"22".repeat(32)}`,
    expectedVersion: String(version),
    signature: "0x00",
  });
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
    const together = await world(slow);
    const many = await timeIt(() =>
      publishConnection(together.deps, CONNECTION_ID),
    );
    expect(many.value.map((r) => r.outcome)).toEqual(
      Array(6).fill("published"),
    );
    // One after another it could not be quicker than 6 streams x 4 blob calls
    // x 40 ms. Together the transfers overlap; only the slot turns (registry
    // calls) stay one after another.
    expect(many.ms).toBeLessThan(6 * 4 * 40 * 0.55);
  });

  it("starts every stream at once: no stream count bounds them", async () => {
    // Every upload parks until all six streams have one out. A bound below six
    // would leave a stream unstarted, and the wait would never be satisfied.
    const parked: { stream: string; release: () => void }[] = [];
    const { deps } = await world({
      streams: 6,
      holdPut: (key) =>
        new Promise<void>((release) =>
          parked.push({ stream: streamOfKey(key)!, release }),
        ),
    });
    const publishing = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(() =>
      expect(new Set(parked.map((p) => p.stream)).size).toBe(6),
    );
    for (let i = 0; i < parked.length; i++) parked[i]!.release();
    // Uploads started after the first release park too: let them all go.
    const open = setInterval(() => {
      for (const p of parked.splice(0)) p.release();
    }, 5);
    try {
      expect((await publishing).map((r) => r.outcome)).toEqual(
        Array(6).fill("published"),
      );
    } finally {
      clearInterval(open);
    }
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
    const results = await publishConnection(logged, CONNECTION_ID);
    expect(results.map((r) => r.stream)).toEqual(names);
    expect(finished).not.toEqual(names);
    expect(finished).toHaveLength(6);
  });

  it("a control row deleted mid-publish purges, and nothing is written after the purge", async () => {
    // Every part upload waits for the test, so all six streams sit in transfer.
    const parked: { key: string; release: () => void }[] = [];
    const { deps, calls, purges, innerRegistry } = await world({
      streams: 6,
      holdPut: (key) =>
        /-p-/.test(key)
          ? new Promise<void>((release) => parked.push({ key, release }))
          : Promise.resolve(),
    });
    const publishing = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(() => expect(parked).toHaveLength(6));
    // Another writer deletes the connection. The control row is at version 1.
    await tombstoneControl(innerRegistry, 2);
    // Only the first stream continues: its head upload and commit find it.
    parked[0]!.release();
    await vi.waitFor(() => expect(purges.length).toBeGreaterThan(0));
    const purgedAt = purges[0]!;
    for (const part of parked.slice(1)) part.release();
    const results = await publishing;

    // Every stream that started reports it, in stream order; none published.
    expect(results.length).toBeGreaterThan(0);
    expect(results.map((r) => r.stream)).toEqual(
      results.map((_, i) => streamName(i)),
    );
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
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

  it("hands every upload's purge guard down to the storage layer", async () => {
    // The storage wrapper runs the guard right before each request, after its
    // queue and retry waits (see storage-retry.test.ts). Parts, attachments and
    // heads all pass one.
    const { deps, guards } = await world({ streams: 2, attachments: true });
    await publishConnection(deps, CONNECTION_ID);
    const kind = (key: string) =>
      /-p-/.test(key) ? "part" : /-b-/.test(key) ? "attachment" : "head";
    expect(new Set(guards.map(({ key }) => kind(key)))).toEqual(
      new Set(["part", "attachment", "head"]),
    );
    expect(guards.filter(({ guard }) => typeof guard !== "function")).toEqual(
      [],
    );
  });

  it("keeps the result of a stream that published while a slower one found the purge", async () => {
    // s0 parks in its part upload; s1 publishes completely; then the control
    // row is deleted and s0 is let go, so it finds the tombstone at its commit.
    let release!: () => void;
    const parked = new Promise<void>((r) => (release = r));
    const { deps, db, innerRegistry } = await world({
      streams: 2,
      holdPut: (key) => (/\.s0\/.*-p-/.test(key) ? parked : Promise.resolve()),
    });
    const publishing = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(async () =>
      expect(
        await db.query(
          "SELECT 1 FROM run_streams WHERE stream='s1' AND publication_state='published'",
        ),
      ).toHaveLength(1),
    );
    await tombstoneControl(innerRegistry, 2);
    release();
    const results = await publishing;

    // Every stream that started has a result, in stream order. Purged is an
    // explicit status, and it does not hide the stream that published.
    expect(results.map((r) => [r.stream, r.outcome])).toEqual([
      ["s0", "purged"],
      ["s1", "published"],
    ]);
  });

  it("every stream that started reports the purge and nothing is written", async () => {
    const { deps, calls, innerRegistry } = await world({ streams: 4 });
    const first = await publishConnection(deps, CONNECTION_ID);
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
    await sync.intake.end("run-2", endRequest({ lastBatch: 0, live: names }));
    await tombstoneControl(innerRegistry, 2);
    const before = calls.length;
    const results: readonly PublishResult[] = await publishConnection(
      deps,
      CONNECTION_ID,
    );
    // All four started together; each found the purge.
    expect(results.map((r) => [r.stream, r.outcome])).toEqual([
      ["s0", "purged"],
      ["s1", "purged"],
      ["s2", "purged"],
      ["s3", "purged"],
    ]);
    expect(
      calls.slice(before).filter((c) => c.kind === "put" || c.kind === "post"),
    ).toEqual([]);
  });

  /**
   * Every stream parks past its last purge check: with its head, or its attachment, read and encrypted (a first publish
   * has no probe to park at). One is let go
   * and purges the connection (the control row was deleted while all were
   * parked). The rest are then released with the read answering "absent", the
   * answer that sends a stream on to upload.
   */
  async function purgeWhileSiblingsEncrypt(
    options: Pick<Options, "attachments">,
  ) {
    const parked: (() => void)[] = [];
    const park = () => new Promise<void>((release) => parked.push(release));
    const w = await world({
      streams: 4,
      ...options,
      // A stream's first encrypt call is its attachment's, else its head's.
      holdAttachmentEncrypt: park,
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

  it("starts no head upload after a sibling purged while its head was being encrypted", async () => {
    const { calls, purgedAt, results } = await purgeWhileSiblingsEncrypt({});
    expect(results.at(-1)).toMatchObject({ outcome: "purged" });
    expect(calls.slice(purgedAt).filter((c) => c.kind === "put")).toEqual([]);
    expect(calls.slice(purgedAt).filter((c) => c.kind === "post")).toEqual([]);
  });

  it("starts no attachment upload after a sibling purged while its attachment was being encrypted", async () => {
    const { calls, purgedAt, results } = await purgeWhileSiblingsEncrypt({
      attachments: true,
    });
    expect(results.at(-1)).toMatchObject({ outcome: "purged" });
    expect(calls.slice(purgedAt).filter((c) => c.kind === "put")).toEqual([]);
    expect(calls.slice(purgedAt).filter((c) => c.kind === "post")).toEqual([]);
  });

  it("an attachment-only stream whose connection was deleted while its attachment was out purges and does not say noop", async () => {
    // The stream's row is unchanged; only its attachment is not known to be
    // in storage (a driver the process has not uploaded through), so its turn
    // ends with an attachment to upload and nothing to publish. One stream, so
    // that no sibling's purge can stop it: only the check after the upload can.
    let tombstoned: Promise<void> | undefined;
    const probe: { run?: () => Promise<void> } = {};
    const w = await world({
      streams: 1,
      attachments: true,
      holdGet: async (key) => {
        if (/-b-/.test(key)) await probe.run?.();
      },
    });
    const first = await publishConnection(w.deps, CONNECTION_ID);
    expect(first.map((r) => r.outcome)).toEqual(["published"]);
    const db = w.db;
    const fresh: LocalSyncDeps = {
      ...w.deps,
      db: {
        info: db.info,
        query: (sql, params) => db.query(sql, params),
        batch: (statements) => db.batch(statements),
        close: () => db.close(),
      },
    };
    // The control row is at version 1; another device deletes the connection
    // while the attachment is being probed, after the snapshot.
    probe.run = () => (tombstoned ??= tombstoneControl(w.innerRegistry, 2));
    const results = await publishConnection(fresh, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["purged"]);
    expect(w.purges.length).toBeGreaterThan(0);
  });

  it("an attachment-only stream whose row another device advanced while its attachment was out plans again, and does not say noop", async () => {
    // Same shape as above, but the stream row moves instead of the connection
    // going away. The plan that found nothing to publish was over the old row.
    let advanced: Promise<void> | undefined;
    const probe: { run?: () => Promise<void> } = {};
    const w = await world({
      streams: 1,
      attachments: true,
      holdGet: async (key) => {
        if (/-b-/.test(key)) await probe.run?.();
      },
    });
    const first = await publishConnection(w.deps, CONNECTION_ID);
    expect(first.map((r) => r.outcome)).toEqual(["published"]);
    const db = w.db;
    const fresh: LocalSyncDeps = {
      ...w.deps,
      db: {
        info: db.info,
        query: (sql, params) => db.query(sql, params),
        batch: (statements) => db.batch(statements),
        close: () => db.close(),
      },
    };
    const headVersion = async () =>
      (
        await db.query<{ v: number }>(
          "SELECT head_version AS v FROM stream_state WHERE connection_id = ? AND stream = 's0'",
          [CONNECTION_ID],
        )
      )[0]!.v;
    expect(await headVersion()).toBe(1);
    probe.run = () => (advanced ??= foreignHead(w, "s0", 2));
    const results = await publishConnection(fresh, CONNECTION_ID);
    // The winner's head holds none of this device's rows: the stream applied
    // it (version 2), planned again over it and published its own (version 3).
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    expect(await headVersion()).toBe(3);
  });

  it("remembers an uploaded attachment until the connection is purged, and not after", async () => {
    // What this process uploaded is not probed again while the lifetime lives
    // (an idle cycle would otherwise ask for every attachment every time). A
    // purge ends the lifetime: storage may have dropped the objects, and the
    // memory must not vouch for them.
    const w = await world({ streams: 1, attachments: true });
    expect(
      (await publishConnection(w.deps, CONNECTION_ID)).map((r) => r.outcome),
    ).toEqual(["published"]);
    const key = w.calls.find(
      (c) => c.kind === "put" && /-b-/.test(c.scope),
    )!.scope;
    const [{ blob_id: blobId }] = (await w.db.query<{ blob_id: string }>(
      "SELECT blob_id FROM blobs",
    )) as [{ blob_id: string }];
    const descriptor = {
      blobId,
      key,
      scope: streamScope(CONNECTOR, "", "s0"),
    };
    w.hidden.add(key);
    // Remembered: no probe, so the missing object goes unnoticed.
    await uploadBlobs(w.deps, [descriptor]);
    await purgeConnection(w.deps, CONNECTION_ID, { controlVersion: 2 });
    // Forgotten: probed, found absent, and the bytes are gone with the purge.
    await expect(uploadBlobs(w.deps, [descriptor])).rejects.toBeInstanceOf(
      MissingAttachmentError,
    );
  });

  it("on a failure waits for every running stream and throws the earliest stream's error", async () => {
    // All six streams start. Each parks at its first part upload on a gate the
    // test controls: s1 and s2 will fail, in the reverse of stream order, and
    // the others will succeed.
    type Gate = { settle: (error?: Error) => void; promise: Promise<void> };
    const gates = new Map<string, Gate>();
    const gateFor = (stream: string): Gate => {
      let gate = gates.get(stream);
      if (!gate) {
        let settle!: Gate["settle"];
        const promise = new Promise<void>((resolve, reject) => {
          settle = (error) => (error ? reject(error) : resolve());
        });
        // A rejection is observed by the upload that awaits the gate.
        promise.catch(() => {});
        gates.set(stream, (gate = { settle, promise }));
      }
      return gate;
    };
    const { deps, calls, db } = await world({
      streams: 6,
      holdPut: (key) =>
        /-p-/.test(key)
          ? gateFor(streamOfKey(key)!).promise
          : Promise.resolve(),
    });
    let settled = false;
    const publishing = publishConnection(deps, CONNECTION_ID);
    const outcome = publishing.then(
      () => (settled = true),
      () => (settled = true),
    );
    // A few setImmediate turns, not timers: whatever a failure would set going
    // has run.
    const quiet = async () => {
      for (let turn = 0; turn < 10; turn++)
        await new Promise<void>((r) => setImmediate(r));
    };
    await vi.waitFor(() =>
      expect([...gates.keys()].sort()).toEqual([
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
      ]),
    );

    // The later stream fails first: nothing is rejected yet.
    gates.get("s2")!.settle(new Error("s2 upload failed"));
    await quiet();
    expect(settled).toBe(false);

    // The earlier stream fails second: still waiting for the others.
    gates.get("s1")!.settle(new Error("s1 upload failed"));
    await quiet();
    expect(settled).toBe(false);

    // The rest finish; only then does the publish end, with the earliest error.
    for (const stream of ["s0", "s3", "s4", "s5"]) gates.get(stream)!.settle();
    await expect(publishing).rejects.toThrow("s1 upload failed");
    await outcome;
    // The running streams were waited for: their heads are posted before the rejection.
    for (const stream of ["s0", "s3", "s4", "s5"])
      expect(
        calls.some((c) => c.kind === "post" && c.scope.endsWith(`.${stream}`)),
      ).toBe(true);
    // Every stream dropped its spool rows, the failed ones too.
    expect(await db.query("SELECT 1 FROM publish_spool")).toEqual([]);
  });

  it("leaves a stream in the queue, not failed, when storage defers its upload", async () => {
    const { deps, calls, db } = await world({
      streams: 3,
      holdPut: (key) =>
        streamOfKey(key) === "s1" && /-p-/.test(key)
          ? Promise.reject(
              new StorageDeferredError(
                180_000,
                new Error("Storage PUT failed (429)"),
              ),
            )
          : Promise.resolve(),
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => [r.stream, r.outcome])).toEqual([
      ["s0", "published"],
      ["s1", "backoff"],
      ["s2", "published"],
    ]);
    // Nothing of the deferred stream was posted: its watermark did not move,
    // so the next cycle sends it again.
    expect(
      calls.some((c) => c.kind === "post" && c.scope.endsWith(".s1")),
    ).toBe(false);
    expect(await db.query("SELECT 1 FROM publish_spool")).toEqual([]);
  });
});

/** A memory budget that logs what is reserved and released, and can be made to wait or refuse. */
function recordingGovernor(
  reserveFirst?: (bytes: number, objectBytes?: number) => Promise<void>,
) {
  const state = {
    held: 0,
    peak: 0,
    reserves: [] as string[],
    /** What each reservation was shrunk to, in order. */
    shrinks: [] as number[],
  };
  const governor: NonNullable<StreamSyncBlobs["governor"]> = {
    async reserve(bytes, objectBytes) {
      state.reserves.push(`${bytes}/${objectBytes ?? "-"}`);
      await reserveFirst?.(bytes, objectBytes);
      state.held += bytes;
      state.peak = Math.max(state.peak, state.held);
      let kept = bytes;
      return Object.assign(
        () => {
          state.held -= kept;
          kept = 0;
        },
        {
          shrink(keep: number) {
            state.shrinks.push(keep);
            const next = Math.max(0, Math.min(kept, keep));
            state.held -= kept - next;
            kept = next;
          },
        },
      );
    },
    window: () => ({
      end: () => ({
        window: 1,
        requests: 0,
        throttles: 0,
        retryAfterWaitMs: 0,
        peakBytesInFlight: 0,
      }),
    }),
  };
  return { state, governor };
}

describe("the memory budget is taken before data is built", () => {
  it("holds a reservation at every encrypt and every upload, and gives all of it back", async () => {
    const { state, governor } = recordingGovernor();
    const heldAt = {
      encrypt: [] as number[],
      encryptPart: [] as number[],
      put: [] as number[],
    };
    const { deps } = await world({
      streams: 3,
      attachments: true,
      governor,
      onEncrypt: (kind) => heldAt[kind].push(state.held),
      holdPut: async () => void heldAt.put.push(state.held),
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
    // 3 attachments and 3 heads are encrypted, 3 parts are encrypted: each
    // with memory held, and each upload (attachment, part, head) too.
    expect(heldAt.encrypt).toHaveLength(6);
    expect(heldAt.encryptPart).toHaveLength(3);
    expect(heldAt.put).toHaveLength(9);
    for (const held of [
      ...heldAt.encrypt,
      ...heldAt.encryptPart,
      ...heldAt.put,
    ])
      expect(held).toBeGreaterThan(0);
    // An attachment is held twice (plain and encrypted) and named by its own size.
    const attachment = new TextEncoder().encode("attachment of s0").length;
    expect(state.reserves).toContain(`${2 * attachment}/${attachment}`);
    // One reservation per part, one per head and one per attachment: nothing
    // is built unreserved, and a sibling's reservation cannot stand in for it.
    // A part is held twice (plain and encrypted) and named by its own size,
    // like an attachment; a head is one part-target unit that names no object.
    const partUnit = 4 * 1024 * 1024;
    expect(state.reserves.filter((r) => r === `${partUnit}/-`)).toHaveLength(3);
    expect(
      state.reserves.filter((r) => r === `${2 * partUnit}/${partUnit}`),
    ).toHaveLength(3);
    expect(state.reserves).toHaveLength(9);
    expect(state.held).toBe(0);
  });

  it("keeps a part's own reservation until its upload has ended", async () => {
    // One stream, so no sibling's reservation can stand in for the part's.
    const { state, governor } = recordingGovernor();
    const heldAtPut: Array<{ head: boolean; held: number; bytes: number }> = [];
    const { deps } = await world({
      streams: 1,
      governor,
      holdPut: async (key, bytes) => {
        heldAtPut.push({
          head: /\/h-/.test(key),
          held: state.held,
          bytes,
        });
      },
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    const part = heldAtPut.find((p) => !p.head);
    const head = heldAtPut.find((p) => p.head);
    // Once encrypted a part holds only its ciphertext: the plain bytes are
    // dropped and the reservation shrinks to what the PUT still carries.
    expect(part?.held).toBe(part?.bytes);
    expect(part?.held).toBeGreaterThan(0);
    expect(head?.held).toBeGreaterThanOrEqual(4 * 1024 * 1024);
    expect(state.held).toBe(0);
  });

  it("shrinks an attachment's reservation to its ciphertext once it is encrypted", async () => {
    const { state, governor } = recordingGovernor();
    const { deps } = await world({ streams: 1, attachments: true, governor });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    // The plain bytes are dropped, as a part's are: what the upload keeps is
    // the attachment's own size (the test cipher adds nothing).
    const attachment = new TextEncoder().encode("attachment of s0").length;
    expect(state.shrinks).toContain(attachment);
    expect(state.held).toBe(0);
  });

  it("builds and encrypts nothing for any stream while the budget is full", async () => {
    let open!: () => void;
    const full = new Promise<void>((resolve) => (open = resolve));
    const { state, governor } = recordingGovernor(() => full);
    let built = 0;
    const { deps } = await world({
      streams: 6,
      attachments: true,
      governor,
      onEncrypt: () => built++,
    });
    const publishing = publishConnection(deps, CONNECTION_ID);
    await vi.waitFor(() => expect(state.reserves.length).toBeGreaterThan(0));
    await sleep(100);
    expect(built).toBe(0);
    expect(state.held).toBe(0);
    open();
    expect((await publishing).map((r) => r.outcome)).toEqual(
      Array(6).fill("published"),
    );
    expect(state.held).toBe(0);
  });

  it("gives the memory back when an upload fails", async () => {
    const { state, governor } = recordingGovernor();
    const { deps } = await world({
      streams: 2,
      attachments: true,
      governor,
      holdPut: async (key) => {
        if (/\/h-/.test(key)) throw new Error("head upload refused");
      },
    });
    await expect(publishConnection(deps, CONNECTION_ID)).rejects.toThrow(
      "head upload refused",
    );
    await vi.waitFor(() => expect(state.held).toBe(0));
  });

  it("fails with the store's own limit error, and posts no head, for an attachment it could never accept", async () => {
    const { governor } = recordingGovernor(async (_bytes, objectBytes) => {
      if (objectBytes !== undefined && objectBytes > 10)
        throw new StorageObjectTooLargeError(objectBytes, 10);
    });
    const w = await world({ streams: 1, attachments: true, governor });
    await expect(
      publishConnection(w.deps, CONNECTION_ID),
    ).rejects.toBeInstanceOf(StorageObjectTooLargeError);
    // The control row is settled before any transfer; no stream head is posted.
    expect(
      w.calls.filter((c) => c.kind === "post" && c.scope !== CONTROL),
    ).toEqual([]);
  });
});

describe("the uploads of every stream's wave go through one send gate", () => {
  it("never has more requests on the wire than the gate's window, with every stream's wave started", async () => {
    let onWire = 0;
    let peak = 0;
    const wire = async <T>(work: () => Promise<T>): Promise<T> => {
      onWire += 1;
      peak = Math.max(peak, onWire);
      try {
        await sleep(40);
        return await work();
      } finally {
        onWire -= 1;
      }
    };
    const partBytes = 4 * 1024 * 1024;
    const { deps } = await world({
      streams: 6,
      attachments: true,
      store: (inner) =>
        createStorageStreamSyncBlobs(
          {
            urlForKey: (key: string) => key,
            upload: (key: string, bytes: Uint8Array) =>
              wire(async () => (await inner.put(key, bytes), key)),
            download: (url: string) =>
              wire(async () => (await inner.get(url)) ?? new Uint8Array()),
            exists: (url: string) => wire(() => inner.exists(url)),
            delete: async () => true,
          } as never,
          {
            ...DEFAULT_STORAGE_ACCESS_POLICY,
            // The window may grow to two requests, no further.
            maxBytesInFlight: 2 * partBytes,
            partBytes,
          },
        ),
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    // Six streams each start an attachment, a part and a head together: 18
    // uploads want to leave. The gate lets two out at most.
    expect(peak).toBeGreaterThanOrEqual(1);
    expect(peak).toBeLessThanOrEqual(2);
  });

  it("writes the stream's registry row only after every part and the head are stored, with many parts on the wire", async () => {
    const partBytes = 2048;
    let onWire = 0;
    let peak = 0;
    let started = 0;
    let stored = 0;
    let storedAtPost: number | undefined;
    let startedAtPost: number | undefined;
    const wire = async <T>(work: () => Promise<T>): Promise<T> => {
      onWire += 1;
      peak = Math.max(peak, onWire);
      try {
        await sleep(40);
        return await work();
      } finally {
        onWire -= 1;
      }
    };
    const { deps, names } = await world({
      streams: 1,
      recordsPerStream: 24,
      padBytes: 1500,
      partTargetBytes: partBytes,
      onPost: (scope) => {
        if (scope === CONTROL) return;
        storedAtPost = stored;
        startedAtPost = started;
      },
      store: (inner) =>
        createStorageStreamSyncBlobs(
          {
            urlForKey: (key: string) => key,
            upload: (key: string, bytes: Uint8Array) =>
              wire(async () => {
                started += 1;
                await inner.put(key, bytes);
                stored += 1;
                return key;
              }),
            download: (url: string) =>
              wire(async () => (await inner.get(url)) ?? new Uint8Array()),
            exists: (url: string) => wire(() => inner.exists(url)),
            delete: async () => true,
          } as never,
          {
            ...DEFAULT_STORAGE_ACCESS_POLICY,
            // The window may grow to eight parts.
            maxBytesInFlight: 8 * partBytes,
            partBytes,
          },
        ),
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    expect(names).toHaveLength(1);
    // About one part per record, and the head.
    expect(stored).toBeGreaterThan(20);
    // Two parts and the head were the most a stream could have out at once.
    expect(peak).toBeGreaterThan(3);
    expect(peak).toBeLessThanOrEqual(8);
    // At the stream's registry write, every upload that ever started was stored.
    expect(startedAtPost).toBe(stored);
    expect(storedAtPost).toBe(stored);
  });
});

// The transfer starts while the snapshot is still copying rows into the spool.
// What stays true: the registry row waits for every file, memory stays inside
// the store's budget, and the version holds exactly the rows of one slot turn.
describe("a stream's transfer starts while its snapshot is still copying rows", () => {
  // About one part per record, so the snapshot copies many prefixes.
  const MANY_PARTS = {
    streams: 1,
    recordsPerStream: 24,
    padBytes: 1500,
    partTargetBytes: 2048,
  } as const;

  /** `db` that calls `before(n)` ahead of the n-th prefix the snapshot copies. */
  const watchFreeze = (
    db: SqlDriver,
    before: (nth: number) => Promise<void> | void,
  ): SqlDriver => {
    let nth = 0;
    return {
      info: db.info,
      reads: db.reads,
      query: db.query.bind(db),
      close: () => db.close(),
      async batch(statements) {
        if (statements[0]?.sql.includes("INSERT INTO publish_spool")) {
          nth += 1;
          await before(nth);
        }
        return db.batch(statements);
      },
    };
  };

  /** A put hold that parks every upload until `releaseAll`. */
  const parking = () => {
    const parked: (() => void)[] = [];
    const starts: string[] = [];
    let first!: () => void;
    const firstPut = new Promise<void>((resolve) => (first = resolve));
    return {
      starts,
      parked,
      firstPut,
      hold: (key: string) =>
        new Promise<void>((release) => {
          starts.push(key);
          parked.push(release);
          first();
        }),
      releaseAll: () => {
        for (const release of parked.splice(0)) release();
      },
      /** Let every upload through, now and later. */
      open: () => {
        const timer = setInterval(() => {
          for (const release of parked.splice(0)) release();
        }, 2);
        return () => clearInterval(timer);
      },
    };
  };

  it("starts the first upload before the snapshot has copied every prefix", async () => {
    const puts = parking();
    const w = await world({ ...MANY_PARTS, holdPut: puts.hold });
    let copied = 0;
    let stalled = false;
    const deps = {
      ...w.deps,
      db: watchFreeze(w.db, async (nth) => {
        copied = nth;
        // The third prefix is copied only once an upload is out: a snapshot
        // that finishes first never lets that happen.
        if (nth === 3) {
          const outcome = await Promise.race([
            puts.firstPut.then(() => "put"),
            sleep(1500).then(() => "stalled"),
          ]);
          stalled = outcome === "stalled";
        }
      }),
    };
    const stop = puts.open();
    try {
      const results = await publishConnection(deps, CONNECTION_ID);
      expect(results.map((r) => r.outcome)).toEqual(["published"]);
    } finally {
      stop();
    }
    // The test is not vacuous: the snapshot copied more prefixes than it waited at.
    expect(copied).toBeGreaterThan(3);
    expect(stalled).toBe(false);
  });

  it("posts the registry row only after every part and the head are stored, though the snapshot ended first", async () => {
    const puts = parking();
    const posts: { scope: string; uploadsReleased: boolean }[] = [];
    let released = false;
    const w = await world({
      ...MANY_PARTS,
      holdPut: puts.hold,
      onPost: (scope) => posts.push({ scope, uploadsReleased: released }),
    });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(puts.starts.length).toBeGreaterThan(20));
    // The snapshot is long over and every part is encoded and out, parked.
    await sleep(150);
    expect(posts.filter((p) => p.scope !== CONTROL)).toEqual([]);
    released = true;
    const stop = puts.open();
    try {
      expect((await publishing).map((r) => r.outcome)).toEqual(["published"]);
    } finally {
      stop();
    }
    const stream = posts.filter((p) => p.scope !== CONTROL);
    expect(stream).toHaveLength(1);
    expect(stream[0]!.uploadsReleased).toBe(true);
  });

  it("posts nothing and stops copying when an upload fails while the snapshot is still copying", async () => {
    const puts = parking();
    let uploads = 0;
    const w = await world({
      ...MANY_PARTS,
      holdPut: (key) => {
        uploads += 1;
        return uploads === 1
          ? Promise.reject(new Error("storage said no"))
          : puts.hold(key);
      },
    });
    let copied = 0;
    const deps = {
      ...w.deps,
      db: watchFreeze(w.db, async (nth) => {
        copied = nth;
        // Give the failed upload time to end the transfer before the copy goes on.
        if (nth === 3) await sleep(200);
      }),
    };
    const stop = puts.open();
    try {
      await expect(publishConnection(deps, CONNECTION_ID)).rejects.toThrow(
        "storage said no",
      );
    } finally {
      stop();
    }
    // Nobody reads more prefixes, so the snapshot copies no more of them.
    expect(copied).toBeLessThanOrEqual(5);
    expect(
      w.calls.filter((c) => c.kind === "post" && c.scope !== CONTROL),
    ).toEqual([]);
    // And the spool is dropped.
    expect(await w.db.query("SELECT COUNT(*) AS n FROM publish_spool")).toEqual(
      [{ n: 0 }],
    );
  });

  it("ends the transfer and posts nothing when the snapshot fails after uploads started", async () => {
    const puts = parking();
    let settled = 0;
    const w = await world({
      ...MANY_PARTS,
      holdPut: (key) => puts.hold(key).finally(() => (settled += 1)),
    });
    let startedAtFailure = 0;
    const deps = {
      ...w.deps,
      db: watchFreeze(w.db, async (nth) => {
        if (nth === 3) {
          await Promise.race([puts.firstPut, sleep(1500)]);
          // The failure is injected with an upload out, or the test proves nothing.
          startedAtFailure = puts.starts.length;
          throw new Error("copy failed");
        }
      }),
    };
    const stop = puts.open();
    try {
      await expect(publishConnection(deps, CONNECTION_ID)).rejects.toThrow(
        "copy failed",
      );
      // Every upload that started has ended: nothing of the transfer runs on.
      await vi.waitFor(() => expect(settled).toBe(puts.starts.length));
    } finally {
      stop();
    }
    expect(startedAtFailure).toBeGreaterThan(0);
    expect(
      w.calls.filter((c) => c.kind === "post" && c.scope !== CONTROL),
    ).toEqual([]);
    expect(await w.db.query("SELECT COUNT(*) AS n FROM publish_spool")).toEqual(
      [{ n: 0 }],
    );
  });

  it("holds no more than the byte budget while the snapshot copies ahead of the uploads", async () => {
    const partTarget = 2048;
    // A part waiting on its PUT holds its ciphertext (part target plus the
    // seal's overhead). The part being built holds the plain bytes and room
    // for the ciphertext, and joins the waiting parts when sealed. This budget
    // fits three waiting parts and the builder: four PUTs start in all.
    const sealOverhead = 64;
    const budget = 3 * (partTarget + sealOverhead) + 2 * partTarget;
    const state = { held: 0, peak: 0 };
    const waiting: (() => void)[] = [];
    const governor: NonNullable<StreamSyncBlobs["governor"]> = {
      async reserve(bytes) {
        while (state.held + bytes > budget)
          await new Promise<void>((resolve) => waiting.push(resolve));
        state.held += bytes;
        state.peak = Math.max(state.peak, state.held);
        let kept = bytes;
        const wakeAll = () => {
          for (const wake of waiting.splice(0)) wake();
        };
        return Object.assign(
          () => {
            state.held -= kept;
            kept = 0;
            wakeAll();
          },
          {
            shrink(keep: number) {
              const next = Math.max(0, Math.min(kept, keep));
              state.held -= kept - next;
              kept = next;
              wakeAll();
            },
          },
        );
      },
      window: () => ({
        end: () => ({
          window: 1,
          requests: 0,
          throttles: 0,
          retryAfterWaitMs: 0,
          peakBytesInFlight: 0,
        }),
      }),
    };
    const puts = parking();
    const w = await world({
      ...MANY_PARTS,
      governor,
      holdPut: puts.hold,
    });
    let copied = 0;
    const deps = {
      ...w.deps,
      db: watchFreeze(w.db, (nth) => void (copied = nth)),
    };
    const publishing = publishConnection(deps, CONNECTION_ID);
    // Uploads are parked, so the encoder stops at the budget...
    await vi.waitFor(() => expect(puts.starts.length).toBe(4));
    await sleep(150);
    expect(puts.starts.length).toBe(4);
    // ...while the snapshot, which holds rows on disk and not in memory, has
    // copied every prefix.
    expect(copied).toBeGreaterThan(20);
    const stop = puts.open();
    try {
      expect((await publishing).map((r) => r.outcome)).toEqual(["published"]);
    } finally {
      stop();
    }
    expect(state.peak).toBeLessThanOrEqual(budget);
    expect(state.peak).toBeGreaterThan(0);
    expect(state.held).toBe(0);
  });

  it("leaves a run that ends during the copy out of this version", async () => {
    const puts = parking();
    const w = await world({ ...MANY_PARTS, holdPut: puts.hold });
    // The run collects before the publish and ends during it. Collecting takes
    // no slot; the end does, so it waits for the snapshot's turn.
    await w.sync.intake.begin("run-late", {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: false,
      owner: { address: OWNER, leaseId: null },
    });
    await w.sync.intake.batch("run-late", {
      batch: 0,
      records: [{ stream: "s0", data: { id: "late-marker-row" } }],
    });
    let lateEnded: Promise<unknown> | undefined;
    let uploadsOutAtEnd = 0;
    const deps = {
      ...w.deps,
      db: watchFreeze(w.db, async (nth) => {
        if (nth !== 3) return;
        // An upload is out and the snapshot is still copying: the run ends now.
        await Promise.race([puts.firstPut, sleep(1500)]);
        uploadsOutAtEnd = puts.starts.length;
        lateEnded = w.sync.intake.end(
          "run-late",
          endRequest({ lastBatch: 0, live: ["s0"] }),
        );
        await sleep(30);
      }),
    };
    const stop = puts.open();
    try {
      const first = await publishConnection(deps, CONNECTION_ID);
      expect(first.map((r) => r.outcome)).toEqual(["published"]);
      await lateEnded;
      const stored = async () => {
        const texts: string[] = [];
        for (const { key } of w.guards.map((g) => ({ key: g.key }))) {
          const bytes = await w.innerBlobs.get(key);
          if (bytes) texts.push(new TextDecoder("latin1").decode(bytes));
        }
        return texts.join("\n");
      };
      // The run ended while the snapshot was still copying and an upload was out.
      expect(uploadsOutAtEnd).toBeGreaterThan(0);
      const afterFirst = await stored();
      // The check can see rows: an original record is in what was uploaded.
      expect(afterFirst).toContain("s0-1");
      expect(afterFirst).not.toContain("late-marker-row");
      // The late run is still pending, and the next publish carries it.
      const second = await publishConnection(deps, CONNECTION_ID);
      expect(second.map((r) => r.outcome)).toEqual(["published"]);
      expect(await stored()).toContain("late-marker-row");
    } finally {
      stop();
    }
  });

  describe("on a database file, with the production driver's separate read connection", () => {
    // 200 records of about 1.5 KB at a 32 KiB part target: about ten prefixes
    // of some twenty rows each, so a copy batch is more than one row.
    const FILE_PARTS = {
      streams: 1,
      recordsPerStream: 200,
      padBytes: 1500,
      partTargetBytes: 32 * 1024,
    } as const;

    const fileWorld = async (
      hold: (key: string) => Promise<void>,
    ): Promise<Awaited<ReturnType<typeof world>>> => {
      const dir = mkdtempSync(join(tmpdir(), "publish-wal-"));
      scratchDirs.push(dir);
      return world({
        ...FILE_PARTS,
        dbPath: join(dir, "local.sqlite"),
        holdPut: hold,
      });
    };

    /** A pk_hash range a copy batch covers (or `all` for the one-prefix stream). */
    type Range = { readonly lo: string; readonly hi: string };
    const rangeOfCopy = (params: readonly unknown[] | undefined): Range =>
      params && params.length > 3
        ? { lo: String(params[3]), hi: String(params[4]) }
        : { lo: "", hi: "g" };

    it("reads only prefixes whose copy has committed, though the snapshot is copying the next ones, and leaves a write made during the publish out", async () => {
      const puts = parking();
      const w = await fileWorld(puts.hold);
      const writer = w.db;
      const reader = writer.reads;
      // The production driver offers a read connection on a file database.
      expect(reader).toBeDefined();

      const committed: Range[] = [];
      const seen = {
        readerSpool: 0,
        writerSpool: 0,
        unannounced: [] as string[],
        overlapped: false,
        copyBatches: 0,
        probes: [] as number[],
        probeTotal: -1,
        probeEnough: 0,
      };
      let firstRead!: () => void;
      const readServed = new Promise<void>((resolve) => (firstRead = resolve));
      const announced = (key: string) =>
        committed.some((r) => key >= r.lo && key < r.hi);

      const spiedReads = {
        async query(text: string, params?: readonly never[]) {
          if (text.includes("FROM publish_spool")) {
            seen.readerSpool += 1;
            // Every spool read's first key bound lies inside a prefix whose copy
            // batch has already returned: it is one the feed announced.
            const key = String(params?.[1] ?? "");
            if (!announced(key))
              seen.unannounced.push(`${text.slice(0, 40)} ${key}`);
            firstRead();
          }
          return reader!.query(text, params);
        },
      } as NonNullable<SqlDriver["reads"]>;

      let late: Promise<unknown> | undefined;
      const db: SqlDriver = {
        info: writer.info,
        reads: spiedReads,
        close: () => writer.close(),
        async query(text, params) {
          if (text.includes("FROM publish_spool")) seen.writerSpool += 1;
          return writer.query(text, params);
        },
        async batch(statements) {
          const first = statements[0];
          if (!first?.sql.includes("INSERT INTO publish_spool"))
            return writer.batch(statements);
          seen.copyBatches += 1;
          const range = rangeOfCopy(first.params);
          if (seen.copyBatches === 4) {
            // Three prefixes are copied. Copy the fourth only once the transfer
            // has read from the spool through the read connection and an upload
            // is out: this batch then runs beside a transfer that is working.
            const outcome = await Promise.race([
              Promise.all([readServed, puts.firstPut]).then(() => "both"),
              sleep(1500).then(() => "stalled"),
            ]);
            seen.overlapped = outcome === "both";
            // A write during the publish: a run that collects and ends now. It
            // queues behind the snapshot's slot turn.
            late = (async () => {
              await w.sync.intake.begin("run-late", {
                connector: CONNECTOR,
                artifactDigest: CONNECTOR,
                wantFull: false,
                owner: { address: OWNER, leaseId: null },
              });
              await w.sync.intake.batch("run-late", {
                batch: 0,
                records: [{ stream: "s0", data: { id: "late-marker-row" } }],
              });
              await w.sync.intake.end(
                "run-late",
                endRequest({ lastBatch: 0, live: ["s0"] }),
              );
            })();
            // Count this prefix's spool rows over the read connection while its
            // batch runs: the reader sees none of them or all of them.
            const attempt = String(first.params![0]);
            const bounds = range.lo === "" ? [] : [range.lo, range.hi];
            const count = () =>
              reader!.query<{ n: number }>(
                `SELECT COUNT(*) AS n FROM publish_spool WHERE attempt = ?${bounds.length ? " AND pk_hash >= ? AND pk_hash < ?" : ""}`,
                [attempt, ...bounds],
              );
            let done = false;
            const batch = writer.batch(statements).finally(() => (done = true));
            while (!done) seen.probes.push((await count())[0]!.n);
            const result = await batch;
            seen.probeTotal = result.changes[0]!;
            seen.probes.push((await count())[0]!.n);
            committed.push(range);
            return result;
          }
          // Slow each copy down, so a prefix announced before its batch has
          // returned would be read while its rows are not yet there.
          await sleep(10);
          const result = await writer.batch(statements);
          committed.push(range);
          return result;
        },
      };
      const deps = { ...w.deps, db };

      const stop = puts.open();
      try {
        await verify();
      } finally {
        stop();
      }

      async function verify() {
        const first = await publishConnection(deps, CONNECTION_ID);
        await late;
        expect(first.map((r) => r.outcome)).toEqual(["published"]);

        // It read no prefix before that prefix's copy had committed.
        expect(seen.unannounced).toEqual([]);
        // The transfer's spool reads used the read connection, never the writer's.
        expect(seen.writerSpool).toBe(0);
        expect(seen.readerSpool).toBeGreaterThan(0);
        // The snapshot was still copying while the transfer read and uploaded.
        expect(seen.overlapped).toBe(true);
        expect(seen.copyBatches).toBeGreaterThan(4);
        // A reader checking the prefix in flight saw none of its rows or all of them.
        expect(seen.probeTotal).toBeGreaterThan(1);
        expect(seen.probes.length).toBeGreaterThan(0);
        for (const n of seen.probes) expect([0, seen.probeTotal]).toContain(n);
        expect(seen.probes.at(-1)).toBe(seen.probeTotal);

        // The published version is exactly the 200 rows of the snapshot.
        const stored = async () => {
          const texts: string[] = [];
          for (const { key } of w.guards) {
            const bytes = await w.innerBlobs.get(key);
            if (bytes) texts.push(new TextDecoder("latin1").decode(bytes));
          }
          return texts.join("\n");
        };
        const afterFirst = await stored();
        const ids = afterFirst.match(/s0-\d+/g) ?? [];
        expect(ids).toHaveLength(200);
        expect(new Set(ids)).toEqual(
          new Set(Array.from({ length: 200 }, (_, i) => `s0-${i + 1}`)),
        );
        expect(afterFirst).not.toContain("late-marker-row");
        // The write is not lost: the next publish carries it.
        const second = await publishConnection(deps, CONNECTION_ID);
        expect(second.map((r) => r.outcome)).toEqual(["published"]);
        expect(await stored()).toContain("late-marker-row");
        expect(
          await w.db.query("SELECT COUNT(*) AS n FROM publish_spool"),
        ).toEqual([{ n: 0 }]);
      }
    });
  });
});
