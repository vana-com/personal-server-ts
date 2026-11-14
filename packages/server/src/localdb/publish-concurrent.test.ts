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
      options.onPost?.(request.scope);
      await sleep(options.registryMs ?? 0);
      return innerRegistry.post(request);
    },
    listControlRows: () => innerRegistry.listControlRows(),
    listStreamRows: (connector) => innerRegistry.listStreamRows(connector),
    listConnectionRows: (connector, ns) =>
      innerRegistry.listConnectionRows(connector, ns),
  };
  const innerBlobs = createMemoryStreamSyncBlobs();
  /** Keys storage answers "absent" for, as if removed from outside. */
  const hidden = new Set<string>();
  const guards: { key: string; guard: (() => void) | undefined }[] = [];
  const timedBlobs: StreamSyncBlobs = {
    governor: options.governor,
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
  await sync.intake.end("run-1", {
    outcome: "succeeded",
    coveredStreams: names,
    lastBatch: 0,
  });
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
  const state = { held: 0, peak: 0, reserves: [] as string[] };
  const governor: NonNullable<StreamSyncBlobs["governor"]> = {
    async reserve(bytes, objectBytes) {
      state.reserves.push(`${bytes}/${objectBytes ?? "-"}`);
      await reserveFirst?.(bytes, objectBytes);
      state.held += bytes;
      state.peak = Math.max(state.peak, state.held);
      let released = false;
      return () => {
        if (released) return;
        released = true;
        state.held -= bytes;
      };
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
    const heldAtPut: Array<{ head: boolean; held: number }> = [];
    const { deps } = await world({
      streams: 1,
      governor,
      holdPut: async (key) => {
        heldAtPut.push({ head: /\/h-/.test(key), held: state.held });
      },
    });
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published"]);
    const part = heldAtPut.find((p) => !p.head);
    const head = heldAtPut.find((p) => p.head);
    // A part is held twice: plain encoded bytes and ciphertext.
    expect(part?.held).toBe(2 * 4 * 1024 * 1024);
    expect(head?.held).toBeGreaterThanOrEqual(4 * 1024 * 1024);
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
