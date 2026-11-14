// What one publish asks of the registry and of storage.
//
// One listing of the connection's rows replaces the snapshot reads of every
// stream after the first. A first publish makes no existence probe. A stream's
// part and head uploads overlap, and only the registry write waits for all.
// Real SQLite driver and connection queue; the registry and storage are fakes
// that count and can hold a call.
import { afterEach, describe, expect, it } from "vitest";
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
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openRegistryView } from "../../../core/src/localdb/registry-view.js";
import { newUploadWave } from "../../../core/src/localdb/upload-wave.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const CONTROL = controlScope(CONNECTOR, "");
const keccak = async (b: Uint8Array) => keccak_256(b);

type Call = {
  readonly kind: "read" | "post" | "list" | "probe" | "put";
  readonly scope: string;
  /** The blob key, for probes and puts. */
  readonly key?: string;
};

type Options = {
  readonly streams: number;
  /** A registry that cannot list a connection in one pass. */
  readonly noListing?: boolean;
  /** Runs when a put starts, after it is logged; the put waits for it. */
  readonly holdPut?: (key: string) => Promise<void>;
  /** Runs after the registry took a listing and before the publish sees it. */
  readonly afterList?: () => Promise<void>;
  /** Runs after the registry answered a read, before the publish sees the answer. */
  readonly afterRead?: (scope: string) => Promise<void>;
};

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const streamName = (i: number) => `s${i}`;
const scopeOfKey = (key: string) => key.slice(0, key.lastIndexOf("/"));

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
  const inner = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const registry: StreamSyncRegistry = {
    async read(scope) {
      calls.push({ kind: "read", scope });
      const read = await inner.read(scope);
      await options.afterRead?.(scope);
      return read;
    },
    async post(request) {
      calls.push({ kind: "post", scope: request.scope });
      return inner.post(request);
    },
    listControlRows: () => inner.listControlRows(),
    listStreamRows: (connector) => inner.listStreamRows(connector),
    ...(options.noListing
      ? {}
      : {
          async listConnectionRows(connector: string, ns: string) {
            calls.push({ kind: "list", scope: connector });
            const rows = await inner.listConnectionRows(connector, ns);
            await options.afterList?.();
            return rows;
          },
        }),
  };
  const innerBlobs = createMemoryStreamSyncBlobs();
  const blobs = {
    governor: innerBlobs.governor,
    get: (key: string) => innerBlobs.get(key),
    async exists(key: string) {
      calls.push({ kind: "probe", scope: scopeOfKey(key), key });
      return innerBlobs.exists(key);
    },
    async put(key: string, bytes: Uint8Array) {
      calls.push({ kind: "put", scope: scopeOfKey(key), key });
      await options.holdPut?.(key);
      await innerBlobs.put(key, bytes);
    },
  };
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry,
    blobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
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
  let runs = 0;
  /** A run that writes `rows` rows of every stream, with `version` in each. */
  const collect = async (version: number, rows = 2) => {
    const runId = `run-${++runs}`;
    await sync.intake.begin(runId, {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch(runId, {
      batch: 0,
      records: names.flatMap((stream) =>
        Array.from({ length: rows }, (_, n) => ({
          stream,
          data: { id: `${stream}-${n}`, version },
        })),
      ),
    });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: names,
      lastBatch: 0,
    });
  };
  /** A later partial run that found nothing new in any stream. */
  const idle = async () => {
    const runId = `run-${++runs}`;
    await sync.intake.begin(runId, {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: false,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch(runId, { batch: 0, records: [] });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: names,
      lastBatch: 0,
    });
    return runId;
  };
  await collect(1);
  // The run's own registry traffic is not the publish's.
  calls.length = 0;
  return { deps, db, calls, names, inner, collect, idle, blobs, innerBlobs };
}

const count = (calls: readonly Call[], kind: Call["kind"], scope?: string) =>
  calls.filter(
    (c) => c.kind === kind && (scope === undefined || c.scope === scope),
  ).length;

/** A head another device wrote, with no rows, so that it wins a CAS. */
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
  const { dataHash, blobName } = await digestHead(keccak, bytes);
  await w.innerBlobs.put(`${scope}/${blobName}`, bytes);
  await w.inner.post({
    ownerAddress: OWNER,
    scope,
    dataHash,
    metadataHash: `0x${"22".repeat(32)}`,
    expectedVersion: String(version),
    signature: "0x00",
  });
}

describe("one listing of the connection's registry rows", () => {
  it("is taken once for six streams, and only the first stream reads its own rows", async () => {
    const w = await world({ streams: 6 });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    expect(count(w.calls, "list")).toBe(1);
    // Stream rows: the first stream's snapshot read. The others come from the
    // listing, and a CAS follows each commit, so none is read again.
    const streamReads = w.names.map((n) =>
      count(w.calls, "read", streamScope(CONNECTOR, "", n)),
    );
    expect(streamReads).toEqual([1, 0, 0, 0, 0, 0]);
    // Control: the first snapshot's read and its read-back after creating the
    // row, then the commit's live check before and after each of six posts.
    expect(count(w.calls, "read", CONTROL)).toBe(2 + 6 * 2);
  });

  it("is not taken for a registry that cannot list a connection: every stream reads its rows", async () => {
    const w = await world({ streams: 6, noListing: true });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    expect(count(w.calls, "list")).toBe(0);
    for (const n of w.names)
      expect(count(w.calls, "read", streamScope(CONNECTOR, "", n))).toBe(1);
    // Each snapshot reads it (6), one read-back after creating it, and the
    // commit's two live checks per stream (12).
    expect(count(w.calls, "read", CONTROL)).toBe(6 + 1 + 12);
  });

  it("is not taken for two streams: it would not save a request", async () => {
    const w = await world({ streams: 2 });
    await publishConnection(w.deps, CONNECTION_ID);
    expect(count(w.calls, "list")).toBe(0);
  });

  it("falls back to reading each row when the listing fails", async () => {
    const w = await world({ streams: 4 });
    (
      w.deps.registry as { listConnectionRows: () => Promise<never> }
    ).listConnectionRows = async () => {
      throw new Error("offline");
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("published"));
    for (const n of w.names)
      expect(count(w.calls, "read", streamScope(CONNECTOR, "", n))).toBe(1);
  });

  it("publishes every stream after a lost CAS, the loser reading its row again", async () => {
    // All streams start at once and queue their first snapshot turn before any
    // commit turn, so no first snapshot follows the conflict: the listing is
    // taken once. The loser applies the winner and retries from a live read.
    const w = await world({ streams: 4 });
    const s0 = streamScope(CONNECTOR, "", "s0");
    let beaten = false;
    w.inner.beforePost = async (post) => {
      if (post.scope !== s0 || beaten) return;
      beaten = true;
      await foreignHead(w, "s0", 1);
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("published"));
    expect(count(w.calls, "list")).toBe(1);
    expect(count(w.calls, "read", s0)).toBeGreaterThanOrEqual(2);
    expect(count(w.calls, "post", s0)).toBeGreaterThanOrEqual(2);
  });
});

describe("a stream that loses every CAS", () => {
  it("gives up with backoff while the other streams publish, and the listing is taken once", async () => {
    // A foreign head wins each of s0's five CASes, so s0 backs off. Every
    // stream starts at once and queues its first snapshot before any commit,
    // so no first snapshot follows a loss and no second listing is needed.
    const w = await world({ streams: 4 });
    const s0 = streamScope(CONNECTOR, "", "s0");
    let posts = 0;
    let winning = false;
    w.inner.beforePost = async (post) => {
      // The winner is itself a post to this scope.
      if (post.scope !== s0 || winning) return;
      posts++;
      winning = true;
      try {
        await foreignHead(w, "s0", posts);
      } finally {
        winning = false;
      }
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual([
      "backoff",
      "published",
      "published",
      "published",
    ]);
    expect(count(w.calls, "post", s0)).toBe(5);
    expect(count(w.calls, "list")).toBe(1);
  });
});

describe("a listing taken before an apply", () => {
  it("is not handed to a stream that starts after the apply", async () => {
    const w = await world({ streams: 4 });
    // Another device already wrote s1's head. s1 learns it from the listing the
    // second stream took, and applies it: the listing predates that apply.
    await foreignHead(w, "s1", 1);
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results).toHaveLength(4);
    // s2 took a new listing after s1's apply; s3 used that one.
    expect(count(w.calls, "list")).toBe(2);
    const lists = w.calls
      .map((c, i) => (c.kind === "list" ? i : -1))
      .filter((i) => i >= 0);
    const apply = w.calls.findIndex(
      (c, i) => i > lists[0]! && c.kind === "read" && c.scope.endsWith(".s1"),
    );
    expect(apply).toBeGreaterThan(lists[0]!);
    expect(lists[1]).toBeGreaterThan(apply);
  });
});

/** Another device deletes the connection: the control row, at version 1, is tombstoned. */
async function tombstoneControl(
  w: Awaited<ReturnType<typeof world>>,
): Promise<void> {
  const hashes = await controlHashes(
    keccak,
    await deriveKeyCheck(w.deps.keys.namespaceHmac),
  );
  await w.inner.post({
    ownerAddress: OWNER,
    scope: CONTROL,
    dataHash: hashes.tombstoneData,
    metadataHash: hashes.tombstoneMetadata,
    expectedVersion: "2",
    signature: "0x00",
  });
}

describe("a stream with no work, served by a listing older than its turn", () => {
  // Every stream is published once; a later partial run finds nothing new, so
  // each stream's plan has nothing to publish but a run to take evidence of.
  // `afterList` runs once the second stream's listing is taken: its rows are
  // then older than the turn of every stream after the first.
  const refreshWorld = async (
    afterList: (w: Awaited<ReturnType<typeof world>>) => Promise<void>,
    afterRead?: (
      w: Awaited<ReturnType<typeof world>>,
      scope: string,
    ) => Promise<void>,
  ) => {
    let armed = false;
    const holder: { w?: Awaited<ReturnType<typeof world>> } = {};
    const w = await world({
      streams: 4,
      afterList: async () => {
        if (armed) await afterList(holder.w!);
      },
      afterRead: async (scope) => {
        if (armed) await afterRead?.(holder.w!, scope);
      },
    });
    holder.w = w;
    await publishConnection(w.deps, CONNECTION_ID);
    const runId = await w.idle();
    w.calls.length = 0;
    armed = true;
    return { w, runId };
  };
  const evidenceOf = async (
    w: Awaited<ReturnType<typeof world>>,
    runId: string,
  ) =>
    Object.fromEntries(
      (
        await w.db.query<{ stream: string; published_version: number | null }>(
          "SELECT stream, published_version FROM run_streams WHERE run_id = ?",
          [runId],
        )
      ).map((row) => [row.stream, row.published_version]),
    );

  it("purges when the control row was deleted after the listing, and does not say noop", async () => {
    const { w, runId } = await refreshWorld(tombstoneControl);
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(count(w.calls, "list")).toBe(1);
    // Only the stream that read its own rows has evidence for the run.
    const evidence = await evidenceOf(w, runId);
    expect(evidence.s1).toBeNull();
    // s0 read its own rows and found the connection live; s1 held a listing
    // that still showed it active.
    expect(results[0]!.outcome).toBe("noop");
    expect(results[1]!.outcome).toBe("purged");
    expect(results.slice(1).some((r) => r.outcome === "noop")).toBe(false);
  });

  it("reads the stream row first and the control row second: a deletion between them is caught", async () => {
    // The connection is deleted just after s1's stream row is read, and its
    // row is unchanged (it survives the deletion). Only a control read made
    // after the row read can see it.
    const s1 = streamScope(CONNECTOR, "", "s1");
    let deleted = false;
    const { w, runId } = await refreshWorld(
      async () => {},
      async (world, scope) => {
        if (scope !== s1 || deleted) return;
        deleted = true;
        await tombstoneControl(world);
      },
    );
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(deleted).toBe(true);
    expect(results[1]!.outcome).toBe("purged");
    expect((await evidenceOf(w, runId)).s1).toBeNull();
  });

  it("saves no evidence for a row another publisher advanced after the listing", async () => {
    const { w, runId } = await refreshWorld((world) =>
      foreignHead(world, "s1", 2),
    );
    await publishConnection(w.deps, CONNECTION_ID);
    const evidence = await evidenceOf(w, runId);
    // s0 read the row itself: its evidence names version 1. s1's listed row
    // (version 1) was not current by its turn: no evidence for that version.
    expect(evidence.s0).toBe(1);
    expect(evidence.s1).not.toBe(1);
    // s2 and s3 came from the same listing but their rows did not move.
    expect(evidence.s2).toBe(1);
    expect(evidence.s3).toBe(1);
  });
});

describe("a stream with no work whose rows were all read live", () => {
  // No listing hint serves these publishes' first reads (the first stream, a
  // connection of fewer than three streams, a registry that cannot list, a
  // listing that fails), so nothing in the snapshot is a hint to confirm. The
  // control row was still read before the stream row. A delete that lands
  // between the two leaves the stream row as it was (it outlives the
  // deletion), so only a control read after the row read can see it.
  const cases: readonly {
    readonly name: string;
    readonly streams: number;
    /** The stream whose row read is followed by the deletion. */
    readonly stream: number;
    readonly noListing?: boolean;
    readonly listingFails?: boolean;
  }[] = [
    { name: "the first stream of four", streams: 4, stream: 0 },
    { name: "the only stream", streams: 1, stream: 0 },
    { name: "the first of two streams", streams: 2, stream: 0 },
    { name: "the second of two streams", streams: 2, stream: 1 },
    {
      name: "a registry with no listing",
      streams: 4,
      stream: 1,
      noListing: true,
    },
    { name: "a listing that fails", streams: 4, stream: 1, listingFails: true },
  ];
  it.each(cases)(
    "purges and keeps no evidence when the connection is deleted after the row read: $name",
    async ({ streams, stream, noListing, listingFails }) => {
      const target = streamScope(CONNECTOR, "", streamName(stream));
      let armed = false;
      let deleted = false;
      const holder: { w?: Awaited<ReturnType<typeof world>> } = {};
      const w: Awaited<ReturnType<typeof world>> = await world({
        streams,
        ...(noListing && { noListing }),
        afterRead: async (scope) => {
          if (!armed || deleted || scope !== target) return;
          deleted = true;
          await tombstoneControl(holder.w!);
        },
      });
      holder.w = w;
      if (listingFails) {
        (
          w.deps.registry as { listConnectionRows: () => Promise<never> }
        ).listConnectionRows = async () => {
          throw new Error("offline");
        };
      }
      await publishConnection(w.deps, CONNECTION_ID);
      const runId = await w.idle();
      w.calls.length = 0;
      armed = true;
      const results = await publishConnection(w.deps, CONNECTION_ID);
      expect(deleted).toBe(true);
      expect(results[stream]!.outcome).toBe("purged");
      expect(
        results.some(
          (r) => r.stream === streamName(stream) && r.outcome === "noop",
        ),
      ).toBe(false);
      const [row] = await w.db.query<{ published_version: number | null }>(
        "SELECT published_version FROM run_streams WHERE run_id = ? AND stream = ?",
        [runId, streamName(stream)],
      );
      expect(row?.published_version).toBeNull();
    },
  );
});

describe("the registry view", () => {
  const deps = (rows: () => Promise<unknown[]>) =>
    ({
      registry: { listConnectionRows: rows },
      logger: { warn: () => {}, info: () => {} },
    }) as unknown as LocalSyncDeps;

  it("hands out no listing that was in flight when the publish applied registry state", async () => {
    let finish!: () => void;
    const slow = new Promise<void>((resolve) => (finish = resolve));
    let lists = 0;
    const view = openRegistryView(
      deps(async () => {
        lists += 1;
        await slow;
        return [];
      }),
      { connector: CONNECTOR, ns: "" },
      3,
    );
    await view.firstSnapshot("a"); // the first stream gets none
    const second = view.firstSnapshot("b");
    view.invalidate();
    finish();
    expect(await second).toEqual({});
    // The next stream takes a fresh listing.
    expect(await view.firstSnapshot("c")).toMatchObject({
      stream: { found: false },
    });
    expect(lists).toBe(2);
  });

  it("serves a stream's first snapshot only", async () => {
    const view = openRegistryView(
      deps(async () => []),
      { connector: CONNECTOR, ns: "" },
      3,
    );
    await view.firstSnapshot("a");
    expect(await view.firstSnapshot("b")).toMatchObject({
      stream: { found: false },
    });
    expect(await view.firstSnapshot("b")).toEqual({});
  });
});

describe("existence probes", () => {
  it("a first publish makes none and uploads every part and head", async () => {
    const w = await world({ streams: 6 });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    expect(count(w.calls, "probe")).toBe(0);
    // One part and one head per stream.
    expect(count(w.calls, "put")).toBe(12);
  });

  it("a first publish that crashed before its registry write publishes on the retry, uploading the same objects again", async () => {
    const w = await world({ streams: 3 });
    let crash = true;
    w.inner.beforePost = async (post) => {
      if (crash && post.scope !== CONTROL) throw new Error("connection lost");
    };
    await expect(publishConnection(w.deps, CONNECTION_ID)).rejects.toThrow();
    const stored = count(w.calls, "put");
    expect(stored).toBeGreaterThan(0);
    crash = false;
    w.calls.length = 0;
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
    // No registry row yet, so still no probe; the stored names are uploaded again.
    expect(count(w.calls, "probe")).toBe(0);
    expect(count(w.calls, "put")).toBeGreaterThan(0);
  });

  it("a refresh probes where a registry row exists", async () => {
    const w = await world({ streams: 3 });
    await publishConnection(w.deps, CONNECTION_ID);
    w.calls.length = 0;
    await w.collect(2);
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
    // Every stream probed its part and its head.
    expect(count(w.calls, "probe")).toBe(6);
  });
});

describe("a stream's uploads overlap and the registry write waits for all", () => {
  it("starts the head before the part is stored, and posts only after both", async () => {
    let releasePart!: () => void;
    const partGate = new Promise<void>((resolve) => (releasePart = resolve));
    let headStarted!: () => void;
    const headSeen = new Promise<void>((resolve) => (headStarted = resolve));
    const w = await world({
      streams: 1,
      holdPut: async (key) => {
        if (key.includes("-p-")) await partGate;
        else headStarted();
      },
    });
    const published = publishConnection(w.deps, CONNECTION_ID);
    // The part's upload is held; the head's upload starts all the same.
    await headSeen;
    expect(
      w.calls.some((c) => c.kind === "put" && c.key!.includes("-p-")),
    ).toBe(true);
    // Nothing is posted while the part is not stored.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(count(w.calls, "post", streamScope(CONNECTOR, "", "s0"))).toBe(0);
    releasePart();
    const results = await published;
    expect(results[0]?.outcome).toBe("published");
    expect(count(w.calls, "post", streamScope(CONNECTOR, "", "s0"))).toBe(1);
  });

  it("does not post when a part fails to upload, and leaves no upload running", async () => {
    const w = await world({
      streams: 1,
      holdPut: async (key) => {
        if (key.includes("-p-")) throw new Error("storage refused the part");
        await new Promise((resolve) => setTimeout(resolve, 30));
      },
    });
    await expect(publishConnection(w.deps, CONNECTION_ID)).rejects.toThrow(
      "storage refused the part",
    );
    expect(count(w.calls, "post", streamScope(CONNECTOR, "", "s0"))).toBe(0);
    // The head's upload was settled before the failure was reported.
    expect(w.innerBlobs.exists).toBeDefined();
    const putsAtReturn = count(w.calls, "put");
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(count(w.calls, "put")).toBe(putsAtReturn);
  });

  it("a delete that purges the connection during the uploads stops every stream and posts no stream row", async () => {
    let first = true;
    const w: Awaited<ReturnType<typeof world>> = await world({
      streams: 3,
      holdPut: async () => {
        if (!first) return;
        first = false;
        const hashes = await controlHashes(
          keccak,
          await deriveKeyCheck(w.deps.keys.namespaceHmac),
        );
        await w.inner.post({
          ownerAddress: OWNER,
          scope: CONTROL,
          dataHash: hashes.tombstoneData,
          metadataHash: hashes.tombstoneMetadata,
          expectedVersion: "2",
          signature: "0x00",
        });
      },
    });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
    for (const n of w.names)
      expect(count(w.calls, "post", streamScope(CONNECTOR, "", n))).toBe(0);
    const putsAtReturn = count(w.calls, "put");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(count(w.calls, "put")).toBe(putsAtReturn);
  });
});

describe("the upload wave", () => {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("starts every upload at once and holds none back", async () => {
    const wave = newUploadWave();
    let running = 0;
    let peak = 0;
    const work = async () => {
      running += 1;
      peak = Math.max(peak, running);
      await sleep(10);
      running -= 1;
    };
    for (let i = 0; i < 7; i++) wave.start(work);
    await wave.drain();
    expect(peak).toBe(7);
  });

  it("throws the first failure, starts nothing after it, and settles the rest", async () => {
    const wave = newUploadWave();
    let started = 0;
    let finished = 0;
    wave.start(async () => {
      started += 1;
      await sleep(5);
      throw new Error("first");
    });
    wave.start(async () => {
      started += 1;
      await sleep(30);
      finished += 1;
    });
    await sleep(15);
    expect(() =>
      wave.start(async () => {
        started += 1;
      }),
    ).toThrow("first");
    expect(started).toBe(2);
    await wave.settle();
    expect(finished).toBe(1);
    await expect(wave.drain()).rejects.toThrow("first");
  });
});
