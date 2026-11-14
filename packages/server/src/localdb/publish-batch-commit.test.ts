// The streams of one connection commit in one registry request that carries
// the connection-alive condition. The real gateway adapter, the real publish
// driver, the real SQLite driver and the real connection queue run against a
// fake gateway that implements the batch contract (fake-gateway.ts).
import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  streamScope,
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
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway, type FakeGatewayOptions } from "./fake-gateway.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const CONTROL = controlScope(CONNECTOR, "");
const sName = (i: number) => `s${i}`;
const scopeOf = (stream: string) => streamScope(CONNECTOR, "", stream);

type Options = {
  readonly streams: number;
  /** A part upload of a matching key waits for the returned promise. */
  readonly holdPut?: (key: string) => Promise<void> | undefined;
  /** A blob upload of a matching key fails. */
  readonly failPut?: (key: string) => boolean;
  /** Runs when the transfer probes whether a blob exists. */
  readonly onExists?: (key: string) => Promise<void> | void;
  readonly gateway?: Partial<FakeGatewayOptions>;
};

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function world(options: Options) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  const names = Array.from({ length: options.streams }, (_, i) => sName(i));
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    isTombstone: (v) =>
      v.dataHash === hashes.tombstoneData &&
      v.metadataHash === hashes.tombstoneMetadata,
    ...options.gateway,
  });
  const innerBlobs = createMemoryStreamSyncBlobs();
  const putsDone: string[] = [];
  const blobs: StreamSyncBlobs = {
    governor: innerBlobs.governor,
    get: (key) => innerBlobs.get(key),
    async exists(key) {
      await options.onExists?.(key);
      return innerBlobs.exists(key);
    },
    async put(key, bytes) {
      if (options.failPut?.(key)) throw new Error(`upload failed: ${key}`);
      await options.holdPut?.(key);
      await innerBlobs.put(key, bytes);
      putsDone.push(key);
    },
  };
  const purges: string[] = [];
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry: createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: OWNER,
      fetch: gateway.fetch,
    }),
    blobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: {
      info: (_o, message) => {
        if (message === "purge connection") purges.push(message);
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
  /** One run that writes `records` (stream, id) and ends covering `covered`. */
  const run = async (
    runId: string,
    records: readonly { stream: string; id: string }[],
    covered: readonly string[] = names,
  ) => {
    await sync.intake.begin(runId, {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      owner: { address: OWNER, leaseId: null },
    });
    await sync.intake.batch(runId, {
      batch: 0,
      records: records.map(({ stream, id }) => ({ stream, data: { id } })),
    });
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: covered,
      lastBatch: 0,
    });
  };
  await run(
    "run-1",
    names.flatMap((stream) => [
      { stream, id: `${stream}-1` },
      { stream, id: `${stream}-2` },
    ]),
  );
  const tombstoneControl = () =>
    gateway.write(CONTROL, {
      dataHash: hashes.tombstoneData,
      metadataHash: hashes.tombstoneMetadata,
    });
  /** Another writer reconnects: the control row is active at a higher version. */
  const reconnectControl = () =>
    gateway.write(CONTROL, {
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
    });
  const outcomes = (results: readonly { stream: string; outcome: string }[]) =>
    results.map((r) => [r.stream, r.outcome]);
  /** A later partial run that found nothing new in any stream. */
  const idleRun = async (runId: string) => {
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
  };
  return {
    idleRun,
    deps,
    db,
    gateway,
    names,
    purges,
    putsDone: () => putsDone,
    run,
    tombstoneControl,
    reconnectControl,
    outcomes,
  };
}

/** Streams whose rows the gateway holds, besides the control row. */
const streamRows = (gateway: ReturnType<typeof createFakeGateway>) =>
  [...gateway.versions.keys()].filter((scope) => scope !== CONTROL);

const controlReads = (gateway: ReturnType<typeof createFakeGateway>) =>
  gateway.calls.filter((c) => c.kind === "read" && c.scope === CONTROL).length;

const holdParts = () => {
  const parked: { key: string; release: () => void }[] = [];
  return {
    parked,
    holdPut: (key: string) =>
      /-p-/.test(key)
        ? new Promise<void>((release) => parked.push({ key, release }))
        : undefined,
  };
};

describe("one request commits the streams of a connection", () => {
  it("six streams all publish, each row once", async () => {
    const w = await world({ streams: 6 });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    expect(streamRows(w.gateway)).toHaveLength(6);
    for (const stream of w.names) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
    }
    // No stream head went through the single-write route.
    expect(
      w.gateway.calls.filter((c) => c.kind === "post" && c.scope !== CONTROL),
    ).toEqual([]);
    const batches = w.gateway.batches();
    expect(
      batches.flatMap((b) => b.body.rows.map((r) => r.scope)).sort(),
    ).toEqual(w.names.map(scopeOf).sort());
    // Every request names the control row at its generation, not deleted.
    for (const batch of batches) {
      expect(batch.body.requires).toEqual([
        {
          scope: CONTROL,
          expectedVersion: "1",
          notDeleted: true,
          expectedDataHash: expect.stringMatching(/^0x[0-9a-f]{64}$/),
        },
      ]);
    }
  });

  it("streams that become ready while a request is in flight go together in exactly one next request", async () => {
    const hold = holdParts();
    const w = await world({ streams: 4, holdPut: hold.holdPut });
    let sent!: () => void;
    const firstSent = new Promise<void>((r) => (sent = r));
    let reply!: () => void;
    const firstHeld = new Promise<void>((r) => (reply = r));
    w.gateway.beforeBatch = async () => {
      w.gateway.beforeBatch = undefined;
      sent();
      await firstHeld;
    };
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(4));
    const [lead, ...others] = hold.parked;
    // One stream is ready: its request goes at once, alone, and stays in flight.
    lead!.release();
    await firstSent;
    expect(w.gateway.batches()).toHaveLength(1);
    // Three more become ready while it is in flight (every stream's head blob
    // is its last upload before its commit). None is sent yet.
    for (const part of others) part.release();
    await vi.waitFor(() =>
      expect(w.putsDone().filter((k) => !/-p-/.test(k))).toHaveLength(4),
    );
    await new Promise((r) => setTimeout(r, 25));
    expect(w.gateway.batches()).toHaveLength(1);
    reply();
    const results = await publishing;
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("published"));
    const batches = w.gateway.batches();
    expect(batches.map((b) => b.body.rows.length)).toEqual([1, 3]);
  });

  it("the client no longer reads the control row around the writes", async () => {
    const batch = await world({ streams: 6 });
    await publishConnection(batch.deps, CONNECTION_ID);
    const alone = await world({ streams: 6, gateway: { batchRoute: 404 } });
    await publishConnection(alone.deps, CONNECTION_ID);
    // Without the batch route each stream reads the control row before and
    // after its write. The snapshots' reads are the same in both.
    expect(controlReads(alone.gateway) - controlReads(batch.gateway)).toBe(12);
  });

  it("a refused row is retried in a later request; the other rows are written once", async () => {
    const w = await world({ streams: 4 });
    w.gateway.refuseOnce(scopeOf("s2"));
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("published"));
    for (const stream of w.names) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
    }
    const sentIn = (stream: string) =>
      w.gateway
        .batches()
        .filter((b) => b.body.rows.some((r) => r.scope === scopeOf(stream)));
    expect(sentIn("s2")).toHaveLength(2);
    for (const stream of ["s0", "s1", "s3"]) {
      expect(sentIn(stream)).toHaveLength(1);
    }
  });

  it("a stream that finishes its transfer late commits in a later request and nobody waits for it", async () => {
    let release!: () => void;
    const late = new Promise<void>((r) => (release = r));
    const w = await world({
      streams: 6,
      holdPut: (key) => (/\.s5\/.*-p-/.test(key) ? late : undefined),
    });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(streamRows(w.gateway)).toHaveLength(5));
    expect(w.gateway.rowsOf(scopeOf("s5"))).toBe(0);
    const before = w.gateway.batches().length;
    release();
    const results = await publishing;
    expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
    const batches = w.gateway.batches();
    expect(batches.length).toBeGreaterThan(before);
    expect(batches.at(-1)!.body.rows.map((r) => r.scope)).toEqual([
      scopeOf("s5"),
    ]);
    for (const earlier of batches.slice(0, -1)) {
      expect(earlier.body.rows.map((r) => r.scope)).not.toContain(
        scopeOf("s5"),
      );
    }
  });
});

describe("a failed condition writes nothing", () => {
  it("a control row deleted between the check and the write purges, and no stream is marked published", async () => {
    const hold = holdParts();
    const w = await world({ streams: 4, holdPut: hold.holdPut });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(4));
    // The delete lands after every read of the publish, as the batch arrives:
    // exactly the window a client-side read cannot close.
    w.gateway.beforeBatch = () => w.tombstoneControl();
    for (const part of hold.parked) part.release();
    const results = await publishing;
    expect(w.outcomes(results)).toEqual(
      w.names.map((name) => [name, "purged"]),
    );
    expect(streamRows(w.gateway)).toEqual([]);
    expect(w.purges).toHaveLength(1);
    expect(
      await w.db.query(
        "SELECT 1 FROM run_streams WHERE publication_state='published'",
      ),
    ).toEqual([]);
    expect(await w.db.query("SELECT head_version FROM stream_state")).toEqual(
      w.names.map(() => ({ head_version: 0 })),
    );
  });

  it("a reconnect (the control row at another version) defers and writes nothing", async () => {
    const hold = holdParts();
    const w = await world({ streams: 3, holdPut: hold.holdPut });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(3));
    w.gateway.beforeBatch = () => w.reconnectControl();
    for (const part of hold.parked) part.release();
    const results = await publishing;
    expect(w.outcomes(results)).toEqual(
      w.names.map((name) => [name, "deferred"]),
    );
    expect(streamRows(w.gateway)).toEqual([]);
    expect(w.purges).toEqual([]);
  });

  it.each(["batch", "single", "none"] as const)(
    "a gateway that names the failed condition as %s is read right; a missing detail is read from the control row",
    async (failureBody) => {
      for (const [change, expected] of [
        ["tombstone", "purged"],
        ["reconnect", "deferred"],
      ] as const) {
        const hold = holdParts();
        const w = await world({
          streams: 2,
          holdPut: hold.holdPut,
          gateway: { failureBody },
        });
        const publishing = publishConnection(w.deps, CONNECTION_ID);
        await vi.waitFor(() => expect(hold.parked).toHaveLength(2));
        w.gateway.beforeBatch = () => {
          w.gateway.beforeBatch = undefined;
          if (change === "tombstone") w.tombstoneControl();
          else w.reconnectControl();
        };
        for (const part of hold.parked) part.release();
        const results = await publishing;
        expect(results.map((r) => r.outcome)).toEqual([expected, expected]);
        expect(streamRows(w.gateway)).toEqual([]);
        // With a detail the client reads nothing after the request; without it
        // it reads the control row once to classify.
        const readsAfter = w.gateway.calls
          .slice(w.gateway.calls.findIndex((c) => c.kind === "batch") + 1)
          .filter((c) => c.kind === "read" && c.scope === CONTROL).length;
        expect(readsAfter).toBe(
          failureBody === "none" ? w.gateway.batches().length : 0,
        );
      }
    },
  );

  const addIntent = (db: SqlDriver) =>
    db.batch([
      {
        sql: "INSERT OR REPLACE INTO delete_intents(connector,delete_id,intent) VALUES (?,?,?)",
        params: [CONNECTOR, "d1", "{}"],
      },
    ]);

  it("a local delete intent that appears during the transfer stops the request", async () => {
    const hold = holdParts();
    const w = await world({ streams: 3, holdPut: hold.holdPut });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(3));
    // The basis changes, each stream re-snapshots, and then commits with the
    // intent in its basis. A re-snapshot may put its parts again: release
    // every put as it parks.
    await addIntent(w.db);
    let settled = false;
    const pump = (async () => {
      while (!settled) {
        for (const part of hold.parked.splice(0)) part.release();
        await new Promise((r) => setTimeout(r, 5));
      }
    })();
    const results = await publishing;
    settled = true;
    await pump;
    expect(results.every((r) => r.outcome === "deferred")).toBe(true);
    expect(w.gateway.batches()).toEqual([]);
    expect(streamRows(w.gateway)).toEqual([]);
  });

  it("a local delete intent that appears between the opening check and the snapshot is vetoed under the commit slot", async () => {
    const w = await world({ streams: 3 });
    // The snapshot's control read comes after the opening check; the intent
    // is in the basis the snapshot records, so the basis never changes again.
    let added = false;
    const deps: LocalSyncDeps = {
      ...w.deps,
      registry: {
        ...w.deps.registry,
        postBatch: (request) => w.deps.registry.postBatch!(request),
        async read(scope) {
          if (scope === CONTROL && !added) {
            added = true;
            await addIntent(w.db);
          }
          return w.deps.registry.read(scope);
        },
      },
    };
    const results = await publishConnection(deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "deferred")).toBe(true);
    expect(w.gateway.batches()).toEqual([]);
    expect(streamRows(w.gateway)).toEqual([]);
  });
});

describe("lost replies and old gateways", () => {
  it.each(["stale", "created"] as const)(
    "a lost reply is resent once, identically, and the rows count once (replay answered as %s)",
    async (replay) => {
      const w = await world({ streams: 3, gateway: { replay } });
      w.gateway.dropNextBatchReply = true;
      const results = await publishConnection(w.deps, CONNECTION_ID);
      expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("published"));
      const batches = w.gateway.batches();
      expect(batches.length).toBeGreaterThanOrEqual(2);
      expect(batches[1]!.raw).toBe(batches[0]!.raw);
      for (const stream of w.names) {
        expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
      }
      expect(
        (await w.db.query("SELECT head_version FROM stream_state")).every(
          (row) => row.head_version === 1,
        ),
      ).toBe(true);
    },
  );

  it("two lost replies in a row are an unknown outcome and fail the publish, as a lost single write does", async () => {
    const w = await world({ streams: 2 });
    let drops = 0;
    const original = w.gateway.fetch;
    const deps = {
      ...w.deps,
      registry: createGatewayStreamSyncRegistry({
        gatewayUrl: "https://gateway.test",
        ownerAddress: OWNER,
        fetch: (async (url: string, init?: RequestInit) => {
          if (String(url).endsWith("/v1/data/batch")) {
            drops++;
            throw new TypeError("fetch failed");
          }
          return original(url, init);
        }) as typeof fetch,
      }),
    };
    await expect(publishConnection(deps, CONNECTION_ID)).rejects.toThrow(
      /no reply/,
    );
    expect(drops).toBeGreaterThanOrEqual(2);
    expect(drops % 2).toBe(0);
    expect(
      await w.db.query(
        "SELECT 1 FROM run_streams WHERE publication_state='published'",
      ),
    ).toEqual([]);
  });

  it.each([404, 405] as const)(
    "a gateway that answers the batch route with %s falls back to one write per stream, and asks once",
    async (batchRoute) => {
      const w = await world({ streams: 6, gateway: { batchRoute } });
      const results = await publishConnection(w.deps, CONNECTION_ID);
      expect(results.map((r) => r.outcome)).toEqual(Array(6).fill("published"));
      expect(w.gateway.batches().length).toBeLessThanOrEqual(1);
      const posts = w.gateway.calls.filter(
        (c) => c.kind === "post" && c.scope !== CONTROL,
      );
      expect(posts).toHaveLength(6);
      for (const post of posts) {
        expect(post.kind === "post" && "requires" in post.body).toBe(false);
      }
      for (const stream of w.names) {
        expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
      }
    },
  );
});

describe("participants that do not commit", () => {
  it("a stream with nothing to publish, and a stream that fails, never hold the others", async () => {
    const w = await world({ streams: 6 });
    const first = await publishConnection(w.deps, CONNECTION_ID);
    expect(first.every((r) => r.outcome === "published")).toBe(true);
    // Only s0, s1, s2 and s3 change. s4 and s5 have nothing to publish.
    await w.run("run-2", [
      { stream: "s0", id: "s0-new" },
      { stream: "s1", id: "s1-new" },
      { stream: "s2", id: "s2-new" },
      { stream: "s3", id: "s3-new" },
    ]);
    const second = await publishConnection(w.deps, CONNECTION_ID);
    expect(
      second.map((r) => r.outcome).filter((o) => o === "published"),
    ).toHaveLength(4);
    for (const stream of ["s0", "s1", "s2", "s3"]) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(2);
    }
    for (const stream of ["s4", "s5"]) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
    }

    // A stream whose upload fails ends the publish with its error. The others
    // are released and nothing hangs.
    const failing = await world({
      streams: 6,
      failPut: (key) => /\.s3\/.*-p-/.test(key),
    });
    await expect(
      publishConnection(failing.deps, CONNECTION_ID),
    ).rejects.toThrow(/upload failed/);
    expect(failing.gateway.rowsOf(scopeOf("s3"))).toBe(0);
  });

  it("a stream whose head equals the registry's still reads the stream and control rows fresh, and purges on a tombstone", async () => {
    let probe: (() => void) | undefined;
    const w = await world({
      streams: 2,
      onExists: () => probe?.(),
    });
    const first = await publishConnection(w.deps, CONNECTION_ID);
    expect(first.every((r) => r.outcome === "published")).toBe(true);
    // The same rows again: the head is the registry's, so there is no write.
    await w.run("run-2", [
      { stream: "s0", id: "s0-1" },
      { stream: "s0", id: "s0-2" },
      { stream: "s1", id: "s1-1" },
      { stream: "s1", id: "s1-2" },
    ]);
    const batchesBefore = w.gateway.batches().length;
    // The remote delete lands during the transfer, after the snapshot.
    probe = () => {
      probe = undefined;
      w.tombstoneControl();
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
    expect(w.gateway.batches()).toHaveLength(batchesBefore);
    expect(w.purges).toHaveLength(1);
  });
});

describe("purge", () => {
  it("a purge found at commit releases every waiting stream and writes nothing", async () => {
    const hold = holdParts();
    const w = await world({ streams: 6, holdPut: hold.holdPut });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() =>
      expect(hold.parked.length).toBeGreaterThanOrEqual(2),
    );
    await w.tombstoneControl();
    hold.parked[0]!.release();
    await vi.waitFor(() => expect(w.purges.length).toBeGreaterThan(0));
    for (const part of hold.parked.slice(1)) part.release();
    const results = await publishing;
    expect(results.length).toBeGreaterThan(0);
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
    expect(streamRows(w.gateway)).toEqual([]);
    expect(w.purges).toHaveLength(1);
  });

  it("a delete that lands after the request committed is purged by the next snapshot", async () => {
    const w = await world({ streams: 3 });
    const first = await publishConnection(w.deps, CONNECTION_ID);
    expect(first.every((r) => r.outcome === "published")).toBe(true);
    // The old check after the write is gone: the next publish finds it.
    await w.tombstoneControl();
    const next = await publishConnection(w.deps, CONNECTION_ID);
    expect(next.every((r) => r.outcome === "purged")).toBe(true);
    expect(w.purges).toHaveLength(1);
  });
});

describe("per-row outcomes and the conditions that guard them", () => {
  it("a control row refreshed at the same version (other content) defers and writes nothing", async () => {
    const hold = holdParts();
    const w = await world({ streams: 3, holdPut: hold.holdPut });
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(3));
    // The version is the one the snapshot saw; only the content differs.
    w.gateway.beforeBatch = () =>
      w.gateway.replaceHead(CONTROL, {
        dataHash: `0x${"ab".repeat(32)}`,
        metadataHash: `0x${"cd".repeat(32)}`,
      });
    for (const part of hold.parked) part.release();
    const results = await publishing;
    expect(results.map((r) => r.outcome)).toEqual(Array(3).fill("deferred"));
    expect(streamRows(w.gateway)).toEqual([]);
    expect(w.purges).toEqual([]);
  });

  it("a first row names no head; a later row names the data hash of the head it replaces", async () => {
    const w = await world({ streams: 2 });
    await publishConnection(w.deps, CONNECTION_ID);
    const firstHeads = w.gateway.batches().flatMap((b) => b.body.rows);
    expect(firstHeads.every((r) => r.expectedHeadDataHash === undefined)).toBe(
      true,
    );
    const heads = new Map(
      w.names.map((name) => [
        scopeOf(name),
        w.gateway.versions.get(scopeOf(name))![0]!.dataHash,
      ]),
    );
    await w.run("run-2", [
      { stream: "s0", id: "s0-new" },
      { stream: "s1", id: "s1-new" },
    ]);
    const seen = w.gateway.batches().length;
    await publishConnection(w.deps, CONNECTION_ID);
    const later = w.gateway
      .batches()
      .slice(seen)
      .flatMap((b) => b.body.rows);
    expect(later).toHaveLength(2);
    for (const row of later) {
      expect(row.expectedHeadDataHash).toBe(heads.get(row.scope));
    }
  });

  it("a same-version refresh by another writer is not overwritten: the head fence refuses the row", async () => {
    const w = await world({
      streams: 1,
      gateway: { refresh: true },
    });
    await publishConnection(w.deps, CONNECTION_ID);
    await w.run("run-2", [{ stream: "s0", id: "s0-new" }]);
    const foreign = {
      dataHash: `0x${"ee".repeat(32)}`,
      metadataHash: `0x${"ff".repeat(32)}`,
    };
    // Another writer lands version 2 between this device's snapshot and its
    // request. A version-only guard would refresh (overwrite) it.
    w.gateway.beforeBatch = () => {
      w.gateway.beforeBatch = undefined;
      w.gateway.write(scopeOf("s0"), foreign);
    };
    await publishConnection(w.deps, CONNECTION_ID).catch(() => undefined);
    const rows = w.gateway.versions.get(scopeOf("s0"))!;
    expect(rows[1]).toEqual(foreign);
  });

  it("a lost reply, then a delete before the resend: the resend is answered 'deleted', the connection is purged and nothing is marked published", async () => {
    const w = await world({ streams: 3 });
    w.gateway.dropNextBatchReply = true;
    let batchCalls = 0;
    w.gateway.beforeBatch = () => {
      batchCalls++;
      if (batchCalls === 2) w.tombstoneControl();
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
    expect(w.gateway.batches()[1]!.raw).toBe(w.gateway.batches()[0]!.raw);
    expect(w.purges).toHaveLength(1);
    expect(
      await w.db.query(
        "SELECT 1 FROM run_streams WHERE publication_state='published'",
      ),
    ).toEqual([]);
  });

  it("an older gateway that answers a replayed row 'stale' with the row's own hash counts it as published", async () => {
    const w = await world({ streams: 2, gateway: { replay: "stale" } });
    w.gateway.dropNextBatchReply = true;
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(["published", "published"]);
    for (const stream of w.names) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
    }
  });
});

describe("a reply is settled only in the lifetime that sent the request", () => {
  const moveLifetime = (w: Awaited<ReturnType<typeof world>>) =>
    w.db.batch([
      {
        sql: "UPDATE connections SET generation = generation + 1 WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
    ]);

  it.each(["a fresh reply", "a stored reply to a resend"] as const)(
    "%s that arrives after the local lifetime moved is discarded: nothing is recorded as published",
    async (which) => {
      const w = await world({ streams: 3 });
      let calls = 0;
      if (which === "a stored reply to a resend") {
        w.gateway.dropNextBatchReply = true;
      }
      w.gateway.beforeBatch = async () => {
        calls++;
        // The first request, or its resend: the gateway has not looked at it
        // yet, and the local lifetime moves.
        if (calls === (which === "a fresh reply" ? 1 : 2)) {
          await moveLifetime(w);
        }
      };
      const results = await publishConnection(w.deps, CONNECTION_ID);
      expect(results.some((r) => r.outcome === "published")).toBe(false);
      expect(
        await w.db.query(
          "SELECT 1 FROM run_streams WHERE publication_state='published'",
        ),
      ).toEqual([]);
    },
  );
});

describe("a stream with nothing to write is a condition of the request, not a read", () => {
  /**
   * Four streams; s0 and s1 changed, s2 and s3 did not. s0's request is in
   * flight while s1 (a writer) and s2, s3 (nothing to write) become ready, so
   * the next request carries all three.
   */
  type World = Awaited<ReturnType<typeof world>>;
  const fenced = async (
    setup?: (w: World) => void,
    /** Runs before each request after the first, with its 1-based number among them. */
    later?: (w: World, n: number) => void,
  ) => {
    const hold = holdParts();
    let armed = false;
    let sent!: () => void;
    const firstSent = new Promise<void>((r) => (sent = r));
    let reply!: () => void;
    const firstHeld = new Promise<void>((r) => (reply = r));
    let probed: string[] = [];
    const w = await world({
      streams: 4,
      holdPut: (key) => (armed ? hold.holdPut(key) : undefined),
      // The unchanged streams finish their transfer only once the first
      // request is in flight, so they meet a busy slot.
      onExists: (key) => {
        probed.push(key);
        return armed && /\.s[23]\//.test(key) ? firstSent : undefined;
      },
    });
    // The gateway applied every row of a first publish whose replies were all
    // lost: every stream's head is already the registry's, still unpublished.
    w.gateway.beforeBatch = () => {
      w.gateway.dropNextBatchReply = true;
    };
    await publishConnection(w.deps, CONNECTION_ID).catch(() => undefined);
    w.gateway.beforeBatch = undefined;
    for (const stream of w.names) {
      expect(w.gateway.rowsOf(scopeOf(stream))).toBe(1);
    }
    await w.run("run-2", [
      { stream: "s0", id: "s0-new" },
      { stream: "s1", id: "s1-new" },
    ]);
    probed = [];
    setup?.(w);
    const seenBatches = w.gateway.batches().length;
    const seenCalls = w.gateway.calls.length;
    armed = true;
    let laterCalls = 0;
    w.gateway.beforeBatch = async () => {
      w.gateway.beforeBatch = () => later?.(w, ++laterCalls);
      sent();
      await firstHeld;
    };
    const publishing = publishConnection(w.deps, CONNECTION_ID);
    await vi.waitFor(() => expect(hold.parked).toHaveLength(2));
    hold.parked.find((part) => /\.s0\//.test(part.key))!.release();
    await firstSent;
    hold.parked.find((part) => /\.s1\//.test(part.key))!.release();
    await vi.waitFor(() =>
      expect(
        w.putsDone().filter((k) => /\.s1\//.test(k)).length,
      ).toBeGreaterThan(0),
    );
    await new Promise((r) => setTimeout(r, 50));
    reply();
    const results = await publishing;
    return { w, results, seenBatches, seenCalls };
  };

  it("the request names each unchanged stream's row (version, data hash) beside the control row, and nothing is read after it", async () => {
    const { w, results, seenBatches, seenCalls } = await fenced();
    expect(results.map((r) => r.outcome)).toEqual([
      "published",
      "published",
      "noop",
      "noop",
    ]);
    const batches = w.gateway.batches().slice(seenBatches);
    expect(batches).toHaveLength(2);
    const second = batches[1]!;
    expect(second.body.rows.map((r) => r.scope)).toEqual([scopeOf("s1")]);
    for (const stream of ["s2", "s3"]) {
      const scope = scopeOf(stream);
      expect(second.body.requires).toContainEqual({
        scope,
        expectedVersion: "1",
        notDeleted: true,
        expectedDataHash: w.gateway.versions.get(scope)![0]!.dataHash,
      });
    }
    const after = w.gateway.calls.slice(w.gateway.calls.indexOf(second) + 1);
    expect(after.filter((c) => c.kind === "read")).toEqual([]);
    expect(w.gateway.calls.length).toBeGreaterThan(seenCalls);
  });

  it("a failed fence writes nothing: that stream re-plans, and the writer goes in the very next request, without it", async () => {
    const { w, results, seenBatches } = await fenced((world) =>
      world.gateway.failFenceOnce(scopeOf("s2")),
    );
    expect(results.map((r) => r.outcome)).toEqual([
      "published",
      "published",
      "noop",
      "noop",
    ]);
    const batches = w.gateway.batches().slice(seenBatches);
    // s1's row went exactly once. The request after the failed one is sent at
    // once: it holds s1 and the unchanged s3, not s2.
    expect(w.gateway.rowsOf(scopeOf("s1"))).toBe(2);
    expect(batches[1]!.body.rows.map((r) => r.scope)).toEqual([scopeOf("s1")]);
    expect(batches[2]!.body.rows.map((r) => r.scope)).toEqual([scopeOf("s1")]);
    const named = (batch: (typeof batches)[number]) =>
      batch.body.requires.map((r) => r.scope);
    expect(named(batches[1]!)).toContain(scopeOf("s2"));
    expect(named(batches[2]!)).not.toContain(scopeOf("s2"));
    expect(named(batches[2]!)).toContain(scopeOf("s3"));
    // The fenced stream is read again after the failed request, and rejoins
    // in a request of its own.
    const failedAt = w.gateway.calls.indexOf(batches[1]!);
    expect(
      w.gateway.calls
        .slice(failedAt + 1)
        .some((c) => c.kind === "read" && c.scope === scopeOf("s2")),
    ).toBe(true);
    expect(named(batches.at(-1)!)).toContain(scopeOf("s2"));
  });

  it("a stream that loses its fence every time does not keep its sibling from committing", async () => {
    const { w, results, seenBatches } = await fenced((world) =>
      world.gateway.failFenceAlways(scopeOf("s2")),
    );
    // s2 re-plans, rejoins and loses until its attempts run out; the others
    // finish regardless.
    expect(results.map((r) => r.outcome)).toEqual([
      "published",
      "published",
      "backoff",
      "noop",
    ]);
    const batches = w.gateway.batches().slice(seenBatches);
    expect(w.gateway.rowsOf(scopeOf("s1"))).toBe(2);
    // The request right after the first failure carries s1 and no s2.
    expect(batches[1]!.body.requires.map((r) => r.scope)).toContain(
      scopeOf("s2"),
    );
    expect(batches[2]!.body.rows.map((r) => r.scope)).toEqual([scopeOf("s1")]);
    expect(batches[2]!.body.requires.map((r) => r.scope)).not.toContain(
      scopeOf("s2"),
    );
  });

  it("a lost reply to a request with fences, then a delete: the resend answers 'deleted', the connection is purged and no fenced stream is marked", async () => {
    const { w, results, seenBatches } = await fenced(
      (world) => {
        world.gateway.dropNextBatchReply = false;
      },
      (world, n) => {
        // The second request (s1 and the fences) is applied and its reply is
        // lost; the delete lands before the resend.
        if (n === 1) world.gateway.dropNextBatchReply = true;
        if (n === 2) world.tombstoneControl();
      },
    );
    expect(results.map((r) => r.outcome)).toEqual([
      "published",
      "purged",
      "purged",
      "purged",
    ]);
    const batches = w.gateway.batches().slice(seenBatches);
    expect(batches[2]!.raw).toBe(batches[1]!.raw);
    expect(w.purges).toHaveLength(1);
    // Only s0, whose own request was answered before the delete, is marked.
    const marked = await w.db.query(
      "SELECT DISTINCT stream FROM run_streams WHERE publication_state='published'",
    );
    expect(marked.map((row) => row.stream)).toEqual(["s0"]);
  });

  it("a lost reply to a request with fences is resent, and a success then records the fenced streams", async () => {
    const { w, results, seenBatches } = await fenced(undefined, (world, n) => {
      if (n === 1) world.gateway.dropNextBatchReply = true;
    });
    expect(results.map((r) => r.outcome)).toEqual([
      "published",
      "published",
      "noop",
      "noop",
    ]);
    const batches = w.gateway.batches().slice(seenBatches);
    expect(batches).toHaveLength(3);
    expect(batches[2]!.raw).toBe(batches[1]!.raw);
    expect(w.gateway.rowsOf(scopeOf("s1"))).toBe(2);
  });

  it("a turn with nothing but unchanged streams sends their conditions as a request with no rows, and records them on its success", async () => {
    const w = await world({ streams: 2 });
    // Every row applied, every reply lost: both heads are the registry's.
    w.gateway.beforeBatch = () => {
      w.gateway.dropNextBatchReply = true;
    };
    await publishConnection(w.deps, CONNECTION_ID).catch(() => undefined);
    w.gateway.beforeBatch = undefined;
    const seenBatches = w.gateway.batches().length;
    const seenCalls = w.gateway.calls.length;
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "noop")).toBe(true);
    const batches = w.gateway.batches().slice(seenBatches);
    expect(batches.length).toBeGreaterThan(0);
    for (const batch of batches) expect(batch.body.rows).toEqual([]);
    expect(
      new Set(batches.flatMap((b) => b.body.requires.map((r) => r.scope))),
    ).toEqual(new Set([CONTROL, ...w.names.map(scopeOf)]));
    // No stream was read or posted alone: the conditions were the check.
    const after = w.gateway.calls.slice(seenCalls);
    expect(
      after
        .slice(after.findIndex((c) => c.kind === "batch"))
        .filter((c) => c.kind === "read" || c.kind === "post"),
    ).toEqual([]);
    expect(
      await w.db.query(
        "SELECT 1 FROM run_streams WHERE publication_state='published'",
      ),
    ).not.toEqual([]);
  });

  it("a request of conditions only, answered 'deleted', purges and records nothing", async () => {
    const w = await world({ streams: 2 });
    w.gateway.beforeBatch = () => {
      w.gateway.dropNextBatchReply = true;
    };
    await publishConnection(w.deps, CONNECTION_ID).catch(() => undefined);
    w.gateway.beforeBatch = () => {
      w.gateway.beforeBatch = undefined;
      w.tombstoneControl();
    };
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.every((r) => r.outcome === "purged")).toBe(true);
    expect(w.purges).toHaveLength(1);
  });

  it.each([404, 405] as const)(
    "a gateway that answers a conditions-only request with %s: the unchanged streams read fresh and settle alone",
    async (route) => {
      const w = await world({ streams: 2 });
      w.gateway.beforeBatch = () => {
        w.gateway.dropNextBatchReply = true;
      };
      await publishConnection(w.deps, CONNECTION_ID).catch(() => undefined);
      w.gateway.beforeBatch = undefined;
      w.gateway.setBatchRoute(route);
      const seenBatches = w.gateway.batches().length;
      const seenCalls = w.gateway.calls.length;
      const results = await publishConnection(w.deps, CONNECTION_ID);
      expect(results.every((r) => r.outcome === "noop")).toBe(true);
      // One try at the route, then each stream on its own: fresh stream and
      // control reads, no more requests.
      expect(w.gateway.batches()).toHaveLength(seenBatches + 1);
      const afterRoute = w.gateway.calls.slice(seenCalls);
      expect(
        afterRoute.filter((c) => c.kind === "read" && c.scope !== CONTROL)
          .length,
      ).toBeGreaterThanOrEqual(2);
    },
  );
});

describe("a stream with nothing to publish, served by the connection's listing", () => {
  // Every stream is published once, then a partial run finds nothing new: the
  // plan of each stream has no row to write and only a run to take evidence
  // of. Every stream after the first has the row from the connection's
  // listing as a hint. The hint is confirmed by the request's conditions on
  // the batch path, and by live reads when there is no batch route.
  const idleWorld = async (gateway?: Partial<FakeGatewayOptions>) => {
    const w = await world({ streams: 4, gateway });
    expect(
      (await publishConnection(w.deps, CONNECTION_ID)).map((r) => r.outcome),
    ).toEqual(Array(4).fill("published"));
    await w.idleRun("run-2");
    return {
      w,
      seenCalls: w.gateway.calls.length,
      seenBatches: w.gateway.batches().length,
    };
  };
  const evidenceOf = async (w: Awaited<ReturnType<typeof world>>) =>
    Object.fromEntries(
      (
        await w.db.query<{ stream: string; published_version: number | null }>(
          "SELECT stream, published_version FROM run_streams WHERE run_id = ?",
          ["run-2"],
        )
      ).map((row) => [row.stream, row.published_version]),
    );
  const readsOf = (
    w: Awaited<ReturnType<typeof world>>,
    seen: number,
    scope: string,
  ) =>
    w.gateway.calls
      .slice(seen)
      .filter((c) => c.kind === "read" && c.scope === scope).length;

  it("the stream row is a condition of a batch that writes nothing, and nothing is read live", async () => {
    const { w, seenCalls, seenBatches } = await idleWorld();
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("noop"));
    const batches = w.gateway.batches().slice(seenBatches);
    expect(batches.length).toBeGreaterThan(0);
    for (const batch of batches) expect(batch.body.rows).toEqual([]);
    const required = new Set(
      batches.flatMap((b) => b.body.requires.map((r) => r.scope)),
    );
    // The first stream read its own rows; the three after it ride the batch.
    const listed = w.names.filter((name) => required.has(scopeOf(name)));
    expect(listed).toHaveLength(3);
    for (const name of w.names) {
      expect(readsOf(w, seenCalls, scopeOf(name))).toBe(
        listed.includes(name) ? 0 : 1,
      );
    }
    // The control row is a condition of each request, not a live read after.
    expect(
      batches.every((b) => b.body.requires.some((r) => r.scope === CONTROL)),
    ).toBe(true);
    const evidence = await evidenceOf(w);
    for (const name of w.names) expect(evidence[name]).toBe(1);
  });

  it("without the batch route the hints are confirmed by live reads, stream row then control row", async () => {
    const { w, seenCalls } = await idleWorld({ batchRoute: 404 });
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("noop"));
    for (const name of w.names) {
      expect(readsOf(w, seenCalls, scopeOf(name))).toBe(1);
    }
    expect(controlReads(w.gateway)).toBeGreaterThan(0);
    const evidence = await evidenceOf(w);
    for (const name of w.names) expect(evidence[name]).toBe(1);
  });

  it("a connection deleted after the listing purges, and no stream says noop", async () => {
    const { w } = await idleWorld();
    await w.tombstoneControl();
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.some((r) => r.outcome === "noop")).toBe(false);
    expect(w.purges.length).toBeGreaterThan(0);
    const evidence = await evidenceOf(w);
    for (const name of w.names) expect(evidence[name] ?? null).toBeNull();
  });

  it("a stream row that moved leaves the batch; the others go in the very next request, sent at once", async () => {
    const { w, seenBatches } = await idleWorld();
    w.gateway.failFenceOnce(scopeOf("s2"));
    const results = await publishConnection(w.deps, CONNECTION_ID);
    expect(results.map((r) => r.outcome)).toEqual(Array(4).fill("noop"));
    const batches = w.gateway.batches().slice(seenBatches);
    const named = (batch: (typeof batches)[number]) =>
      batch.body.requires.map((r) => r.scope);
    const failed = batches.findIndex((b) => named(b).includes(scopeOf("s2")));
    expect(failed).toBeGreaterThanOrEqual(0);
    const survivors = named(batches[failed]!).filter(
      (scope) => scope !== scopeOf("s2") && scope !== CONTROL,
    );
    // The request after the failed one carries the survivors and not s2.
    const next = batches[failed + 1];
    if (survivors.length > 0) {
      expect(next).toBeDefined();
      expect(named(next!)).not.toContain(scopeOf("s2"));
      for (const scope of survivors) expect(named(next!)).toContain(scope);
    }
    // s2 read its row live after the failed request and still took evidence.
    expect(
      w.gateway.calls
        .slice(w.gateway.calls.indexOf(batches[failed]!) + 1)
        .some((c) => c.kind === "read" && c.scope === scopeOf("s2")),
    ).toBe(true);
    const evidence = await evidenceOf(w);
    for (const name of w.names) expect(evidence[name]).toBe(1);
  });
});
