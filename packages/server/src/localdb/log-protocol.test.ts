// The stream-sync log: one segment per committed batch holds the operations of
// every stream the batch touched; one registry commit per batch advances one
// per-connection log position (stream-sync/src/log.ts). Real gateway adapter,
// real publish and apply drivers, real SQLite, real connection queue, against
// the fake gateway's batch route (fake-gateway.ts). Every device of a test
// shares one gateway and one blob store, as the devices of one owner do.
import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, describe, expect, it } from "vitest";
import {
  controlHashes,
  controlScope,
  decodeSegment,
  decodeSnapshotPart,
  deriveKeyCheck,
  logScope,
  pkHash,
  shouldCompact,
  streamScope,
  foldLog,
  partitionFold,
  type LogEntry,
  type Segment,
  type SnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
  applyConnection,
  applySegmentOperations,
  applySnapshotPart,
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createFakeGateway } from "./fake-gateway.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const CONTROL = controlScope(CONNECTOR, "");
const LOG = logScope(CONNECTOR, "");
const sName = (i: number) => `s${i}`;
const idHash = (id: string) => pkHash(async (b) => sha256(b), { id }, ["id"]);

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function world(options: {
  streams: number;
  logProtocol: boolean;
  partTargetBytes?: number;
}) {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const gateway = createFakeGateway({
    owner: OWNER,
    isTombstone: (v) =>
      v.dataHash === hashes.tombstoneData &&
      v.metadataHash === hashes.tombstoneMetadata,
  });
  const store = new Map<string, Uint8Array>();
  const innerBlobs = {
    governor: createMemoryStreamSyncBlobs().governor,
    put: async (key: string, bytes: Uint8Array) => {
      store.set(key, bytes.slice());
    },
    get: async (key: string) => store.get(key) ?? null,
    exists: async (key: string) => store.has(key),
    keys: () => [...store.keys()],
    delete: (key: string) => store.delete(key),
  };
  const names = Array.from({ length: options.streams }, (_, i) => sName(i));
  let clock = 1000;

  async function device(
    deviceId: string,
    logProtocol = options.logProtocol,
    hooks: { beforePut?: (key: string) => Promise<void> } = {},
  ) {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner: OWNER,
      network: "test",
      deviceId,
    });
    drivers.push(db);
    const puts: string[] = [];
    const gets: string[] = [];
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      registry: createGatewayStreamSyncRegistry({
        gatewayUrl: "https://gateway.test",
        ownerAddress: OWNER,
        fetch: gateway.fetch,
      }),
      blobs: {
        governor: innerBlobs.governor,
        async get(key) {
          gets.push(key);
          return innerBlobs.get(key);
        },
        exists: (key) => innerBlobs.exists(key),
        async put(key, bytes) {
          await hooks.beforePut?.(key);
          await innerBlobs.put(key, bytes);
          puts.push(key);
        },
      },
      ownerAddress: OWNER,
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: async (_s, b) => b,
        encryptPart: async (_s, b) => b,
        decrypt: async (_s, b) => b,
      },
      signer: { signAddData: async () => "0x00" },
      logger: { info: () => {}, warn: () => {} },
      now: () => clock,
      newOp: () => `${deviceId}-${++op}`,
      ...(logProtocol ? { logProtocol: true } : {}),
      ...(options.partTargetBytes !== undefined
        ? { partTargetBytes: options.partTargetBytes }
        : {}),
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: names.map((name) => ({
          name,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory" as const,
        })),
      }),
      declaredStreams: () => names,
      olderVersionReads: () => true,
    });
    /** One run that writes `records` and ends covering `covered`. */
    const run = async (
      runId: string,
      records: readonly {
        stream: string;
        id: string;
        v?: number;
        pad?: number;
        blobId?: string;
        remove?: boolean;
      }[],
      opts: {
        covered?: readonly string[];
        full?: boolean;
        observedAt?: number;
        /** Bytes the record named by `blobId` carries, sent before the run ends. */
        blob?: { hash: string; bytes: Uint8Array };
      } = {},
    ) => {
      clock++;
      await sync.intake.begin(runId, {
        connector: CONNECTOR,
        artifactDigest: CONNECTOR,
        wantFull: opts.full ?? true,
        observedAt: opts.observedAt,
        owner: { address: OWNER, leaseId: null },
      });
      await sync.intake.batch(runId, {
        batch: 0,
        records: records.map(({ stream, id, v, pad, blobId, remove }) => ({
          stream,
          ...(remove ? { op: "delete" as const } : {}),
          data: {
            id,
            ...(v === undefined ? {} : { v }),
            ...(pad === undefined ? {} : { pad: "p".repeat(pad) }),
            ...(blobId === undefined ? {} : { blob_ref: { blob_id: blobId } }),
          },
        })),
      });
      if (opts.blob)
        await sync.blobs.put({
          runId,
          sha256: opts.blob.hash,
          mimeType: "application/octet-stream",
          bytes: opts.blob.bytes,
        });
      await sync.intake.end(runId, {
        outcome: "succeeded",
        coveredStreams: opts.covered ?? names,
        lastBatch: 0,
        ...(opts.full === false ? {} : { provenFullStreams: names }),
      });
    };
    const cycle = async () => {
      const report = await sync.cycle();
      const failed = report.connections.find((c) => c.error !== null);
      if (failed) throw new Error(`cycle failed: ${failed.error}`);
      return report;
    };
    const records = async () =>
      (
        await db.query<{ stream: string; record_key: string; body: string }>(
          "SELECT stream, record_key, body FROM records ORDER BY stream, record_key",
        )
      ).map((r) => `${r.stream}/${r.record_key}=${r.body}`);
    /** Every column the log promises a caught-up reader agrees on. */
    const rows = async () =>
      (
        await db.query<{
          stream: string;
          record_key: string;
          body: string;
          stamp_o: number;
          stamp_r: string;
          first_o: number | null;
        }>(
          "SELECT stream, record_key, body, stamp_o, stamp_r, first_o FROM records ORDER BY stream, record_key",
        )
      ).map((r) => JSON.stringify(r));
    const position = async () =>
      (
        await db.query<{ position: number }>(
          "SELECT position FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        )
      )[0]?.position ?? 0;
    return { db, deps, sync, run, cycle, records, rows, position, puts, gets };
  }

  /** The decoded segments in the blob store, by position. */
  const segments = async () => {
    const out = new Map<number, Segment>();
    for (const key of innerBlobs.keys()) {
      if (!key.startsWith(`${LOG}/s-`)) continue;
      const bytes = await innerBlobs.get(key);
      const decoded = decodeSegment(bytes!);
      if (decoded.kind === "ok")
        out.set(decoded.segment.position, decoded.segment);
    }
    return out;
  };
  /** Segment blob keys by position. */
  const segmentKeys = async () => {
    const out = new Map<number, string>();
    for (const key of innerBlobs.keys()) {
      if (!key.startsWith(`${LOG}/s-`)) continue;
      const decoded = decodeSegment((await innerBlobs.get(key))!);
      if (decoded.kind === "ok") out.set(decoded.segment.position, key);
    }
    return out;
  };
  /** The snapshot parts a head points at, decoded, in pointer order. */
  const snapshotParts = async (head: Segment) => {
    const parts: SnapshotPart[] = [];
    for (const ref of head.snapshot!.parts) {
      const decoded = decodeSnapshotPart(
        (await innerBlobs.get(`${LOG}/q-${ref.dataHash.slice(2)}`))!,
      );
      if (decoded.kind !== "ok")
        throw new Error("snapshot part did not decode");
      parts.push(decoded.part);
    }
    return parts;
  };
  const writes = () => ({
    batches: gateway.batches().length,
    posts: gateway.calls.filter((c) => c.kind === "post").length,
  });
  return {
    device,
    gateway,
    names,
    innerBlobs,
    segments,
    segmentKeys,
    snapshotParts,
    writes,
    setClock: (t: number) => (clock = t),
  };
}

const six = (prefix = "a") =>
  Array.from({ length: 6 }, (_, i) => [
    { stream: sName(i), id: `${prefix}${i}-1` },
    { stream: sName(i), id: `${prefix}${i}-2` },
  ]).flat();

describe("log protocol, flag on", () => {
  it("a 6-stream batch is one segment PUT and one registry commit", async () => {
    const w = await world({ streams: 6, logProtocol: true });
    const a = await w.device("a");
    await a.run("run-1", six());
    await a.cycle();
    expect(a.puts).toHaveLength(1);
    expect(a.puts[0]).toMatch(/\.~log\/s-[0-9a-f]{64}$/);
    expect(w.writes().batches).toBe(1);
    const [batch] = w.gateway.batches();
    expect(batch!.body.rows.map((r) => r.scope)).toEqual([LOG]);
    expect(batch!.body.rows[0]!.expectedVersion).toBe("1");
    // No stream row exists: the log row is the only data row besides control.
    expect([...w.gateway.versions.keys()].filter((s) => s !== CONTROL)).toEqual(
      [LOG],
    );
    expect(await a.position()).toBe(1);
    const segment = (await w.segments()).get(1)!;
    expect(segment.streams.map((s) => s.stream)).toEqual(w.names);
    expect(segment.operations.filter((o) => o.kind === "upsert")).toHaveLength(
      12,
    );
  });

  it("P2: a receiver at position n fetches and applies only n+1..m", async () => {
    const w = await world({ streams: 6, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", six());
    await a.cycle();
    await b.cycle();
    expect(await b.position()).toBe(1);
    await a.run("run-2", [{ stream: sName(0), id: "late-1" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    await a.run("run-3", [{ stream: sName(1), id: "late-2" }], {
      full: false,
      covered: [sName(1)],
    });
    await a.cycle();
    expect(await a.position()).toBe(3);
    const before = b.gets.length;
    await b.cycle();
    const fetched = b.gets.slice(before).filter((k) => k.startsWith(`${LOG}/`));
    const all = await w.segments();
    // Positions 2 and 3 only: two segment GETs, none for position 1.
    expect(fetched).toHaveLength(2);
    expect(all.size).toBe(3);
    expect(await b.position()).toBe(3);
    expect(await b.records()).toEqual(await a.records());
  });

  it("P1: out-of-order and duplicated segments converge to the same records", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a");
    await a.run("run-1", [
      { stream: sName(0), id: "x", v: 1 },
      { stream: sName(0), id: "y", v: 1 },
      { stream: sName(1), id: "z", v: 1 },
    ]);
    await a.cycle();
    await a.run("run-2", [{ stream: sName(0), id: "x", v: 2 }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    await a.run("run-3", [{ stream: sName(0), id: "y", remove: true }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    const segments = await w.segments();
    expect(segments.size).toBe(3);

    const inOrder = await w.device("in-order");
    const shuffled = await w.device("shuffled");
    for (const d of [inOrder, shuffled])
      await d.db.batch([
        {
          sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns) VALUES (?,?,'')",
          params: [CONNECTION_ID, CONNECTOR],
        },
      ]);
    for (const position of [1, 2, 3])
      await applySegmentOperations(
        inOrder.deps,
        CONNECTION_ID,
        segments.get(position)!,
      );
    for (const position of [3, 1, 2, 2, 3, 1])
      await applySegmentOperations(
        shuffled.deps,
        CONNECTION_ID,
        segments.get(position)!,
      );
    expect(await shuffled.records()).toEqual(await inOrder.records());
    expect(await inOrder.records()).toEqual(
      [`s0/x={"id":"x","v":2}`, `s1/z={"id":"z","v":1}`].sort(),
    );
  });

  it("P2: a gap triggers a full check, and a missing segment never lets n+1 apply before n", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", [{ stream: sName(0), id: "one" }]);
    await a.cycle();
    await b.cycle();
    expect(await b.position()).toBe(1);

    // Ahead of the registry (a restored registry): fail closed, with nothing
    // fetched or applied and the position kept (see the P2-2 tests).
    await b.db.batch([
      {
        sql: "UPDATE log_state SET position = 9 WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
    ]);
    const before = b.gets.length;
    await expect(b.cycle()).rejects.toThrow(/behind this device/);
    expect(await b.position()).toBe(9);
    expect(b.gets.slice(before).some((k) => k.startsWith(`${LOG}/s-`))).toBe(
      false,
    );
    await b.db.batch([
      {
        sql: "UPDATE log_state SET position = 1 WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
    ]);

    // Segment 2 is missing: segment 3 must not apply.
    await a.run("run-2", [{ stream: sName(0), id: "two" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    await a.run("run-3", [{ stream: sName(0), id: "three" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    const two = [...w.innerBlobs.keys()].filter((k) =>
      k.startsWith(`${LOG}/s-`),
    );
    const segments = await w.segments();
    const second = await (async () => {
      for (const key of two) {
        const decoded = decodeSegment((await w.innerBlobs.get(key))!);
        if (decoded.kind === "ok" && decoded.segment.position === 2) return key;
      }
      throw new Error("segment 2 not found");
    })();
    expect(segments.size).toBe(3);
    w.innerBlobs.delete(second);
    await expect(b.cycle()).rejects.toThrow();
    expect(await b.position()).toBe(1);
    expect((await b.records()).some((r) => r.includes("three"))).toBe(false);
  });

  it("P1: caught-up readers equal the greatest-stamp fold of the whole log", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run(
      "run-1",
      [
        { stream: sName(0), id: "x", v: 1 },
        { stream: sName(0), id: "y", v: 1 },
        { stream: sName(1), id: "z", v: 1 },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await b.cycle();
    await b.run("run-2", [{ stream: sName(0), id: "x", v: 2 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1200,
    });
    await b.cycle();
    await a.cycle();
    await a.run("run-3", [{ stream: sName(0), id: "y", remove: true }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1300,
    });
    await a.run("run-4", [{ stream: sName(1), id: "w", v: 1 }], {
      full: false,
      covered: [sName(1)],
      observedAt: 1400,
    });
    await a.cycle();
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();

    // The oracle reads only the segments: per key the greatest stamp wins, a
    // delete wins a tie, and an omission removes what is below its cutoff.
    const stampOf = (op: { stamp: { o: number; r: string } }) => op.stamp;
    const after = (x: { o: number; r: string }, y: { o: number; r: string }) =>
      x.o > y.o || (x.o === y.o && x.r > y.r);
    const ops = [...(await w.segments()).values()].flatMap((g) => g.operations);
    const winners = new Map<string, (typeof ops)[number]>();
    for (const op of ops) {
      if (op.kind === "complete") continue;
      const key = `${op.stream}/${op.pkHash}`;
      const held = winners.get(key);
      if (
        !held ||
        held.kind === "complete" ||
        after(stampOf(op), stampOf(held)) ||
        (!after(stampOf(held), stampOf(op)) && op.kind === "delete")
      )
        winners.set(key, op);
    }
    for (const op of ops)
      if (op.kind === "complete")
        for (const pk of op.omitted) {
          const held = winners.get(`${op.stream}/${pk}`);
          if (
            held &&
            !after(stampOf(held), op.cutoff) &&
            !(held.stamp.o === op.cutoff.o && held.stamp.r === op.cutoff.r)
          )
            winners.delete(`${op.stream}/${pk}`);
        }
    const expected = [...winners.values()]
      .flatMap((op) =>
        op.kind === "upsert"
          ? [
              `${op.stream}/${(op.value as { id: string }).id}=${JSON.stringify(op.value)}`,
            ]
          : [],
      )
      .sort();
    expect(expected).toEqual([
      `s0/x={"id":"x","v":2}`,
      `s1/w={"id":"w","v":1}`,
      `s1/z={"id":"z","v":1}`,
    ]);
    for (const d of [a, b, c]) expect(await d.records()).toEqual(expected);
  });

  it("P5: after a reset a reader adopts the new lifetime and clears the old view", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", [
      { stream: sName(0), id: "x" },
      { stream: sName(0), id: "y" },
    ]);
    await a.cycle();
    await b.cycle();
    expect(await b.records()).toHaveLength(2);

    // The connection is deleted and made again: the control row moves to a
    // new generation and the old log row stays behind in the registry.
    const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
    const hashes = await controlHashes(async (x) => keccak_256(x), keyCheck);
    await a.deps.registry.post({
      ownerAddress: OWNER,
      scope: CONTROL,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      expectedVersion: "2",
      signature: "0x00",
    });
    await a.cycle();
    expect(await a.records()).toEqual([]);
    await a.run("run-2", [{ stream: sName(0), id: "z" }]);
    await a.cycle();

    // B was offline across the reset. It adopts the new lifetime: none of the
    // old records survive, and the new log segment applies on top of the old
    // row's position.
    await b.cycle();
    expect(await b.records()).toEqual([`s0/z={"id":"z"}`]);
    expect(await b.position()).toBe(await a.position());
    const gen2 = [...(await w.segments()).values()].filter(
      (g) => g.generation === 2,
    );
    expect(gen2).toHaveLength(1);
  });

  it("P3: an omission completion deletes only records not observed at or after the cutoff", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run(
      "run-1",
      [
        { stream: sName(0), id: "1" },
        { stream: sName(0), id: "2" },
        { stream: sName(0), id: "3" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await b.cycle();
    expect(await b.records()).toHaveLength(3);

    // B sees record 3 again after A's full pass would have run.
    await b.run("run-b", [{ stream: sName(0), id: "3" }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1300,
    });
    // A's full pass lists only 1 and 2: 3 is omitted at cutoff 1200.
    await a.run(
      "run-2",
      [
        { stream: sName(0), id: "1" },
        { stream: sName(0), id: "2" },
      ],
      { observedAt: 1200 },
    );
    await a.cycle();
    const completion = [...(await w.segments()).values()]
      .sort((x, y) => y.position - x.position)
      .flatMap((s) => s.operations)
      .find((o) => o.kind === "complete");
    expect(completion).toMatchObject({
      kind: "complete",
      stream: sName(0),
      omitted: [await idHash("3")],
    });
    await b.cycle();
    // 1 and 2 stay; 3 was observed by B after the cutoff, so B keeps it.
    expect((await b.records()).map((r) => r.split("=")[0])).toEqual([
      "s0/1",
      "s0/2",
      "s0/3",
    ]);
    // A fresh device replays the whole log: B's later observation of 3 is in
    // it, at a stamp above the cutoff, so 3 stays however the segments order.
    const c = await w.device("c");
    await c.cycle();
    expect((await c.records()).map((r) => r.split("=")[0])).toEqual([
      "s0/1",
      "s0/2",
      "s0/3",
    ]);
    // A device holding only the first two segments never saw B's observation
    // of 3, so the completion drops it.
    const segments = await w.segments();
    expect(segments.size).toBe(3);
    const d = await w.device("d");
    await d.db.batch([
      {
        sql: "INSERT OR IGNORE INTO connections(connection_id,connector,ns) VALUES (?,?,'')",
        params: [CONNECTION_ID, CONNECTOR],
      },
    ]);
    for (const position of [1, 2])
      await applySegmentOperations(
        d.deps,
        CONNECTION_ID,
        segments.get(position)!,
      );
    expect((await d.records()).map((r) => r.split("=")[0])).toEqual([
      "s0/1",
      "s0/2",
    ]);
  });

  it("upgrades a connection whose streams were published in the old format", async () => {
    const w = await world({ streams: 3, logProtocol: false });
    const legacy = await w.device("legacy", false);
    await legacy.run("run-1", [
      { stream: sName(0), id: "old-1" },
      { stream: sName(1), id: "old-2" },
    ]);
    await legacy.cycle();
    expect(
      [...w.gateway.versions.keys()].filter((s) => s !== CONTROL).sort(),
    ).toEqual(
      [
        streamScope(CONNECTOR, "", sName(0)),
        streamScope(CONNECTOR, "", sName(1)),
        streamScope(CONNECTOR, "", sName(2)),
      ]
        .filter((s) => w.gateway.versions.has(s))
        .sort(),
    );

    const upgraded = await w.device("upgraded", true);
    await upgraded.cycle();
    // Old heads read; no position yet.
    expect(await upgraded.records()).toEqual(await legacy.records());
    expect(await upgraded.position()).toBe(0);

    await upgraded.run("run-2", [{ stream: sName(2), id: "new-1" }], {
      full: false,
      covered: [sName(2)],
    });
    await upgraded.cycle();
    expect(await upgraded.position()).toBe(1);

    const fresh = await w.device("fresh", true);
    await fresh.cycle();
    expect((await fresh.records()).map((r) => r.split("=")[0])).toEqual([
      "s0/old-1",
      "s1/old-2",
      "s2/new-1",
    ]);
    expect(await fresh.position()).toBe(1);
  });
});

describe("flag off", () => {
  it("publishes per-stream heads and writes no log row", async () => {
    const w = await world({ streams: 6, logProtocol: false });
    const a = await w.device("a");
    await a.run("run-1", six());
    await a.cycle();
    expect(w.gateway.versions.has(LOG)).toBe(false);
    expect(a.puts.length).toBeGreaterThan(6);
  });
});

describe("request counts", () => {
  for (const streams of [6, 20]) {
    it(`${streams} streams: log writes 1 PUT and 1 commit; per-stream writes more`, async () => {
      const records = Array.from({ length: streams }, (_, i) => [
        { stream: sName(i), id: `r${i}-1` },
        { stream: sName(i), id: `r${i}-2` },
      ]).flat();
      const counts: Record<
        string,
        { puts: number; batches: number; posts: number }
      > = {};
      for (const logProtocol of [false, true]) {
        const w = await world({ streams, logProtocol });
        const a = await w.device("a");
        await a.run("run-1", records);
        await a.cycle();
        counts[logProtocol ? "log" : "legacy"] = {
          puts: a.puts.length,
          ...w.writes(),
        };
      }
      console.info(
        `request counts, ${streams} streams`,
        JSON.stringify(counts),
      );
      expect(counts.log!.puts).toBe(1);
      expect(counts.log!.batches).toBe(1);
      expect(counts.legacy!.puts).toBeGreaterThan(counts.log!.puts);
    });
  }
});

// ---------------------------------------------------------------------------
// Compaction, size splitting, attachments.
// ---------------------------------------------------------------------------

type Device = Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>;

/** One more small segment: one update of one record. */
async function grow(d: Device, count: number, from = 0) {
  for (let i = from; i < from + count; i++) {
    await d.run(`run-g${i}`, [{ stream: sName(0), id: "x", v: i }], {
      full: false,
      covered: [sName(0)],
      observedAt: 2000 + i,
    });
    await d.cycle();
  }
}

/** Whether this device's next publish would compact: the library's own rule. */
async function compactionDue(d: Device): Promise<boolean> {
  const [row] = await d.db.query<{ refs: string; snapshot: string | null }>(
    "SELECT refs, snapshot FROM log_state WHERE connection_id = ?",
    [CONNECTION_ID],
  );
  const refs = JSON.parse(row!.refs) as { bytes: number }[];
  const snapshot = row!.snapshot
    ? (JSON.parse(row!.snapshot) as { parts: { bytes: number }[] })
    : null;
  return shouldCompact({
    tailSegments: refs.length,
    tailBytes: refs.reduce((n, r) => n + r.bytes, 0),
    snapshotBytes: snapshot?.parts.reduce((n, p) => n + p.bytes, 0) ?? 0,
  });
}

type Stamp = { o: number; r: string };
type OracleKey = {
  upsert: { stamp: Stamp; value: unknown; firstSeen: number | null } | null;
  /** The greatest deletion: an explicit delete, or a completion's cutoff. */
  deletion: { stamp: Stamp; explicit: boolean } | null;
};

/**
 * The fold of a prefix, written independently of `foldLog`, as a map from key
 * to what a snapshot must say about it: the winning upsert (with the first-seen
 * it carries) and the deletion frontier when it erased something. Order of ranks, as the model has it: an
 * omission at a stamp ranks below an observation at that stamp; an explicit
 * delete at that stamp ranks above it.
 */
function oracleFold(segments: readonly Segment[]) {
  const after = (x: Stamp, y: Stamp) => x.o > y.o || (x.o === y.o && x.r > y.r);
  const same = (x: Stamp, y: Stamp) => x.o === y.o && x.r === y.r;
  const keys = new Map<string, OracleKey>();
  const at = (stream: string, pk: string) => {
    const key = `${stream}/${pk}`;
    if (!keys.has(key)) keys.set(key, { upsert: null, deletion: null });
    return keys.get(key)!;
  };
  const deleted = (c: OracleKey, stamp: Stamp, explicit: boolean) => {
    const d = c.deletion;
    if (
      !d ||
      after(stamp, d.stamp) ||
      (same(stamp, d.stamp) && explicit && !d.explicit)
    )
      c.deletion = { stamp, explicit };
  };
  for (const g of segments)
    for (const op of g.operations) {
      if (op.kind === "upsert") {
        const c = at(op.stream, op.pkHash);
        if (!c.upsert || after(op.stamp, c.upsert.stamp))
          c.upsert = {
            stamp: op.stamp,
            value: op.value,
            firstSeen: op.firstSeen,
          };
      } else if (op.kind === "delete")
        deleted(at(op.stream, op.pkHash), op.stamp, true);
      else
        for (const pk of op.omitted)
          deleted(at(op.stream, pk), op.cutoff, false);
    }
  const out = new Map<
    string,
    {
      upsert?: { stamp: Stamp; value: unknown; firstSeen: number | null };
      tombstone?: { kind: "delete" | "omitted"; stamp: Stamp };
    }
  >();
  for (const [key, c] of keys) {
    const d = c.deletion;
    const survives =
      c.upsert !== null &&
      (!d ||
        after(c.upsert.stamp, d.stamp) ||
        (same(c.upsert.stamp, d.stamp) && !d.explicit));
    const entry: typeof out extends Map<string, infer V> ? V : never = {};
    if (survives) {
      entry.upsert = c.upsert!;
      // Only a deletion the winner is strictly after has erased anything older.
      if (d && after(c.upsert!.stamp, d.stamp))
        entry.tombstone = {
          kind: d.explicit ? "delete" : "omitted",
          stamp: d.stamp,
        };
    } else if (d) {
      entry.tombstone = {
        kind: d.explicit ? "delete" : "omitted",
        stamp: d.stamp,
      };
    }
    out.set(key, entry);
  }
  return out;
}

/** What the parts of a snapshot say, in the oracle's shape. */
const entriesOf = (parts: readonly SnapshotPart[]) => {
  const out = new Map<
    string,
    {
      upsert?: { stamp: Stamp; value: unknown; firstSeen: number | null };
      tombstone?: { kind: "delete" | "omitted"; stamp: Stamp };
    }
  >();
  for (const part of parts)
    for (const e of part.entries as readonly LogEntry[]) {
      const key = `${e.stream}/${e.pkHash}`;
      const cell = out.get(key) ?? {};
      if (e.kind === "upsert")
        cell.upsert = {
          stamp: e.stamp,
          value: e.value,
          firstSeen: e.firstSeen,
        };
      else cell.tombstone = { kind: e.kind, stamp: e.stamp };
      out.set(key, cell);
    }
  return out;
};

/** A log with an early deletion, grown until it has compacted once. */
async function compactedWorld() {
  const w = await world({ streams: 2, logProtocol: true });
  const a = await w.device("a");
  const b = await w.device("b");
  const m = await w.device("m");
  await a.run(
    "run-1",
    [
      { stream: sName(0), id: "x", v: 0 },
      { stream: sName(0), id: "y" },
      { stream: sName(1), id: "z" },
    ],
    { observedAt: 1100 },
  );
  await a.cycle();
  // b and m hold x, y and z at position 1 and then stay behind.
  await b.cycle();
  await m.cycle();
  await a.run("run-2", [{ stream: sName(0), id: "y", remove: true }], {
    full: false,
    covered: [sName(0)],
    observedAt: 1200,
  });
  await a.cycle();
  // z: observed at 1100 (in run-1), deleted at 1300, observed again at 1400.
  await a.run("run-3", [{ stream: sName(1), id: "z", remove: true }], {
    full: false,
    covered: [sName(1)],
    observedAt: 1300,
  });
  await a.cycle();
  await a.run("run-4", [{ stream: sName(1), id: "z", v: 4 }], {
    full: false,
    covered: [sName(1)],
    observedAt: 1400,
  });
  await a.cycle();
  await grow(a, 40);
  const segments = await w.segments();
  const head = segments.get(Math.max(...segments.keys()))!;
  return { w, a, b, m, segments, head };
}

describe("log protocol: compaction", () => {
  it("P4: a snapshot is the fold of its prefix, tombstones included; a snapshot that drops them breaks P1", async () => {
    const { w, a, b, m, segments, head } = await compactedWorld();
    expect(head.snapshot).not.toBeNull();
    const p = head.snapshot!.position;
    expect(head.base).toBe(p);
    expect(head.refs.every((r) => r.position > p)).toBe(true);

    const prefix = [...segments.values()].filter((g) => g.position <= p);
    const parts = await w.snapshotParts(head);
    const snapshot = entriesOf(parts);
    expect(snapshot).toEqual(oracleFold(prefix));
    // y was deleted before the snapshot: its tombstone is in it.
    expect(snapshot.get(`${sName(0)}/${await idHash("y")}`)).toMatchObject({
      tombstone: { kind: "delete" },
    });

    // A reader that was behind the snapshot and holds y converges (P1).
    expect((await b.records()).some((r) => r.includes('"id":"y"'))).toBe(true);
    await b.cycle();
    expect(await b.rows()).toEqual(await a.rows());
    expect((await b.records()).some((r) => r.includes('"id":"y"'))).toBe(false);

    // The mutant: the same snapshot with its deletions dropped. The same kind
    // of reader keeps y, so it no longer equals the caught-up reader.
    for (const part of parts)
      await applySnapshotPart(m.deps, CONNECTION_ID, {
        ...part,
        entries: part.entries.filter((e) => e.kind === "upsert"),
      });
    for (const position of [...segments.keys()].sort((x, y) => x - y))
      if (position > p)
        await applySegmentOperations(
          m.deps,
          CONNECTION_ID,
          segments.get(position)!,
        );
    const mutant = await m.records();
    expect(mutant).not.toEqual(await a.records());
    expect(mutant.some((r) => r.includes('"id":"y"'))).toBe(true);
  });

  it("P1: a reader at 0 installs the snapshot and the tail, and equals a caught-up reader", async () => {
    const { w, a, head } = await compactedWorld();
    const c = await w.device("c");
    await c.cycle();
    expect(await c.records()).toEqual(await a.records());
    expect(await c.position()).toBe(head.position);

    // It fetched the snapshot's parts and only the segments after the base.
    const keys = await w.segmentKeys();
    const folded = [...keys].filter(([position]) => position <= head.base);
    expect(folded.length).toBeGreaterThan(0);
    expect(c.gets.some((k) => k.includes(`${LOG}/q-`))).toBe(true);
    for (const [, key] of folded) expect(c.gets).not.toContain(key);
    expect(c.gets.filter((k) => k.includes(`${LOG}/s-`))).toHaveLength(
      head.position - head.base,
    );
  });

  it("a compaction races a writer's commit: the compare-and-set on the head decides, and every device converges", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    let armed = false;
    let raced = 0;
    const b = await w.device("b");
    const a = await w.device("a", true, {
      beforePut: async (key) => {
        if (!armed || !key.includes(`${LOG}/q-`)) return;
        armed = false;
        raced++;
        // Another writer commits at the position `a` is about to take.
        await b.run("run-b", [{ stream: sName(1), id: "from-b" }], {
          full: false,
          covered: [sName(1)],
          observedAt: 9000,
        });
        await b.cycle();
      },
    });
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    await b.cycle();
    for (let i = 0; !(await compactionDue(a)); i++) {
      expect(i).toBeLessThan(60);
      await grow(a, 1, i);
    }
    const before = Math.max(...(await w.segments()).keys());
    armed = true;
    await a.run("run-a", [{ stream: sName(0), id: "x", v: 99 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 9500,
    });
    await a.cycle();
    expect(raced).toBe(1); // `a` built its compaction and uploaded its parts

    // `a` also PUT a segment for position before+1 before it lost the compare-
    // and-set; that blob is an orphan. The chain is what the final head's refs
    // name, not every blob in the store.
    const all = await w.segments();
    const loser = all.get(before + 2)!;
    const winnerRef = loser.refs.find((r) => r.position === before + 1)!;
    const winner = decodeSegment(
      (await w.innerBlobs.get(`${LOG}/s-${winnerRef.dataHash.slice(2)}`))!,
    );
    if (winner.kind !== "ok") throw new Error("winner did not decode");
    const won = winner.segment;
    expect(Math.max(...all.keys())).toBe(before + 2);
    expect(won.operations.some((o) => o.stream === sName(1))).toBe(true);
    expect(loser.operations.some((o) => o.stream === sName(1))).toBe(false);
    // Both sides folded the same prefix, so both name the same snapshot, and
    // no other compaction exists in the chain.
    expect(won.snapshot?.position).toBe(before);
    expect(loser.base).toBe(before);
    expect(loser.snapshot).toEqual(won.snapshot);
    expect(loser.refs.map((r) => r.position)).toEqual([before + 1]);

    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    const records = await a.records();
    expect(await b.records()).toEqual(records);
    expect(await c.records()).toEqual(records);
    expect(records).toContain(`${sName(0)}/x={"id":"x","v":99}`);
    expect(records.some((r) => r.includes("from-b"))).toBe(true);
  });
});

describe("log protocol: size splitting", () => {
  it("a batch over the part target is written as several whole segments, in order, in rounds", async () => {
    const target = 3000;
    const w = await world({
      streams: 6,
      logProtocol: true,
      partTargetBytes: target,
    });
    const reader = await w.device("reader");
    let segmentPuts = 0;
    let midway: string[] | null = null;
    let midwayPosition = -1;
    const a = await w.device("a", true, {
      beforePut: async (key) => {
        if (!key.includes(`${LOG}/s-`) || ++segmentPuts !== 2) return;
        // Segment 1 is committed and segment 2 is not: a reader here sees
        // exactly one whole segment.
        await reader.cycle();
        midway = await reader.records();
        midwayPosition = await reader.position();
      },
    });
    const records = Array.from({ length: 6 }, (_, i) => [
      { stream: sName(i), id: `r${i}-1`, pad: 500 },
      { stream: sName(i), id: `r${i}-2`, pad: 500 },
    ]).flat();
    await a.run("run-1", records);
    await a.cycle();

    const segments = await w.segments();
    const positions = [...segments.keys()].sort((x, y) => x - y);
    expect(positions.length).toBeGreaterThan(2);
    expect(positions).toEqual(positions.map((_, i) => i + 1));
    expect(await a.position()).toBe(positions.length);
    expect(w.writes().batches).toBe(positions.length);
    // One commit per segment, at consecutive versions.
    expect(
      w.gateway.batches().map((b) => b.body.rows.map((r) => r.expectedVersion)),
    ).toEqual(positions.map((p) => [String(p)]));

    // Streams go in order, each in exactly one segment, none split.
    const order = positions.flatMap((p) =>
      segments.get(p)!.streams.map((m) => m.stream),
    );
    expect(order).toEqual(w.names);
    for (const p of positions) {
      const g = segments.get(p)!;
      expect(g.streams.length).toBeLessThan(6);
      for (const m of g.streams)
        expect(
          g.operations.filter(
            (o) => o.kind === "upsert" && o.stream === m.stream,
          ),
        ).toHaveLength(2);
    }

    // Mid-way, the reader had position 1 and exactly segment 1's records.
    const first = segments.get(1)!;
    expect(midwayPosition).toBe(1);
    expect(midway).toEqual(
      first.operations
        .flatMap((o) =>
          o.kind === "upsert"
            ? [
                `${o.stream}/${(o.value as { id: string }).id}=${JSON.stringify(o.value)}`,
              ]
            : [],
        )
        .sort(),
    );
    await reader.cycle();
    expect(await reader.records()).toEqual(await a.records());
    expect(await reader.records()).toHaveLength(12);
    expect(await reader.position()).toBe(positions.length);
  });
});

describe("log protocol: attachments", () => {
  const bytes = new Uint8Array(5000).fill(7);
  const hash = Buffer.from(sha256(bytes)).toString("hex");

  it("a blob uploaded with a log-mode publish is readable on another device", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run(
      "run-1",
      [{ stream: sName(0), id: "m", blobId: `sha256:${hash}` }],
      {
        blob: { hash, bytes },
      },
    );
    await a.cycle();
    const key = `${streamScope(CONNECTOR, "", sName(0))}/g1-b-${hash}`;
    expect(a.puts).toContain(key);
    // The blob went up before the segment that names its record.
    expect(a.puts.indexOf(key)).toBeLessThan(
      a.puts.findIndex((k) => k.includes(`${LOG}/s-`)),
    );
    await b.cycle();
    expect(new Uint8Array((await b.sync.blobs.get(hash))!.bytes)).toEqual(
      bytes,
    );
  });

  it("bytes that arrive after their records were published are uploaded by the next pass", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", [
      { stream: sName(0), id: "m", blobId: `sha256:${hash}` },
    ]);
    await a.cycle();
    await b.cycle();
    expect(await b.sync.blobs.get(hash)).toBeNull();
    await a.sync.blobs.put({
      runId: "run-1",
      sha256: hash,
      mimeType: "application/octet-stream",
      bytes,
    });
    await a.cycle();
    expect(w.writes().batches).toBe(1); // no new segment: the records are unchanged
    expect(new Uint8Array((await b.sync.blobs.get(hash))!.bytes)).toEqual(
      bytes,
    );
  });
});

// ---------------------------------------------------------------------------
// Review fixes: boundary kinds, rolled-back registry, deletion frontier.
// ---------------------------------------------------------------------------

/** A segment built by hand: operations against stream `s0`, applied directly. */
async function crafted(
  position: number,
  operations: Segment["operations"],
): Promise<Segment> {
  const hash = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as const;
  return {
    format: 1,
    connector: CONNECTOR,
    ns: "",
    generation: 1,
    keyCheck: "0123456789abcdef",
    position,
    observedAt: 5000,
    base: 0,
    snapshot: null,
    refs: Array.from({ length: position - 1 }, (_, i) => ({
      position: i + 1,
      dataHash: hash(i + 1),
      bytes: 100,
    })),
    streams: [
      {
        stream: sName(0),
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
        complete: true,
      },
    ],
    operations,
  };
}

/** A reader that has joined the connection (so its rows can be written) and nothing else. */
async function joined(w: Awaited<ReturnType<typeof world>>, id: string) {
  const d = await w.device(id);
  await d.cycle();
  return d;
}

describe("log protocol: boundary kinds at equal stamps (P2-1)", () => {
  const S = { o: 5000, r: "run-k" };
  const kept = (d: Device) =>
    d.records().then((rs) => rs.some((r) => r.includes('"id":"k"')));

  const seeded = async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "seed" }], {
      observedAt: 1100,
    });
    await a.cycle();
    return w;
  };
  const upsertK = async () => ({
    kind: "upsert" as const,
    stream: sName(0),
    pkHash: await idHash("k"),
    stamp: S,
    firstSeen: 5000,
    value: { id: "k" },
  });
  const omitK = async () => ({
    kind: "complete" as const,
    stream: sName(0),
    cutoff: S,
    omitted: [await idHash("k")],
  });
  const deleteK = async () => ({
    kind: "delete" as const,
    stream: sName(0),
    pkHash: await idHash("k"),
    stamp: S,
  });

  for (const order of ["upsert first", "omission first", "repeated"] as const) {
    it(`an omission at the stamp of an observation does not remove it (${order})`, async () => {
      const w = await seeded();
      const m = await joined(w, "m");
      const up = await crafted(2, [await upsertK()]);
      const om = await crafted(3, [await omitK()]);
      const steps =
        order === "upsert first"
          ? [up, om]
          : order === "omission first"
            ? [om, up]
            : [up, om, up, om, om, up];
      for (const g of steps)
        await applySegmentOperations(m.deps, CONNECTION_ID, g);
      expect(await kept(m)).toBe(true);
    });

    it(`an explicit delete at the stamp of an observation removes it (${order})`, async () => {
      const w = await seeded();
      const m = await joined(w, "m");
      const up = await crafted(2, [await upsertK()]);
      const del = await crafted(3, [await deleteK()]);
      const steps =
        order === "upsert first"
          ? [up, del]
          : order === "omission first"
            ? [del, up]
            : [up, del, up, del, del, up];
      for (const g of steps)
        await applySegmentOperations(m.deps, CONNECTION_ID, g);
      expect(await kept(m)).toBe(false);
    });
  }

  it("an explicit delete and an omission at one stamp remove the record, in any order", async () => {
    const w = await seeded();
    for (const order of [0, 1]) {
      const m = await joined(w, `m${order}`);
      const steps = [
        await crafted(2, [await upsertK()]),
        await crafted(3, [await omitK()]),
        await crafted(4, [await deleteK()]),
      ];
      if (order === 1) steps.reverse();
      for (const g of steps)
        await applySegmentOperations(m.deps, CONNECTION_ID, g);
      expect(await kept(m)).toBe(false);
    }
  });
});

describe("log protocol: a registry that is behind or on another history fails closed (P2-2)", () => {
  /** a writes an insert (position 1) and a delete (position 2); b applies both. */
  const history = async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run(
      "run-1",
      [
        { stream: sName(0), id: "x" },
        { stream: sName(0), id: "y" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await a.run("run-2", [{ stream: sName(0), id: "y", remove: true }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1200,
    });
    await a.cycle();
    await b.cycle();
    expect(await b.position()).toBe(2);
    return { w, a, b };
  };

  it("a registry rolled back below the applied position is not read as caught up", async () => {
    const { w, b } = await history();
    const before = { rows: await b.rows(), position: await b.position() };
    w.gateway.versions.get(LOG)!.pop(); // the registry is at position 1 again
    await expect(b.cycle()).rejects.toThrow(/behind this device/);
    expect(await b.position()).toBe(before.position);
    expect(await b.rows()).toEqual(before.rows);
  });

  it("the same position under a different segment is not read as caught up", async () => {
    const { w, b } = await history();
    const before = { rows: await b.rows(), position: await b.position() };
    w.gateway.versions.get(LOG)!.pop();
    // Another device continues the rolled-back log with its own segment 2.
    const c = await w.device("c");
    await c.cycle();
    await c.run("run-c", [{ stream: sName(0), id: "from-c" }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1300,
    });
    await c.cycle();
    expect(await c.position()).toBe(2);
    await expect(b.cycle()).rejects.toThrow(/different segment/);
    expect(await b.position()).toBe(before.position);
    expect(await b.rows()).toEqual(before.rows);
  });
});

describe("log protocol: a resurrection after a deletion (P2-3)", () => {
  it("a lagging, a fresh and an uninterrupted reader agree on every column, first-seen included", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a");
    const lagging = await w.device("lagging");
    const uninterrupted = await w.device("uninterrupted");
    const step = async () => {
      await a.cycle();
      await uninterrupted.cycle();
    };
    await a.run(
      "run-1",
      [
        { stream: sName(0), id: "x", v: 0 },
        { stream: sName(1), id: "z" },
      ],
      { observedAt: 1100 },
    );
    await step();
    await lagging.cycle(); // holds z, first seen at 1100, and stops here
    await a.run("run-2", [{ stream: sName(1), id: "z", remove: true }], {
      full: false,
      covered: [sName(1)],
      observedAt: 1300,
    });
    await step();
    await a.run("run-3", [{ stream: sName(1), id: "z", v: 4 }], {
      full: false,
      covered: [sName(1)],
      observedAt: 1400,
    });
    await step();
    for (let i = 0; i < 40; i++) {
      await grow(a, 1, i);
      await uninterrupted.cycle();
    }
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    expect(head.snapshot).not.toBeNull();

    // The snapshot says what the oracle says, the deletion frontier included.
    const prefix = [...segments.values()].filter(
      (g) => g.position <= head.snapshot!.position,
    );
    const parts = await w.snapshotParts(head);
    expect(entriesOf(parts)).toEqual(oracleFold(prefix));
    const z = entriesOf(parts).get(`${sName(1)}/${await idHash("z")}`)!;
    expect(z.tombstone).toMatchObject({ kind: "delete", stamp: { o: 1300 } });
    expect(z.upsert?.firstSeen).toBe(1400);

    const fresh = await w.device("fresh");
    await fresh.cycle();
    await lagging.cycle();
    const caughtUp = await uninterrupted.rows();
    expect(await a.rows()).toEqual(caughtUp);
    expect(await fresh.rows()).toEqual(caughtUp);
    expect(await lagging.rows()).toEqual(caughtUp);
    const row = caughtUp
      .map((r) => JSON.parse(r) as { record_key: string; first_o: number })
      .find((r) => r.record_key === "z")!;
    expect(row.first_o).toBe(1400);
  });

  it("a deletion and its resurrection in one segment give the resurrection's first-seen, as two segments do", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "seed" }], {
      observedAt: 1100,
    });
    await a.cycle();
    const K = await idHash("k");
    const upsert = (o: number) => ({
      kind: "upsert" as const,
      stream: sName(0),
      pkHash: K,
      stamp: { o, r: `run-${o}` },
      firstSeen: o,
      value: { id: "k" },
    });
    const remove = {
      kind: "delete" as const,
      stream: sName(0),
      pkHash: K,
      stamp: { o: 6000, r: "run-6000" },
    };
    const separate = await joined(w, "separate");
    const together = await joined(w, "together");
    for (const d of [separate, together])
      await applySegmentOperations(
        d.deps,
        CONNECTION_ID,
        await crafted(2, [upsert(5000)]),
      );
    await applySegmentOperations(
      separate.deps,
      CONNECTION_ID,
      await crafted(3, [remove]),
    );
    await applySegmentOperations(
      separate.deps,
      CONNECTION_ID,
      await crafted(4, [upsert(7000)]),
    );
    await applySegmentOperations(
      together.deps,
      CONNECTION_ID,
      await crafted(3, [remove, upsert(7000)]),
    );
    const firstSeen = async (d: Device) =>
      (
        await d.db.query<{ first_o: number }>(
          "SELECT first_o FROM records WHERE record_key = 'k'",
        )
      )[0]!.first_o;
    expect(await firstSeen(separate)).toBe(7000);
    expect(await firstSeen(together)).toBe(7000);
  });
});

describe("log protocol: first-seen travels with the winning observation (P2-a, P2-b)", () => {
  // `first_o` is read by `/additions` (the day a record arrived) and by nothing
  // else: no merge, delete or publish decision depends on it. The rule that
  // every reader can compute from the log is that a record's first-seen is the
  // one its winning observation carries (NULL when that observation's is
  // unknown). A late delete never touches a row that outlives it, and a
  // snapshot, which keeps the winner, keeps its first-seen.
  type Obs =
    { kind: "u"; o: number; f: number | null } | { kind: "d"; o: number };
  const U = (o: number, f: number | null): Obs => ({ kind: "u", o, f });
  const D = (o: number): Obs => ({ kind: "d", o });

  const K = () => idHash("k");
  const operation = async (obs: Obs): Promise<Segment["operations"][number]> =>
    obs.kind === "u"
      ? {
          kind: "upsert",
          stream: sName(0),
          pkHash: await K(),
          stamp: { o: obs.o, r: `run-${obs.o}` },
          firstSeen: obs.f,
          value: { id: "k", v: obs.o },
        }
      : {
          kind: "delete",
          stream: sName(0),
          pkHash: await K(),
          stamp: { o: obs.o, r: `run-${obs.o}` },
        };
  const context = {
    connector: CONNECTOR,
    ns: "",
    generation: 1,
    keyCheck: "0123456789abcdef",
  };

  /** What the winning-observation rule says, written from the rule alone. */
  const expected = (log: readonly Obs[]) => {
    const upserts = log.filter((x): x is Obs & { kind: "u" } => x.kind === "u");
    const deletes = log.filter((x) => x.kind === "d");
    const winner = upserts.reduce<(typeof upserts)[number] | null>(
      (best, x) => (best === null || x.o > best.o ? x : best),
      null,
    );
    const frontier = Math.max(-1, ...deletes.map((x) => x.o));
    // An explicit delete at the winner's stamp outranks it.
    return winner !== null && winner.o > frontier ? winner : null;
  };

  const seeded = async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "seed" }], {
      observedAt: 1100,
    });
    await a.cycle();
    return w;
  };
  const kRow = async (d: Device) =>
    (await d.rows())
      .map(
        (r) => JSON.parse(r) as { record_key: string; first_o: number | null },
      )
      .filter((r) => r.record_key === "k");

  /** A reader that applies the log one segment at a time, in position order. */
  const sequential = async (
    w: Awaited<ReturnType<typeof world>>,
    id: string,
    log: readonly Obs[],
  ) => {
    const d = await joined(w, id);
    for (const [i, obs] of log.entries())
      await applySegmentOperations(
        d.deps,
        CONNECTION_ID,
        await crafted(i + 2, [await operation(obs)]),
      );
    return d;
  };
  /** A reader that installs the fold of `prefix`, then applies the rest. */
  const throughSnapshot = async (
    w: Awaited<ReturnType<typeof world>>,
    id: string,
    log: readonly Obs[],
    split: number,
  ) => {
    const d = await joined(w, id);
    const prefix = await Promise.all(
      log
        .slice(0, split)
        .map(async (obs, i) => await crafted(i + 2, [await operation(obs)])),
    );
    const fold = foldLog({ snapshot: [], segments: prefix });
    for (const part of partitionFold(fold, { ...context, position: split + 1 }))
      await applySnapshotPart(d.deps, CONNECTION_ID, part);
    for (const [i, obs] of log.slice(split).entries())
      await applySegmentOperations(
        d.deps,
        CONNECTION_ID,
        await crafted(split + i + 2, [await operation(obs)]),
      );
    return d;
  };

  it("P2-a: an unknown first-seen at the lower stamp does not outlast a later known one, in either order", async () => {
    const w = await seeded();
    for (const [name, log] of [
      ["unknown first", [U(10, null), U(30, 30)]],
      ["known first", [U(30, 30), U(10, null)]],
    ] as const) {
      const online = await sequential(w, `online-${name}`, log);
      const fresh = await throughSnapshot(w, `fresh-${name}`, log, log.length);
      expect(await kRow(online)).toMatchObject([{ first_o: 30 }]);
      expect(await online.rows()).toEqual(await fresh.rows());
    }
  });

  it("P2-a: a later observation whose first-seen is unknown makes it unknown for every reader", async () => {
    const w = await seeded();
    const log = [U(10, 10), U(30, null)];
    const online = await sequential(w, "online", log);
    const fresh = await throughSnapshot(w, "fresh", log, 2);
    expect(await kRow(online)).toMatchObject([{ first_o: null }]);
    expect(await online.rows()).toEqual(await fresh.rows());
  });

  it("P2-b: a late delete below a surviving row leaves its first-seen alone, for the online and the fresh reader", async () => {
    const w = await seeded();
    const log = [U(10, 10), U(30, 30), D(20)];
    const online = await sequential(w, "online", log);
    const prefixThenTail = await throughSnapshot(w, "prefix", log, 2);
    const fresh = await throughSnapshot(w, "fresh", log, 3);
    expect(await kRow(online)).toMatchObject([{ first_o: 30 }]);
    expect(await prefixThenTail.rows()).toEqual(await online.rows());
    expect(await fresh.rows()).toEqual(await online.rows());
  });

  it("every short history gives every reader the winning observation's first-seen", async () => {
    const w = await seeded();
    const alphabet = [
      U(10, null),
      U(10, 10),
      U(30, null),
      U(30, 30),
      D(15),
      D(25),
    ];
    // Every pair, and every triple over the three observations that matter
    // most: an old unknown, a later known, and a delete between them.
    const triple = [U(10, null), U(30, 30), D(20)];
    const logs: Obs[][] = [];
    for (const x of alphabet) {
      logs.push([x]);
      for (const y of alphabet) logs.push([x, y]);
    }
    for (const x of triple)
      for (const y of triple) for (const z of triple) logs.push([x, y, z]);
    let n = 0;
    for (const log of logs) {
      const tag = `h${n++}`;
      const online = await sequential(w, `${tag}-online`, log);
      const want = expected(log);
      expect(
        (await kRow(online)).map((r) => r.first_o),
        JSON.stringify(log),
      ).toEqual(want === null ? [] : [want.f]);
      for (let split = 0; split <= log.length; split++) {
        const reader = await throughSnapshot(w, `${tag}-${split}`, log, split);
        expect(
          await reader.rows(),
          `${JSON.stringify(log)} split ${split}`,
        ).toEqual(await online.rows());
      }
    }
  }, 120_000);
});

describe("log protocol: the log noop shortcut and unresolved partial state", () => {
  // With the log on, a stream the log wrote reads from a local version above the
  // registry's own stream row, and the apply of that stream answers noop without
  // reading it. That answer says nothing about rows an earlier failed apply of a
  // newer per-stream head merged: neither the per-stream head nor the log holds
  // them. So it must not count as proof that the stream is repaired.
  it("a partial per-stream apply, the per-stream registry back at an older version, and an unchanged log: the mark stays and nothing claims a repair", async () => {
    const w = await world({
      streams: 1,
      logProtocol: false,
      partTargetBytes: 400,
    });
    const s0 = streamScope(CONNECTOR, "", sName(0));
    const rowsLocal = async (d: Device) =>
      (
        await d.db.query<{ record_key: string }>(
          "SELECT record_key FROM records WHERE stream = ?",
          [sName(0)],
        )
      ).map((r) => r.record_key);
    const state = async (d: Device) =>
      (
        await d.db.query<{ head_version: number; apply_partial: number }>(
          `SELECT s.head_version, c.apply_partial FROM stream_state s
             JOIN connections c ON c.connection_id = s.connection_id
            WHERE s.stream = ?`,
          [sName(0)],
        )
      )[0]!;

    // The per-stream registry holds version 1.
    const legacy = await w.device("legacy", false);
    await legacy.run("run-1", [{ stream: sName(0), id: "a" }]);
    await legacy.cycle();

    // This device reads version 1, then the log carries it to local version 3.
    const b = await w.device("b", true);
    await b.cycle();
    for (const id of ["b1", "b2"]) {
      await b.run(`run-${id}`, [{ stream: sName(0), id }], {
        full: false,
        covered: [sName(0)],
      });
      await b.cycle();
    }
    expect((await state(b)).head_version).toBe(3);
    const logRows = await rowsLocal(b);
    expect(logRows).toEqual(expect.arrayContaining(["a", "b1", "b2"]));

    // The per-stream registry grows to version 4 with many rows in many parts.
    for (let i = 0; i < 3; i++) {
      await legacy.run(
        `run-L${i}`,
        Array.from({ length: 12 }, (_, j) => ({
          stream: sName(0),
          id: `x${i}-${j}`,
          pad: 60,
        })),
        { full: false, covered: [sName(0)] },
      );
      await legacy.cycle();
    }
    expect(w.gateway.rowsOf(s0)).toBe(4);

    // Applying it merges some parts and then a part download fails.
    const get = b.deps.blobs.get.bind(b.deps.blobs);
    let parts = 0;
    b.deps.blobs.get = async (key) => {
      if (key.startsWith(`${s0}/`) && key.includes("-p-") && ++parts === 3)
        throw new Error("part blob transfer failed");
      return get(key);
    };
    await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow(
      "part blob transfer failed",
    );
    b.deps.blobs.get = get;
    expect(await state(b)).toEqual({ head_version: 3, apply_partial: 1 });
    const merged = (await rowsLocal(b)).filter((k) => k.startsWith("x"));
    expect(merged.length).toBeGreaterThan(0);

    // The per-stream registry goes back to version 1; the log has not moved.
    const rows = w.gateway.versions.get(s0)!;
    while (rows.length > 1) rows.pop();
    await applyConnection(b.deps, CONNECTION_ID);

    // Rows the version-4 head merged are in neither source, and the mark says so.
    expect(await state(b)).toEqual({ head_version: 3, apply_partial: 1 });
    expect((await rowsLocal(b)).filter((k) => k.startsWith("x"))).toEqual(
      merged,
    );
    // The log's own state is intact.
    expect(await rowsLocal(b)).toEqual(expect.arrayContaining(logRows));
  }, 60_000);
});
