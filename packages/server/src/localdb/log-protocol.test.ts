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
  type LogEntry,
  type Segment,
  type SnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
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
    const position = async () =>
      (
        await db.query<{ position: number }>(
          "SELECT position FROM log_state WHERE connection_id = ?",
          [CONNECTION_ID],
        )
      )[0]?.position ?? 0;
    return { db, deps, sync, run, cycle, records, position, puts, gets };
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

    // Ahead of the registry (a restored registry): replay from the start.
    await b.db.batch([
      {
        sql: "UPDATE log_state SET position = 9 WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
    ]);
    const before = b.gets.length;
    await b.cycle();
    expect(await b.position()).toBe(1);
    expect(b.gets.slice(before).some((k) => k.startsWith(`${LOG}/s-`))).toBe(
      true,
    );

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

/**
 * The fold of a prefix, written independently of `foldLog`: per key the
 * greatest upsert and the greatest deletion (an explicit delete, or the cutoff
 * of a completion that omitted the key); the upsert wins only if strictly
 * after the deletion.
 */
function oracleFold(segments: readonly Segment[]) {
  const after = (x: { o: number; r: string }, y: { o: number; r: string }) =>
    x.o > y.o || (x.o === y.o && x.r > y.r);
  const best = new Map<
    string,
    {
      up?: { stamp: { o: number; r: string }; value: unknown };
      del?: { o: number; r: string };
    }
  >();
  const at = (stream: string, pk: string) => {
    const key = `${stream}/${pk}`;
    if (!best.has(key)) best.set(key, {});
    return best.get(key)!;
  };
  for (const g of segments)
    for (const op of g.operations) {
      if (op.kind === "upsert") {
        const c = at(op.stream, op.pkHash);
        if (!c.up || after(op.stamp, c.up.stamp))
          c.up = { stamp: op.stamp, value: op.value };
      } else if (op.kind === "delete") {
        const c = at(op.stream, op.pkHash);
        if (!c.del || after(op.stamp, c.del)) c.del = op.stamp;
      } else
        for (const pk of op.omitted) {
          const c = at(op.stream, pk);
          if (!c.del || after(op.cutoff, c.del)) c.del = op.cutoff;
        }
    }
  const out = new Map<string, unknown>();
  for (const [key, c] of best)
    if (c.up && (!c.del || after(c.up.stamp, c.del)))
      out.set(key, { kind: "upsert", stamp: c.up.stamp, value: c.up.value });
    else if (c.del) out.set(key, { kind: "delete", stamp: c.del });
  return out;
}

const entriesOf = (parts: readonly SnapshotPart[]) => {
  const out = new Map<string, unknown>();
  for (const part of parts)
    for (const e of part.entries as readonly LogEntry[])
      out.set(
        `${e.stream}/${e.pkHash}`,
        e.kind === "upsert"
          ? { kind: "upsert", stamp: e.stamp, value: e.value }
          : { kind: "delete", stamp: e.stamp },
      );
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
      kind: "delete",
    });

    // A reader that was behind the snapshot and holds y converges (P1).
    expect((await b.records()).some((r) => r.includes('"id":"y"'))).toBe(true);
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
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
