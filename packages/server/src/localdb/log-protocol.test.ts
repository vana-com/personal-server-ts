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
  deriveKeyCheck,
  logScope,
  pkHash,
  streamScope,
  type Segment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import {
  applySegmentOperations,
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

async function world(options: { streams: number; logProtocol: boolean }) {
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

  async function device(deviceId: string, logProtocol = options.logProtocol) {
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
        remove?: boolean;
      }[],
      opts: {
        covered?: readonly string[];
        full?: boolean;
        observedAt?: number;
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
        records: records.map(({ stream, id, v, remove }) => ({
          stream,
          ...(remove ? { op: "delete" as const } : {}),
          data: v === undefined ? { id } : { id, v },
        })),
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

  it.todo(
    "P4: a compacted snapshot keeps the latest winner per key, including tombstones (compaction is a later slice)",
  );

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
