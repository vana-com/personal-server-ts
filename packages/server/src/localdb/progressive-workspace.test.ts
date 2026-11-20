import { afterEach, expect, it } from "vitest";
import {
  foldLog,
  canonicalJson,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyLog } from "../../../core/src/localdb/log-apply.js";
import { closeWorldDrivers, CONNECTION_ID } from "./log-world.test-utils.js";
import { progressiveScenario as scenario } from "./progressive-workspace.test-utils.js";
afterEach(closeWorldDrivers);
it("holds a key removed in a later snapshot part until a later part writes it again", async () => {
  const { b, parts, head, context } = await scenario();
  const visible: number[][] = [];
  const batch = b.db.batch.bind(b.db);
  b.db.batch = async (statements) => {
    const result = await batch(statements);
    if (
      statements.some(
        (s) =>
          (s.sql.includes("temp.incoming") && s.sql.startsWith("INSERT")) ||
          s.sql.startsWith("INSERT INTO workspace_receipts"),
      ) &&
      statements.some((s) =>
        s.sql.includes("INSERT OR REPLACE INTO stream_partial"),
      )
    ) {
      const rows = await b.db.query<{ stamp_o: number }>(
        "SELECT stamp_o FROM records r WHERE NOT EXISTS(SELECT 1 FROM partial_hidden h WHERE h.connection_id=r.connection_id AND h.stream=r.stream AND h.pk_hash=r.pk_hash)",
      );
      visible.push(rows.map((r) => r.stamp_o));
    }
    return result;
  };
  await applyLog(b.deps, CONNECTION_ID, context);
  expect(
    visible[0],
    "an early value must stay hidden across decoded-unit eviction",
  ).toEqual([]);
  expect(visible.some((v) => v.includes(30))).toBe(true);
  const expected = foldLog({
    snapshot: parts,
    segments: [head],
  }).entries.filter((e) => e.kind === "upsert");
  expect(
    (await b.db.query<{ body: string }>("SELECT body FROM records")).map((r) =>
      JSON.parse(r.body),
    ),
  ).toEqual(expected.map((e) => e.value));
});

it.each([0x12345678, 0xaabbccdd, 0x13579bdf])(
  "progressive disk replay agrees with foldLog for ties, omissions and resurrection: %s",
  async (seed) => {
    const { idHash } = await import("./log-world.test-utils.js");
    const hashes = await Promise.all([0, 1, 2, 3].map(idHash));
    let random = seed;
    const next = () => {
      random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
      return random;
    };
    const entries = Array.from({ length: 24 }, (_, i) => {
      const id = (next() >>> 16) % 4,
        kind = next() % 3,
        stamp = { o: 2000 + Math.floor(i / 4), r: `r${Math.floor(i / 4)}` };
      return [
        kind === 0
          ? {
              kind: "delete" as const,
              stream: "s0",
              pkHash: hashes[id]!,
              key: [id],
              stamp,
            }
          : kind === 1
            ? {
                kind: "omitted" as const,
                stream: "s0",
                pkHash: hashes[id]!,
                key: [id],
                stamp,
              }
            : {
                kind: "upsert" as const,
                stream: "s0",
                pkHash: hashes[id]!,
                stamp,
                ordinal: i % 2,
                firstSeen: i % 2 ? null : 100,
                value: { id, v: i, text: '\\"é' },
              },
      ];
    });
    const { b, parts, head, context } = await scenario(
      entries.length,
      false,
      entries,
    );
    await applyLog(b.deps, CONNECTION_ID, context);
    const expected = foldLog({ snapshot: parts, segments: [head] });
    const winners = expected.entries
      .filter((e) => e.kind === "upsert")
      .map((e) => ({
        pk_hash: e.pkHash,
        body: canonicalJson(e.value),
        stamp_o: e.stamp.o,
        stamp_r: e.stamp.r,
        stamp_n: e.ordinal ?? 0,
        first_o: e.firstSeen,
      }))
      .sort((a, b) => a.pk_hash.localeCompare(b.pk_hash));
    expect(
      await b.db.query(
        "SELECT pk_hash,body,stamp_o,stamp_r,stamp_n,first_o FROM records ORDER BY pk_hash",
      ),
    ).toEqual(winners);
    const deletions = expected.entries
      .filter((e) => e.kind !== "upsert")
      .map((e) => ({
        pk_hash: e.pkHash,
        stamp_o: e.stamp.o,
        stamp_r: e.stamp.r,
        rank: e.kind === "delete" ? 2 : 0,
      }))
      .sort((a, b) => a.pk_hash.localeCompare(b.pk_hash));
    const tombstones = await b.db.query(
      "SELECT t.pk_hash,t.stamp_o,t.stamp_r,t.rank FROM log_tombstones t WHERE NOT EXISTS(SELECT 1 FROM records r WHERE r.connection_id=t.connection_id AND r.stream=t.stream AND r.pk_hash=t.pk_hash AND (r.stamp_o,r.stamp_r,1)>(t.stamp_o,t.stamp_r,t.rank)) ORDER BY t.pk_hash",
    );
    const effective = deletions.filter(
      (d) =>
        !winners.some(
          (w) =>
            w.pk_hash === d.pk_hash &&
            (w.stamp_o > d.stamp_o ||
              (w.stamp_o === d.stamp_o &&
                (w.stamp_r > d.stamp_r ||
                  (w.stamp_r === d.stamp_r && 1 > d.rank)))),
        ),
    );
    expect(tombstones).toEqual(effective);
  },
);

it("a new registry head fences old removal facts before adopting another partial prefix", async () => {
  const { b, w, head, context } = await scenario();
  const { encodeSegment, digestSegment } =
    await import("@opendatalabs/personal-server-ts-stream-sync");
  const { keccak_256 } = await import("@noble/hashes/sha3");
  const { idHash, LOG } = await import("./log-world.test-utils.js");
  const batch = b.db.batch.bind(b.db);
  let stopAt = "partial-1";
  b.db.batch = async (statements) => {
    if (
      statements.some(
        (s) =>
          s.sql.startsWith("INSERT INTO workspace_receipts") &&
          s.params?.[1] === stopAt,
      )
    )
      throw new Error("stop prefix");
    return batch(statements);
  };
  await expect(applyLog(b.deps, CONNECTION_ID, context)).rejects.toThrow(
    "stop prefix",
  );
  expect(
    await b.db.query("SELECT parts_applied,failed FROM stream_partial"),
  ).toEqual([{ parts_applied: 1, failed: 1 }]);
  const previous = (
    await b.db.query<{ operation: string; binding: string }>(
      "SELECT operation,binding FROM workspaces",
    )
  )[0]!;
  const metadata = (
    await b.db.query<{
      network: string;
      device_id: string;
      created_at: number;
    }>("SELECT network,device_id,created_at FROM db_meta WHERE id=1")
  )[0]!;
  expect(JSON.parse(previous.binding)[1]).toBe(
    JSON.stringify([metadata.network, metadata.device_id, metadata.created_at]),
  );
  const changed = {
    ...head,
    operations: [
      {
        kind: "delete" as const,
        stream: "s0",
        pkHash: await idHash("k"),
        key: ["k"],
        stamp: { o: 100, r: "r" },
      },
    ],
  };
  const bytes = encodeSegment(changed);
  const digest = await digestSegment(async (bytes) => keccak_256(bytes), bytes);
  await w.innerBlobs.put(`${LOG}/${digest.blobName}`, bytes);
  const updated = {
    ...context,
    read: { ...context.read, dataHash: digest.dataHash },
  };
  stopAt = "partial-3";
  await expect(applyLog(b.deps, CONNECTION_ID, updated)).rejects.toThrow(
    "stop prefix",
  );
  expect(await b.db.query("SELECT stamp_o FROM records")).toEqual([
    { stamp_o: 30 },
  ]);
  expect(await b.db.query("SELECT pk_hash FROM partial_hidden")).toHaveLength(
    1,
  );
  const { openLogWorkspace } =
    await import("../../../core/src/localdb/workspace-consumer.js");
  const [
    owner,
    databaseIncarnation,
    connection,
    generation,
    keyCheck,
    operation,
    expectedHead,
    codecVersion,
  ] = JSON.parse(previous.binding);
  await expect(
    openLogWorkspace(b.db, {
      owner,
      databaseIncarnation,
      connection,
      generation,
      keyCheck,
      operation,
      expectedHead,
      codecVersion,
    }),
  ).rejects.toThrow();
  stopAt = "none";
  await applyLog(b.deps, CONNECTION_ID, updated);
  expect(await b.db.query("SELECT body FROM records")).toEqual([]);
  expect(await b.db.query("SELECT * FROM stream_partial")).toEqual([]);
});

it("corrupt prerequisite input leaves no applied receipt or complete marker and releases its lease", async () => {
  const { b, w, head, context } = await scenario();
  const { LOG } = await import("./log-world.test-utils.js");
  const key = `${LOG}/q-${head.snapshot!.parts[2]!.dataHash.slice(2)}`;
  const bytes = (await w.innerBlobs.get(key))!;
  await w.innerBlobs.put(key, new Uint8Array([1, 2, 3]));
  await expect(applyLog(b.deps, CONNECTION_ID, context)).rejects.toThrow(
    "invalid log snapshot part",
  );
  expect(await b.db.query("SELECT position FROM workspace_receipts")).toEqual(
    [],
  );
  expect(await b.db.query("SELECT body FROM records")).toEqual([]);
  expect(await b.db.query("SELECT complete FROM stream_state")).toEqual([
    { complete: 0 },
  ]);
  expect(
    await b.db.query("SELECT parts_applied,failed FROM stream_partial"),
  ).toEqual([{ parts_applied: 0, failed: 1 }]);
  await w.innerBlobs.put(key, bytes);
  await applyLog(b.deps, CONNECTION_ID, context);
  expect(await b.db.query("SELECT * FROM stream_partial")).toEqual([]);
});

it("resolves referenced bodies only in their application unit, after the snapshot prefix commits", async () => {
  const { b, w, head, parts, context } = await scenario();
  const { putBodiesOutOfLine } =
    await import("../../../core/src/localdb/log-bodies.js");
  const { encodeSegment, digestSegment } =
    await import("@opendatalabs/personal-server-ts-stream-sync");
  const { keccak_256 } = await import("@noble/hashes/sha3");
  const { LOG, idHash } = await import("./log-world.test-utils.js");
  const value = { id: "large", pad: "x".repeat(4096) };
  const bodies = await putBodiesOutOfLine(
    b.deps,
    LOG,
    [
      {
        kind: "upsert" as const,
        stream: "s0",
        pkHash: await idHash("large"),
        stamp: { o: 200, r: "r" },
        firstSeen: null,
        value,
      },
    ],
    128,
  );
  const pieceKeys = new Set(
    bodies.pieces.map((piece) => `${LOG}/${piece.name}`),
  );
  for (const piece of bodies.pieces)
    await w.innerBlobs.put(`${LOG}/${piece.name}`, piece.cipher);
  const changed = { ...head, operations: bodies.ops };
  const bytes = encodeSegment(changed),
    digest = await digestSegment(async (bytes) => keccak_256(bytes), bytes);
  await w.innerBlobs.put(`${LOG}/${digest.blobName}`, bytes);
  const get = b.deps.blobs.get.bind(b.deps.blobs);
  let observed = false;
  b.deps.blobs.get = async (key) => {
    if (!observed && pieceKeys.has(key)) {
      observed = true;
      expect(
        await b.db.query("SELECT count(*) n FROM workspace_receipts"),
      ).toEqual([{ n: parts.length }]);
    }
    return get(key);
  };
  await applyLog(b.deps, CONNECTION_ID, {
    ...context,
    read: { ...context.read, dataHash: digest.dataHash },
  });
  expect(observed).toBe(true);
  expect(
    (await b.db.query<{ body: string }>("SELECT body FROM records")).map(
      (row) => JSON.parse(row.body),
    ),
  ).toContainEqual(value);
});

it("restores the same registry head after its former workspace has been reclaimed", async () => {
  const { b, context } = await scenario();
  await applyLog(b.deps, CONNECTION_ID, context);
  const before = await b.db.query("SELECT body FROM records");
  await b.db.batch([
    { sql: "UPDATE write_ctx SET origin='remote' WHERE id=1" },
    { sql: "DELETE FROM records" },
    { sql: "DELETE FROM log_state" },
    { sql: "UPDATE stream_state SET complete=0" },
  ]);
  await applyLog(b.deps, CONNECTION_ID, context);
  expect(await b.db.query("SELECT body FROM records")).toEqual(before);
  expect(await b.db.query("SELECT position FROM log_state")).toEqual([
    { position: 5 },
  ]);
});

it("a growing registry head keeps the committed cursor and finishes streams absent from the new tail", async () => {
  const { world, CONNECTOR, CONNECTION_ID } =
    await import("./log-world.test-utils.js");
  const { applyConnection } =
    await import("../../../core/src/localdb/index.js");
  const w = await world({ streams: 2 }),
    a = await w.device("writer");
  let run = 0;
  const publish = async (stream: string, id: string) => {
    await a.run(`r${++run}`, [{ stream, id }], {
      full: false,
      selected: [stream],
      observedAt: 1000 + run,
    });
    await a.cycle();
  };
  await publish("s0", "a");
  await publish("s1", "b");
  await publish("s1", "c");
  const b = await w.device("reader", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
  });
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  const batch = b.db.batch.bind(b.db);
  let fail = true;
  const positions: number[] = [];
  b.db.batch = async (statements) => {
    const state = statements.find((s) =>
      s.sql.includes("INSERT OR REPLACE INTO log_state"),
    );
    if (fail && state?.params?.[1] === 2) throw new Error("stop prefix");
    const result = await batch(statements);
    if (state) positions.push(state.params![1] as number);
    return result;
  };
  await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow(
    "stop prefix",
  );
  expect(await b.position()).toBe(1);
  await publish("s1", "d");
  fail = false;
  positions.length = 0;
  await applyConnection(b.deps, CONNECTION_ID);
  expect(positions).toEqual([2, 3, 4]);
  expect(
    await b.db.query(
      "SELECT stream,complete FROM stream_state WHERE connection_id=? ORDER BY stream",
      [CONNECTION_ID],
    ),
  ).toEqual([
    { stream: "s0", complete: 1 },
    { stream: "s1", complete: 1 },
  ]);
  expect(await b.db.query("SELECT * FROM stream_partial")).toEqual([]);
});
