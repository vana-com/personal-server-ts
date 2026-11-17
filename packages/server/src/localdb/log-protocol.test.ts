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
  decodeSegment,
  deriveKeyCheck,
  digestSegment,
  encodeSegment,
  firstDeletionKeyMismatch,
  LOG_FORMAT,
  PART_LIMIT_BYTES,
  pkHash,
  primaryKeyValues,
  type LogKey,
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
  fetchSegment,
  recordKeyOfKey,
} from "../../../core/src/localdb/log-apply.js";
import { PAGE_BYTES } from "../../../core/src/localdb/log-publish.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { computeRecordKeyFromData } from "../../../core/src/storage/pdpp-records/record-key.js";
import {
  applySegmentOperations,
  applySnapshotPart,
} from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  CONTROL,
  LOG,
  OWNER,
  closeWorldDrivers,
  idHash,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const six = (prefix = "a") =>
  Array.from({ length: 6 }, (_, i) => [
    { stream: sName(i), id: `${prefix}${i}-1` },
    { stream: sName(i), id: `${prefix}${i}-2` },
  ]).flat();

describe("log protocol", () => {
  it("a 6-stream batch is one segment PUT and one registry commit, which also creates the control row", async () => {
    const w = await world({ streams: 6 });
    const a = await w.device("a");
    await a.run("run-1", six());
    await a.cycle();
    expect(a.puts).toHaveLength(1);
    expect(a.puts[0]).toMatch(/\.~log\/s-[0-9a-f]{64}$/);
    expect(w.writes().batches).toBe(1);
    const [batch] = w.gateway.batches();
    // A first save: the control row and the log row that needs it.
    expect(batch!.body.rows.map((r) => r.scope)).toEqual([CONTROL, LOG]);
    expect(batch!.body.rows.map((r) => r.expectedVersion)).toEqual(["1", "1"]);
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
    const w = await world({ streams: 6 });
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
    const w = await world({ streams: 2 });
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
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    const b = await w.device("b");
    await a.run("run-1", [{ stream: sName(0), id: "one" }]);
    await a.cycle();
    await b.cycle();
    expect(await b.position()).toBe(1);

    // Ahead of the registry with no segment of its own above it, so nothing
    // to put back: the device goes back to the last position both agree on
    // (see the P2-2 tests).
    await b.db.batch([
      {
        sql: "UPDATE log_state SET position = 9 WHERE connection_id = ?",
        params: [CONNECTION_ID],
      },
    ]);
    await b.cycle();
    expect(await b.position()).toBe(1);

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
    const w = await world({ streams: 2 });
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
        for (const { pkHash: pk } of op.omitted) {
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
    const w = await world({ streams: 1 });
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
    const w = await world({ streams: 1 });
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
      omitted: [{ pkHash: await idHash("3"), key: ["3"] }],
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
});

describe("request counts", () => {
  for (const streams of [6, 20]) {
    it(`${streams} streams: one segment PUT and one registry commit`, async () => {
      const records = Array.from({ length: streams }, (_, i) => [
        { stream: sName(i), id: `r${i}-1` },
        { stream: sName(i), id: `r${i}-2` },
      ]).flat();
      const w = await world({ streams });
      const a = await w.device("a");
      await a.run("run-1", records);
      await a.cycle();
      expect(a.puts.length).toBe(1);
      expect(w.writes().batches).toBe(1);
    });
  }

  it("a full run that drops rows is one segment: the drop it applies locally is not published again", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      ["x", "y", "z"].map((id) => ({ stream: sName(0), id })),
    );
    await a.cycle();
    // The second full run lists only x: y and z leave as the run's completion.
    // Applying that completion locally deletes y and z, and those deletions are
    // changes the log has nothing to say about: the completion already says them.
    await a.run("run-2", [{ stream: sName(0), id: "x" }]);
    await a.cycle();
    expect(w.gateway.batches()).toHaveLength(2);
    expect(await a.position()).toBe(2);
    await a.cycle();
    expect(w.gateway.batches()).toHaveLength(2);
  });

  it("a connection the device knows publishes before the cycle reads the registry", async () => {
    const w = await world({ streams: 6 });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "r1" }]);
    await a.cycle();
    // The connection is now known and its control row is cached. A second
    // run's changes reach the registry before anything is read from it: the
    // log's writer needs no reading, and each read before the commit is a round
    // trip between the run's end and the new head.
    await a.run("run-2", [{ stream: sName(0), id: "r2" }], {
      full: false,
      covered: [sName(0)],
    });
    w.gateway.calls.length = 0;
    await a.cycle();
    const kinds = w.gateway.calls.map((call) => call.kind);
    expect(kinds).toContain("batch");
    expect(kinds.slice(0, kinds.indexOf("batch"))).toEqual([]);
    // What the cycle then reads is the same as before: nothing is published twice.
    expect(w.gateway.batches()).toHaveLength(1);
  });
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

/**
 * Grow until the log's head carries a snapshot. How many segments that takes is
 * the library's compaction rule (`shouldCompact`) applied to the segments'
 * real sizes, so it is observed, not set here; a rule that never fires ends
 * the test by its timeout.
 */
async function growUntilCompacted(
  d: Device,
  w: Awaited<ReturnType<typeof world>>,
) {
  for (let i = 0; ; i++) {
    const segments = await w.segments();
    if (segments.get(Math.max(...segments.keys()))!.snapshot !== null) return;
    await grow(d, 1, i);
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
        for (const { pkHash: pk } of op.omitted)
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
  const w = await world({ streams: 2 });
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
    const w = await world({ streams: 2 });
    let armed = false;
    let raced = 0;
    const b = await w.device("b");
    const a = await w.device("a", {
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
      partTargetBytes: target,
    });
    const reader = await w.device("reader");
    let segmentPuts = 0;
    let midway: string[] | null = null;
    let midwayPosition = -1;
    const a = await w.device("a", {
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
    // One commit per segment, at consecutive versions; the first also
    // creates the control row.
    expect(
      w.gateway
        .batches()
        .map((b) =>
          b.body.rows
            .filter((r) => r.scope === LOG)
            .map((r) => r.expectedVersion),
        ),
    ).toEqual(positions.map((p) => [String(p)]));
    expect(w.gateway.batches()[0]!.body.rows[0]!.scope).toBe(CONTROL);

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

describe("log protocol: omissions over rounds", () => {
  type Completion = Extract<WireOp, { kind: "complete" }>;
  type WireOp = Segment["operations"][number];
  const completionsIn = (ops: readonly WireOp[]) =>
    ops.filter((o): o is Completion => o.kind === "complete");

  it("a full replacement whose omissions alone exceed the segment limit publishes them in chunks, and a fresh reader has exactly the run's rows", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    // Each omission names its typed key; long keys make 17,000 of them more
    // than one segment may hold, with no row of the replacing run to send.
    const pad = "k".repeat(1000);
    const ids = Array.from({ length: 17_000 }, (_, i) => `${i}-${pad}`);
    await a.run(
      "run-1",
      ids.map((id) => ({ stream: sName(0), id })),
    );
    await a.cycle();
    const before = await a.position();
    const kept = ids.slice(0, 2);
    await a.run(
      "run-2",
      kept.map((id) => ({ stream: sName(0), id })),
    );
    await a.cycle();

    const segments = await w.segments();
    const keys = await w.segmentKeys();
    const after = [...keys.keys()]
      .filter((p) => p > before)
      .sort((x, y) => x - y);
    // Every segment decodes (a segment over the limit does not).
    expect(after.every((p) => segments.has(p))).toBe(true);
    for (const p of after)
      expect(
        (await w.innerBlobs.get(keys.get(p)!))!.length,
      ).toBeLessThanOrEqual(PART_LIMIT_BYTES);
    const chunks = after.map((p) => completionsIn(segments.get(p)!.operations));
    expect(chunks.filter((c) => c.length > 0).length).toBeGreaterThan(1);
    // The omissions stay omissions, at the run's cutoff, each key once.
    const omitted = chunks
      .flat()
      .flatMap((c) => c.omitted.map((o) => o.pkHash));
    expect(new Set(omitted).size).toBe(omitted.length);
    expect(omitted).toHaveLength(ids.length - kept.length);
    expect(
      new Set(chunks.flat().map((c) => `${c.cutoff.o}/${c.cutoff.r}`)).size,
    ).toBe(1);
    expect(
      after
        .flatMap((p) => segments.get(p)!.operations)
        .some((o) => o.kind === "delete"),
    ).toBe(false);
    for (const k of kept) expect(omitted).not.toContain(await idHash(k));
    // Only the last segment says the stream is complete.
    const said = after.map(
      (p) =>
        segments.get(p)!.streams.find((m) => m.stream === sName(0))?.complete,
    );
    expect(said.at(-1)).toBe(true);
    expect(said.slice(0, -1).every((c) => c === false)).toBe(true);

    const c = await w.device("c");
    await c.cycle();
    const records = await c.records();
    expect(records).toHaveLength(kept.length);
    expect(records).toEqual(await a.records());
  }, 300_000);

  it("a reader that applies some omission chunks and then the rest never gets an omitted key back", async () => {
    const w = await world({ streams: 1, partTargetBytes: 3000 });
    const reader = await w.device("reader");
    let armed = false;
    let puts = 0;
    let midway: string[] | null = null;
    let midwayComplete: number | null = null;
    const a = await w.device("a", {
      beforePut: async (key) => {
        if (!armed || !key.includes(`${LOG}/s-`) || ++puts !== 2) return;
        // The first chunk is committed and the second is not.
        await reader.cycle();
        midway = await reader.records();
        midwayComplete =
          (
            await reader.db.query<{ complete: number }>(
              "SELECT complete FROM stream_state WHERE stream = ?",
              [sName(0)],
            )
          )[0]?.complete ?? null;
      },
    });
    const ids = Array.from(
      { length: 120 },
      (_, i) => `id-${String(i).padStart(3, "0")}`,
    );
    const idOf = new Map<string, string>();
    for (const id of ids) idOf.set(await idHash(id), id);
    const held = (records: readonly string[]) =>
      records.map(
        (r) => (JSON.parse(r.slice(r.indexOf("=") + 1)) as { id: string }).id,
      );
    await a.run(
      "run-1",
      ids.map((id) => ({ stream: sName(0), id })),
    );
    await a.cycle();
    await reader.cycle();
    expect(await reader.records()).toHaveLength(ids.length);

    armed = true;
    const before = await a.position();
    const kept = ids.slice(0, 2);
    await a.run(
      "run-2",
      kept.map((id) => ({ stream: sName(0), id })),
    );
    await a.cycle();

    const segments = await w.segments();
    const after = [...segments.keys()]
      .filter((p) => p > before)
      .sort((x, y) => x - y);
    expect(after.length).toBeGreaterThan(2);
    const firstChunk = completionsIn(
      segments.get(after[0]!)!.operations,
    ).flatMap((c) => c.omitted.map((o) => idOf.get(o.pkHash)!));
    expect(firstChunk.length).toBeGreaterThan(0);
    expect(firstChunk.length).toBeLessThan(ids.length - kept.length);

    // Midway: the first chunk's keys are gone, later ones are still held,
    // and the stream does not say it is complete.
    expect(midway).not.toBeNull();
    const mid = held(midway!);
    for (const id of firstChunk) expect(mid).not.toContain(id);
    expect(mid.length).toBeGreaterThan(kept.length);
    expect(midwayComplete).toBe(0);

    await reader.cycle();
    expect(held(await reader.records()).sort()).toEqual([...kept].sort());
    expect(await reader.rows()).toEqual(await a.rows());
    // Settled: another pass publishes nothing and the log does not move.
    const settled = await a.position();
    await a.cycle();
    await reader.cycle();
    expect(await a.position()).toBe(settled);
    expect(held(await reader.records()).sort()).toEqual([...kept].sort());
  });
});

describe("log protocol: attachments", () => {
  const bytes = new Uint8Array(5000).fill(7);
  const hash = Buffer.from(sha256(bytes)).toString("hex");

  it("a blob uploaded with a log-mode publish is readable on another device", async () => {
    const w = await world({ streams: 1 });
    // The registry commit that names the blob's record comes after the blob and
    // the segment are both in storage; their own order is free.
    const batchesAtPut: number[] = [];
    const a = await w.device("a", {
      beforePut: async () => {
        batchesAtPut.push(w.gateway.batches().length);
      },
    });
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
    expect(a.puts.some((k) => k.includes(`${LOG}/s-`))).toBe(true);
    expect(batchesAtPut).toEqual([0, 0]);
    expect(w.writes().batches).toBe(1);
    await b.cycle();
    expect(new Uint8Array((await b.sync.blobs.get(hash))!.bytes)).toEqual(
      bytes,
    );
  });

  it("bytes that arrive after their records were published are uploaded by the next pass", async () => {
    const w = await world({ streams: 1 });
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
    format: LOG_FORMAT,
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
    const w = await world({ streams: 1 });
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
    omitted: [{ pkHash: await idHash("k"), key: ["k"] }],
  });
  const deleteK = async () => ({
    kind: "delete" as const,
    stream: sName(0),
    pkHash: await idHash("k"),
    key: ["k"],
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

describe("log protocol: a registry behind this device gets its lost segments back; one on another history gets what only the device's history held (P2-2)", () => {
  /** a writes an insert (position 1) and a delete (position 2); b applies both. */
  const history = async () => {
    const w = await world({ streams: 1 });
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

  it("a registry rolled back below the applied position is not read as caught up: the device commits the lost segment again", async () => {
    const { w, b } = await history();
    const before = { rows: await b.rows(), position: await b.position() };
    w.gateway.versions.get(LOG)!.pop(); // the registry is at position 1 again
    await b.cycle();
    expect(await b.position()).toBe(before.position);
    expect(await b.rows()).toEqual(before.rows);
    expect(w.gateway.rowsOf(LOG)).toBe(before.position);
    // A device that never read the log gets the delete at position 2.
    const c = await w.device("c");
    await c.cycle();
    expect(await c.rows()).toEqual(before.rows);
  });

  it("the same position under a different segment is not read as caught up: the device reads it and puts back the delete only its history held", async () => {
    const { w, b } = await history();
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
    await b.cycle();
    expect(await b.position()).toBe(3);
    const ids = (await b.records()).map((r) => r.split("=")[0]);
    expect(ids).toEqual([`${sName(0)}/from-c`, `${sName(0)}/x`]);
    await c.cycle();
    const d = await w.device("d");
    await d.cycle();
    expect(await c.rows()).toEqual(await b.rows());
    expect(await d.rows()).toEqual(await b.rows());
  });
});

describe("log protocol: a resurrection after a deletion (P2-3)", () => {
  it("a lagging, a fresh and an uninterrupted reader agree on every column, first-seen included", async () => {
    const w = await world({ streams: 2 });
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
    const w = await world({ streams: 1 });
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
      key: ["k"],
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
          key: ["k"],
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
    const w = await world({ streams: 1 });
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

// ---------------------------------------------------------------------------
// The canonical record key travels with every deletion (log format 2).
// ---------------------------------------------------------------------------

describe("log protocol: deletions carry the canonical record key", () => {
  const SEEN = sName(0);
  /** Records 1, 2, 3; 2 deleted and a never-held `ghost` deleted; a full pass then omits 3. */
  async function omissionWorld(compact: boolean) {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      [
        { stream: SEEN, id: "1" },
        { stream: SEEN, id: "2" },
        { stream: SEEN, id: "3" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await a.run(
      "run-2",
      [
        { stream: SEEN, id: "2", remove: true },
        { stream: SEEN, id: "ghost", remove: true },
      ],
      { full: false, covered: [SEEN], observedAt: 1200 },
    );
    await a.cycle();
    await a.run("run-3", [{ stream: SEEN, id: "1" }], { observedAt: 1300 });
    await a.cycle();
    if (compact) await grow(a, 40);
    return { w, a };
  }
  const operations = async (w: Awaited<ReturnType<typeof world>>) =>
    [...(await w.segments()).values()]
      .sort((x, y) => x.position - y.position)
      .flatMap((g) => g.operations);
  const tombstones = (d: Device) =>
    d.db.query<{
      stream: string;
      pk_hash: string;
      record_key: string | null;
      rank: number;
    }>(
      "SELECT stream, pk_hash, record_key, rank FROM log_tombstones ORDER BY pk_hash",
    );

  it("an explicit delete carries the key of a held row and of a key the writer never held", async () => {
    const { w } = await omissionWorld(false);
    const deletes = (await operations(w)).filter((o) => o.kind === "delete");
    expect(deletes.map((o) => (o as { key: unknown[] }).key).sort()).toEqual([
      ["2"],
      ["ghost"],
    ]);
    for (const op of deletes)
      expect((op as { pkHash: string }).pkHash).toBe(
        await idHash((op as { key: string[] }).key[0]!),
      );
  });

  it("an omission names the key of each row it drops", async () => {
    const { w } = await omissionWorld(false);
    const completion = (await operations(w)).find(
      (o) => o.kind === "complete" && o.omitted.length > 0,
    );
    expect(completion).toMatchObject({
      omitted: [{ pkHash: await idHash("3"), key: ["3"] }],
    });
  });

  it("the snapshot form of a delete and of an omission carries the key", async () => {
    const { w } = await omissionWorld(true);
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    expect(head.snapshot).not.toBeNull();
    const entries = (await w.snapshotParts(head)).flatMap((p) => p.entries);
    const tombstone = (kind: string, id: string) =>
      entries.find((e) => e.kind === kind && e.key[0] === id);
    expect(tombstone("delete", "2")).toMatchObject({
      pkHash: await idHash("2"),
    });
    expect(tombstone("delete", "ghost")).toMatchObject({
      pkHash: await idHash("ghost"),
    });
    expect(tombstone("omitted", "3")).toMatchObject({
      pkHash: await idHash("3"),
    });
  });

  it("a reader applies a delete for a key it never held, and keeps the key with the tombstone", async () => {
    const { w, a } = await omissionWorld(false);
    const c = await w.device("c");
    await c.cycle();
    // The reader never held `ghost` or `2` (it joined after both were deleted).
    expect((await c.records()).map((r) => r.split("=")[0])).toEqual(["s0/1"]);
    expect(await c.rows()).toEqual(await a.rows());
    const kept = await tombstones(c);
    expect(kept.map((t) => [t.record_key, t.rank]).sort()).toEqual([
      ["2", 2],
      ["3", 0],
      ["ghost", 2],
    ]);
    for (const t of kept) expect(t.pk_hash).toBe(await idHash(t.record_key!));
  });

  it("a reader that installs a snapshot keeps the key of the tombstones in it", async () => {
    const { w } = await omissionWorld(true);
    const c = await w.device("c");
    await c.cycle();
    const keys = (await tombstones(c)).map((t) => [t.record_key, t.rank]);
    expect(keys).toEqual(
      expect.arrayContaining([
        ["2", 2],
        ["3", 0],
        ["ghost", 2],
      ]),
    );
    expect(c.gets.some((k) => k.includes(`${LOG}/q-`))).toBe(true);
  });

  it("the key is only inside the encrypted segment: no object name, registry row or scope carries it", async () => {
    const { w } = await omissionWorld(true);
    const seen = [
      ...w.innerBlobs.keys(),
      ...w.gateway.versions.keys(),
      ...[...w.gateway.versions.values()].flatMap((rows) =>
        rows.flatMap((r) => [r.dataHash, r.metadataHash]),
      ),
    ];
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.filter((name) => name.includes("ghost"))).toEqual([]);
  });

  it("a hash-only segment (format 1) is refused, not applied as keyless", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: SEEN, id: "seed" }], { observedAt: 1100 });
    await a.cycle();
    const hashOnly = new TextDecoder()
      .decode(
        encodeSegment(
          await crafted(2, [
            {
              kind: "delete",
              stream: SEEN,
              pkHash: await idHash("k"),
              key: ["k"],
              stamp: { o: 5000, r: "run-k" },
            },
          ]),
        ),
      )
      .replace(`"format":${LOG_FORMAT}`, '"format":1')
      .replace(`"rk":["k"],`, "");
    const bytes = new TextEncoder().encode(hashOnly);
    const { dataHash } = await digestSegment(async (b) => keccak_256(b), bytes);
    await w.innerBlobs.put(`${LOG}/s-${dataHash.slice(2)}`, bytes);
    await expect(
      fetchSegment(
        a.deps,
        LOG,
        {
          connector: CONNECTOR,
          ns: "",
          keyCheck: "0123456789abcdef",
        },
        dataHash,
        2,
      ),
    ).rejects.toThrow(/unsupported_format/);
  });
});

describe("log protocol: a deletion's key must be the key its hash names", () => {
  const S = { o: 5000, r: "run-k" };
  const seeded = async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "A" }], { observedAt: 1100 });
    await a.cycle();
    const m = await joined(w, "m");
    return { w, m };
  };
  const state = async (d: Device) => ({
    records: await d.records(),
    tombstones: await d.db.query("SELECT * FROM log_tombstones"),
    position: await d.position(),
  });
  // p names A; rk names B. Each of the three places a deletion names a key.
  const sites = {
    "an explicit delete": async () => ({
      kind: "delete" as const,
      stream: sName(0),
      pkHash: await idHash("A"),
      key: ["B"],
      stamp: S,
    }),
    "a completion's omission": async () => ({
      kind: "complete" as const,
      stream: sName(0),
      cutoff: S,
      omitted: [{ pkHash: await idHash("A"), key: ["B"] }],
    }),
  };
  for (const [name, make] of Object.entries(sites))
    it(`${name} whose key is another record's is refused before anything is written`, async () => {
      const { m } = await seeded();
      const before = await state(m);
      await expect(
        applySegmentOperations(
          m.deps,
          CONNECTION_ID,
          await crafted(2, [await make()]),
        ),
      ).rejects.toThrow(/does not match/);
      expect(await state(m)).toEqual(before);
    });

  it("a snapshot omission, and a snapshot delete, whose key is another record's is refused before anything is written", async () => {
    const { m } = await seeded();
    const before = await state(m);
    const segment = await crafted(2, []);
    for (const kind of ["omitted", "delete"] as const)
      await expect(
        applySnapshotPart(m.deps, CONNECTION_ID, {
          format: LOG_FORMAT,
          connector: CONNECTOR,
          ns: "",
          generation: 1,
          keyCheck: segment.keyCheck,
          position: 2,
          index: 0,
          streams: segment.streams,
          entries: [
            {
              kind,
              stream: sName(0),
              pkHash: await idHash("A"),
              key: ["B"],
              stamp: S,
            },
          ],
        }),
      ).rejects.toThrow(/does not match/);
    expect(await state(m)).toEqual(before);
  });

  it('a key of either type is accepted and kept: 1 and "1" name different hashes and one key', async () => {
    const { w, m } = await seeded();
    const typed = (value: string | number) =>
      pkHash(async (b) => sha256(b), { id: value }, ["id"]);
    const operation = async (value: string | number) => ({
      kind: "delete" as const,
      stream: sName(0),
      pkHash: await typed(value),
      key: [value],
      stamp: S,
    });
    expect(await typed(1)).not.toBe(await typed("1"));
    await applySegmentOperations(
      m.deps,
      CONNECTION_ID,
      await crafted(2, [await operation(1), await operation("1")]),
    );
    expect(
      (
        await m.db.query<{ pk_hash: string; record_key: string }>(
          "SELECT pk_hash, record_key FROM log_tombstones ORDER BY pk_hash",
        )
      ).map((t) => [t.pk_hash, t.record_key]),
    ).toEqual([await typed(1), await typed("1")].sort().map((h) => [h, "1"]));
    expect(w).toBeDefined();
  });

  it("the typed key of typed and compound records passes the reader's check and derives their record key", async () => {
    for (const [record, primaryKey] of [
      [{ id: 1 }, ["id"]],
      [{ id: "1" }, ["id"]],
      [{ a: "x", b: 2 }, ["a", "b"]],
      [{ a: 2, b: "x", c: true }, ["a", "b", "c"]],
    ] as const) {
      const key = primaryKeyValues(record, primaryKey) as LogKey;
      const hash = await pkHash(async (b) => sha256(b), record, primaryKey);
      expect(
        await firstDeletionKeyMismatch(
          async (b) => sha256(b),
          [
            {
              stream: "x",
              primaryKey,
              profile: { key: null, version: "1" },
              complete: true,
            },
          ],
          [{ kind: "delete", stream: "x", pkHash: hash, key, stamp: S }],
        ),
      ).toBeNull();
      expect(recordKeyOfKey(primaryKey, key)).toBe(
        computeRecordKeyFromData(record, [...primaryKey]),
      );
    }
  });

  it("an explicit delete made before the typed key was kept is not acknowledged: the stream is held, nothing is lost, and once the key is known every reader converges", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    const warnings: unknown[] = [];
    (a.deps as { logger: unknown }).logger = {
      info: () => {},
      warn: (...args: unknown[]) => warnings.push(args),
    };
    const [s0, s1] = [sName(0), sName(1)];
    await a.run(
      "run-1",
      [
        { stream: s0, id: 7 },
        { stream: s1, id: "x" },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    const reader = await joined(w, "r");
    expect(await reader.records()).toHaveLength(2);

    await a.run(
      "run-2",
      [
        { stream: s0, id: 7, remove: true },
        { stream: s1, id: "y" },
      ],
      { full: false, covered: [s0, s1], observedAt: 1200 },
    );
    // The delete was made before typed keys were kept.
    await a.db.query(
      "UPDATE record_changes SET pk_values = NULL WHERE op = 'remove'",
    );
    const watermark = async () =>
      a.db.query<{ stream: string; publish_watermark: number }>(
        "SELECT stream, publish_watermark FROM stream_state ORDER BY stream",
      );
    const before = await watermark();
    await a.cycle();

    // Not published, not acknowledged: the change is still owed to the log.
    const ops = () =>
      w.segments().then((m) => [...m.values()].flatMap((g) => g.operations));
    expect((await ops()).filter((o) => o.kind === "delete")).toEqual([]);
    const held = await watermark();
    expect(held.find((r) => r.stream === s0)).toEqual(
      before.find((r) => r.stream === s0),
    );
    expect(
      await a.db.query(
        "SELECT 1 FROM record_changes WHERE stream = ? AND op = 'remove' AND explicit_delete = 1",
        [s0],
      ),
    ).toHaveLength(1);
    expect(warnings).toHaveLength(1);
    expect(JSON.stringify(warnings)).toContain("explicit delete");
    expect(JSON.stringify(warnings)).toContain(`stream \\"${s0}\\"`);
    // The same held state does not warn again on the next cycle.
    await a.cycle();
    expect(warnings).toHaveLength(1);
    // The other stream is not held by it.
    await reader.cycle();
    expect(await reader.records()).toEqual(
      expect.arrayContaining([expect.stringContaining(`${s1}/y=`)]),
    );
    // The reader still holds the record the delete would remove, and says so
    // by the log having nothing for it: this is why the change is kept owed.
    expect(await reader.records()).toEqual(
      expect.arrayContaining([expect.stringContaining(`${s0}/7=`)]),
    );

    // Once its typed key is known the delete is published and acknowledged,
    // and a fresh reader that replays the whole log lacks the record.
    await a.db.query(
      "UPDATE record_changes SET pk_values = '[7]' WHERE op = 'remove' AND pk_values IS NULL",
    );
    await a.cycle();
    expect((await ops()).filter((o) => o.kind === "delete")).toMatchObject([
      { stream: s0, pkHash: await idHash(7), key: [7] },
    ]);
    const fresh = await w.device("fresh");
    await fresh.cycle();
    await reader.cycle();
    for (const d of [fresh, reader]) {
      expect(await d.records()).toEqual(await a.records());
      expect(await d.records()).not.toEqual(
        expect.arrayContaining([expect.stringContaining(`${s0}/7=`)]),
      );
    }
  });

  it("a delete and an omission of a numeric key carry the number, and a reader derives the same record key", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      [
        { stream: sName(0), id: 1 },
        { stream: sName(0), id: 7 },
        { stream: sName(0), id: 8 },
      ],
      { observedAt: 1100 },
    );
    await a.cycle();
    await a.run("run-2", [{ stream: sName(0), id: 7, remove: true }], {
      full: false,
      covered: [sName(0)],
      observedAt: 1200,
    });
    await a.cycle();
    await a.run("run-3", [{ stream: sName(0), id: 1 }], { observedAt: 1300 });
    await a.cycle();
    const ops = [...(await w.segments()).values()]
      .sort((x, y) => x.position - y.position)
      .flatMap((g) => g.operations);
    expect(ops.find((o) => o.kind === "delete")).toMatchObject({
      pkHash: await idHash(7),
      key: [7],
    });
    expect(
      ops.find((o) => o.kind === "complete" && o.omitted.length > 0),
    ).toMatchObject({ omitted: [{ pkHash: await idHash(8), key: [8] }] });
    const c = await w.device("c");
    await c.cycle();
    expect(
      (
        await c.db.query<{ record_key: string; rank: number }>(
          "SELECT record_key, rank FROM log_tombstones ORDER BY record_key",
        )
      ).map((t) => [t.record_key, t.rank]),
    ).toEqual([
      ["7", 2],
      ["8", 0],
    ]);
  });
});

describe("log protocol: an omission reads a bounded page of bodies", () => {
  it("many omitted rows with large bodies are read a page at a time, and only their keys are kept", async () => {
    const SEEN = sName(0);
    const count = 60;
    const pad = 100_000; // 6 MB of bodies, three times a page
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      Array.from({ length: count }, (_, i) => ({
        stream: SEEN,
        id: `k${i}`,
        pad,
      })),
      { observedAt: 1100 },
    );
    await a.cycle();
    await a.run("run-2", [{ stream: SEEN, id: "k0", pad }], {
      observedAt: 1200,
    });

    const bodyReads: number[] = [];
    const real = a.db.query.bind(a.db);
    (a.db as { query: unknown }).query = async (
      sql: string,
      params?: unknown[],
    ) => {
      const rows = await real(sql, params as never);
      if (/SELECT pk_hash, body FROM records/.test(sql))
        bodyReads.push(
          (rows as { body: string }[]).reduce((n, r) => n + r.body.length, 0),
        );
      return rows;
    };
    await a.cycle();

    const completion = [...(await w.segments()).values()]
      .flatMap((g) => g.operations)
      .find((o) => o.kind === "complete" && o.omitted.length > 0) as
      { omitted: { pkHash: string; key: unknown[] }[] } | undefined;
    expect(completion!.omitted.map((o) => o.key[0]).sort()).toEqual(
      Array.from({ length: count - 1 }, (_, i) => `k${i + 1}`).sort(),
    );
    const total = bodyReads.reduce((n, b) => n + b, 0);
    expect(total).toBeGreaterThan(2 * PAGE_BYTES);
    expect(bodyReads.length).toBeGreaterThanOrEqual(3);
    expect(Math.max(...bodyReads)).toBeLessThanOrEqual(PAGE_BYTES);
  });
});

// A key the log must carry the same at the writer and at the reader, or
// refuse at both: through the real writer, the segment and the real reader.
describe("log protocol: adversarial key values converge", () => {
  const accents = ["\u00e9", "e\u0301"]; // precomposed, decomposed
  const ids: (string | number)[] = [-0, 1, 9007199254740992, ...accents];
  const ONE = sName(0);

  it("an explicit delete of each removes it for a reader that held it, and for a fresh one", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      ids.map((id) => ({ stream: ONE, id })),
      { observedAt: 1100 },
    );
    await a.cycle();
    const held = await joined(w, "held");
    expect(await held.records()).toHaveLength(ids.length);
    await a.run(
      "run-2",
      ids.map((id) => ({ stream: ONE, id, remove: true })),
      { full: false, covered: [ONE], observedAt: 1200 },
    );
    await a.cycle();
    await held.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    expect(await a.records()).toEqual([]);
    expect(await held.records()).toEqual([]);
    expect(await fresh.records()).toEqual([]);
    // Each delete named the key its hash was computed from.
    const deletes = [...(await w.segments()).values()]
      .flatMap((g) => g.operations)
      .filter((o) => o.kind === "delete") as {
      pkHash: string;
      key: (string | number)[];
    }[];
    expect(deletes.map((d) => d.key[0]).sort()).toEqual(
      [0, 1, 9007199254740992, ...accents].sort(),
    );
    for (const d of deletes) expect(d.pkHash).toBe(await idHash(d.key[0]!));
  });

  it("an omission of each drops it for a reader that held it, and for a fresh one", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "run-1",
      [...ids, "keep"].map((id) => ({ stream: ONE, id })),
      { observedAt: 1100 },
    );
    await a.cycle();
    const held = await joined(w, "held");
    expect(await held.records()).toHaveLength(ids.length + 1);
    await a.run("run-2", [{ stream: ONE, id: "keep" }], { observedAt: 1200 });
    await a.cycle();
    await held.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    for (const d of [a, held, fresh])
      expect(await d.records()).toEqual([`${ONE}/keep={"id":"keep"}`]);
  });
});

// A delete made before typed keys were kept is held back unless the stream's
// declared key types give its key back, and then only if that key hashes to the
// delete's hash.
describe("log protocol: the declared key types release an untyped delete", () => {
  const ONE = sName(0);
  /** Key 7 published, deleted, and the delete's typed key lost, as before the column. */
  const legacyDelete = async (
    keyTypes?: ("string" | "number" | "integer" | "boolean" | null)[],
  ) => {
    const w = await world({
      streams: 1,
      ...(keyTypes ? { keyTypes } : {}),
    });
    const a = await w.device("a");
    const warnings: string[] = [];
    (a.deps as { logger: unknown }).logger = {
      info: () => {},
      warn: (_fields: unknown, message: string) => warnings.push(message),
    };
    await a.run("run-1", [{ stream: ONE, id: 7 }], { observedAt: 1100 });
    await a.cycle();
    const reader = await joined(w, "r");
    await a.run("run-2", [{ stream: ONE, id: 7, remove: true }], {
      full: false,
      covered: [ONE],
      observedAt: 1200,
    });
    await a.db.query("UPDATE record_changes SET pk_values = NULL");
    await a.cycle();
    const deletes = async () =>
      [...(await w.segments()).values()]
        .flatMap((g) => g.operations)
        .filter((o) => o.kind === "delete");
    return { w, a, reader, warnings, deletes };
  };
  const converged = async (
    w: Awaited<ReturnType<typeof world>>,
    a: Device,
    reader: Device,
  ) => {
    await reader.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    for (const d of [reader, fresh])
      expect(await d.records()).toEqual(await a.records());
    expect(await a.records()).toEqual([]);
  };

  it("an integer key declared by the schema is rebuilt from the record key, published, and every reader converges", async () => {
    const { w, a, reader, warnings, deletes } = await legacyDelete(["integer"]);
    expect(
      (
        await a.db.query<{ key_types: string }>(
          "SELECT key_types FROM stream_state",
        )
      )[0]!.key_types,
    ).toBe('["integer"]');
    expect(await deletes()).toMatchObject([
      { stream: ONE, pkHash: await idHash(7), key: [7] },
    ]);
    expect(warnings).toEqual([]);
    await converged(w, a, reader);
  });

  it("the same delete is held when the schema declares no type for the key", async () => {
    const { w, a, reader, warnings, deletes } = await legacyDelete();
    expect(await deletes()).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(`stream "${ONE}"`);
    expect(await reader.cycle().then(() => reader.records())).toHaveLength(1);
    // The next run that declares the types releases it.
    await a.db.query("UPDATE stream_state SET key_types = '[\"integer\"]'");
    await a.cycle();
    expect(await deletes()).toMatchObject([{ key: [7] }]);
    await converged(w, a, reader);
  });

  it("is held when the data disagrees with the declared type: the rebuilt key does not hash to the delete's hash", async () => {
    const { a, reader, warnings, deletes } = await legacyDelete(["string"]);
    expect(await deletes()).toEqual([]);
    expect(warnings).toHaveLength(1);
    expect(await reader.cycle().then(() => reader.records())).toHaveLength(1);
    expect(await a.db.query("SELECT 1 FROM record_changes")).not.toHaveLength(
      0,
    );
  });
});

// ---------------------------------------------------------------------------
// A run that publishes while it collects can emit a key again in a later batch
// with a changed body, at the run's one stamp. The log's order between the two
// is the intake batch ordinal, then the body hash (stream-sync `upsertAfter`).
// ---------------------------------------------------------------------------

describe("log protocol: a run emits a key again after an interim publish", () => {
  const RUN = "same-run";
  const stream = sName(0);
  const begin = (d: Device, runId = RUN) =>
    d.sync.intake.begin(runId, {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      observedAt: 1500,
      owner: { address: OWNER, leaseId: null },
    });
  const batch = (d: Device, n: number, records: object[], runId = RUN) =>
    d.sync.intake.batch(runId, {
      batch: n,
      records: records.map((data) => ({ stream, data })),
    });
  const end = (d: Device, lastBatch: number, runId = RUN) =>
    d.sync.intake.end(
      runId,
      endRequest({
        lastBatch,
        live: [stream],
        provenFullStreams: [stream],
      }),
    );
  const body = (v: number) => `s0/K={"id":"K","v":${v}}`;

  it("converges to the later batch on the writer, a fresh reader and a reader that applied the first body", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    await begin(a);
    await batch(a, 0, [{ id: "K", v: 1 }]);
    expect(await a.records()).toEqual([body(1)]);
    await a.cycle();
    expect(await a.position()).toBe(1);
    // a reader that holds the first body before the replacement exists
    const early = await w.device("early");
    await early.cycle();
    expect(await early.records()).toEqual([body(1)]);

    await batch(a, 1, [{ id: "K", v: 2 }]);
    await end(a, 1);
    await a.cycle();
    expect(await a.position()).toBe(2);
    expect(await a.records()).toEqual([body(2)]);

    // the second segment names the same stamp and the batch ordinal
    const segments = await w.segments();
    const stamps = [1, 2].map((p) => {
      const op = segments
        .get(p)!
        .operations.find((o) => o.kind === "upsert" && o.stream === stream);
      if (op?.kind !== "upsert") throw new Error("no upsert");
      return op;
    });
    expect(stamps[1]!.stamp).toEqual(stamps[0]!.stamp);
    expect(stamps[0]!.ordinal).toBeUndefined();
    expect(stamps[1]!.ordinal).toBe(1);

    await early.cycle();
    expect(await early.records()).toEqual([body(2)]);
    const fresh = await w.device("fresh");
    await fresh.cycle();
    expect(await fresh.position()).toBe(2);
    expect(await fresh.rows()).toEqual(await a.rows());
    expect(await early.rows()).toEqual(await a.rows());
  });

  it("converges for a reader that installs a compacted snapshot", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    await begin(a);
    await batch(a, 0, [{ id: "K", v: 1 }]);
    await a.cycle();
    // a reader that holds the first body while the log grows and compacts
    const early = await w.device("early");
    await early.cycle();
    expect(await early.records()).toEqual([body(1)]);
    await batch(a, 1, [{ id: "K", v: 2 }]);
    await end(a, 1);
    await a.cycle();
    await growUntilCompacted(a, w);
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    expect(head.snapshot).not.toBeNull();
    expect(head.base).toBeGreaterThan(2);
    const fresh = await w.device("fresh");
    await fresh.cycle();
    await early.cycle();
    for (const reader of [fresh, early])
      expect(
        (await reader.records()).filter((r) => r.startsWith("s0/K=")),
      ).toEqual([body(2)]);
  });

  it("a delete at the run's end beats the interim body whatever its ordinal", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    await begin(a);
    await batch(a, 0, [{ id: "K", v: 1 }]);
    await a.cycle();
    await batch(a, 1, [{ id: "K", v: 2 }]);
    await a.cycle();
    await a.sync.intake.batch(RUN, {
      batch: 2,
      records: [{ stream, op: "delete", data: { id: "K" } }],
    });
    await end(a, 2);
    await a.cycle();
    expect(await a.records()).toEqual([]);
    const fresh = await w.device("fresh");
    await fresh.cycle();
    expect(await fresh.records()).toEqual([]);
  });

  // Three writers share one run id, so one stamp. Each emits the key at its own
  // batch ordinal; the filler keys only move the writer's batch counter.
  const filler = (i: number) => ({ id: `F${i}`, v: 0 });
  const emitAt = async (d: Device, n: number, v: number) => {
    await begin(d);
    for (let i = 0; i < n; i++) await batch(d, i, [filler(i)]);
    await batch(d, n, [{ id: "K", v }]);
  };
  const keyOf = async (d: Device) =>
    (await d.rows())
      .map(
        (r) =>
          JSON.parse(r) as {
            record_key: string;
            body: string;
            stamp_n: number;
          },
      )
      .filter((r) => r.record_key === "K");

  it("an identical body at a higher ordinal advances a reader that holds it, so a lower ordinal of another body loses everywhere", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    const c = await w.device("c");
    const d = await w.device("d");
    // A at n0 (a), A at n2 (c), B at n1 (d). Each writer emits before it pulls, so
    // each writes its own observation; they publish in that order.
    await emitAt(a, 0, 1);
    await emitAt(c, 2, 1);
    await emitAt(d, 1, 2);
    await a.cycle();
    const early = await w.device("early");
    await early.cycle();
    await c.cycle();
    await early.cycle();
    await d.cycle();
    await early.cycle();
    await a.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    const expected = await keyOf(fresh);
    expect(expected).toMatchObject([
      { body: expect.stringContaining('"v":1') },
    ]);
    expect(expected[0]!.stamp_n).toBe(2);
    for (const reader of [early, a])
      expect(await keyOf(reader)).toEqual(expected);
  });

  it("the same trace converges for a reader that installs a compacted snapshot", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    const c = await w.device("c");
    const d = await w.device("d");
    await emitAt(a, 0, 1);
    await emitAt(c, 2, 1);
    await emitAt(d, 1, 2);
    await a.cycle();
    const early = await w.device("early");
    await early.cycle();
    await c.cycle();
    await d.cycle();
    await growUntilCompacted(d, w);
    const segments = await w.segments();
    expect(segments.get(Math.max(...segments.keys()))!.snapshot).not.toBeNull();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    await early.cycle();
    const expected = await keyOf(fresh);
    expect(expected[0]!.stamp_n).toBe(2);
    expect(await keyOf(early)).toEqual(expected);
  });

  it("a run that has pulled a clone's higher ordinal does not replace it with its own lower ordinal", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    const c = await w.device("c");
    await begin(a);
    // the clone publishes B at n1 while a is still collecting
    await emitAt(c, 1, 2);
    await c.cycle();
    await a.cycle();
    expect(await keyOf(a)).toMatchObject([{ stamp_n: 1 }]);
    // a's own first batch: another body at n0
    await batch(a, 0, [{ id: "K", v: 1 }]);
    await a.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    const expected = await keyOf(fresh);
    expect(expected).toMatchObject([{ stamp_n: 1 }]);
    expect(await keyOf(a)).toEqual(expected);
  });

  it("writers that share a run id and emit different bodies at one batch converge on the greater body hash", async () => {
    const w = await world({
      streams: 1,
      publishWhileCollecting: true,
    });
    const a = await w.device("a");
    const c = await w.device("c");
    await begin(a);
    await begin(c);
    await batch(a, 0, [{ id: "K", v: 1 }]);
    await batch(c, 0, [{ id: "K", v: 2 }]);
    await end(a, 0);
    await end(c, 0);
    const hashOf = (v: number) =>
      Buffer.from(
        sha256(new TextEncoder().encode(`{"id":"K","v":${v}}`)),
      ).toString("hex");
    const winner = hashOf(1) > hashOf(2) ? 1 : 2;
    // each publishes its own body first, then reads the other's
    await a.cycle();
    await c.cycle();
    await a.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    for (const d of [a, c, fresh])
      expect(await d.records()).toEqual([body(winner)]);
  });
});
