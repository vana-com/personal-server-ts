// The disk fold (`log-fold-workspace.ts`) is the in-memory fold
// (`foldLog`, stream-sync `log.ts`) on the same history: the same entries in the
// same order, whatever the history holds. The in-memory fold is the oracle and
// stays; these tests are what lets a compaction or a rebase leave memory.
import { afterEach, describe, expect, it } from "vitest";
import {
  createPartitioner,
  decodeSnapshotPart,
  encodeSnapshotPart,
  foldLog,
  partitionFold,
  upsertBodyHash,
  LOG_FORMAT,
  type JsonObject,
  type LogBodyRef,
  type LogEntry,
  type LogOmission,
  type LogOperation,
  type Segment,
  type SnapshotPart,
  type WireEntry,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { openFoldWorkspace } from "../../../core/src/localdb/log-fold-workspace.js";
import { openSpool } from "../../../core/src/localdb/log-spool.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import {
  frameLimited,
  SQL_FRAME_BYTES,
} from "./frame-limited-driver.test-utils.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function database() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: `0x${"11".repeat(20)}`,
    network: "test",
    deviceId: "d",
  });
  drivers.push(db);
  return db;
}

/** A small deterministic generator: a failing seed is a reproduction. */
function rng(seed: number) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number) => Math.floor(next() * n);
  return { next, int, pick: <T>(xs: readonly T[]) => xs[int(xs.length)]! };
}

const CONTEXT = {
  connector: "c",
  ns: "",
  generation: 1,
  keyCheck: "k",
} as const;
const meta = (stream: string, cursor?: number) => ({
  stream,
  primaryKey: ["id"],
  profile: { key: null, version: "1" },
  complete: true,
  ...(cursor === undefined
    ? {}
    : { cursor: { connectorVersion: "1", state: cursor } }),
});

/** The names a history draws its streams, run ids and key hashes from. */
interface Names {
  readonly streams: readonly string[];
  readonly runs: readonly string[];
  readonly pkHash: (k: number) => string;
}
const ASCII: Names = {
  streams: ["s0", "s1"],
  runs: ["a", "b", "c"],
  pkHash: (k) => `h${String(k).padStart(4, "0")}`,
};
/**
 * Names the wire accepts (a stream is any non-empty string, a run id likewise)
 * that UTF-8 byte order and UTF-16 order sort differently: U+E000 and U+FFFF
 * sort before U+10000 and U+1F600 by byte and after them by UTF-16 unit. Lone
 * surrogates are valid in JSON text and distinct from each other.
 */
const WIDE: Names = {
  streams: [
    "s\uE000",
    "s\u{10000}",
    "s\u{1F600}",
    "s\uFFFF",
    "s\uD800",
    "s\uDFFF",
    "s",
  ],
  runs: ["\uE000", "\u{10000}", "\u{1F600}", "\uFFFF", "a", "\uD800", "\uDFFF"],
  // A key hash is 64 lowercase hex characters on the wire.
  pkHash: (k) => k.toString(16).padStart(64, "0"),
};

interface History {
  readonly segments: Segment<LogOperation>[];
  /** The same segments with some bodies by reference, and what they name. */
  readonly wire: Segment<WireOperation>[];
  readonly refs: Map<string, LogBodyRef>;
}

/**
 * A history over few keys, stamps and runs, so that ties, resurrections and
 * omissions at the stamp of an observation are common. Bodies of `big`
 * upserts are by reference in `wire`; the oracle sees them resolved.
 */
function history(
  seed: number,
  shape: { keys: number; segments: number; opsPerSegment: number },
  names: Names = ASCII,
): History {
  const r = rng(seed);
  const streams = names.streams;
  const refs = new Map<string, LogBodyRef>();
  const keyOf = (k: number) => ({
    stream: streams[k % streams.length]!,
    pkHash: names.pkHash(k),
    key: [k] as const,
  });
  const segments: Segment<LogOperation>[] = [];
  const wire: Segment<WireOperation>[] = [];
  for (let position = 1; position <= shape.segments; position += 1) {
    const ops: LogOperation[] = [];
    const wireOps: WireOperation[] = [];
    for (let i = 0; i < shape.opsPerSegment; i += 1) {
      const k = keyOf(r.int(shape.keys));
      const stamp = { o: 1 + r.int(4), r: r.pick(names.runs) };
      const roll = r.next();
      if (roll < 0.6) {
        const big = r.next() < 0.3;
        const value: JsonObject = {
          id: k.key[0],
          v: r.int(3),
          ...(big ? { big: 1 } : {}),
        };
        const ordinal = r.pick([undefined, 0, 1, 2]);
        const op: LogOperation = {
          kind: "upsert",
          stream: k.stream,
          pkHash: k.pkHash,
          stamp,
          ...(ordinal === undefined ? {} : { ordinal }),
          firstSeen: r.pick([null, 1, 2, 3]),
          value,
        };
        ops.push(op);
        if (big) {
          const body: LogBodyRef = {
            sha256: upsertBodyHash(value),
            bytes: JSON.stringify(value).length,
            pieces: [`0x${"ab".repeat(32)}`],
          };
          refs.set(body.sha256, body);
          const {
            value: _value,
            kind: _kind,
            ...rest
          } = op as never as {
            value: JsonObject;
            kind: string;
          } & Record<string, unknown>;
          wireOps.push({ ...rest, kind: "upsert-ref", body } as WireOperation);
        } else wireOps.push(op);
      } else if (roll < 0.75) {
        const op: LogOperation = { kind: "delete", ...k, stamp };
        ops.push(op);
        wireOps.push(op);
      } else {
        const omitted: LogOmission[] = [];
        for (let j = 0; j < 1 + r.int(3); j += 1) {
          const o = keyOf(r.int(shape.keys));
          if (
            o.stream === k.stream &&
            !omitted.some((x) => x.pkHash === o.pkHash)
          )
            omitted.push({ pkHash: o.pkHash, key: o.key });
        }
        omitted.sort((a, b) => (a.pkHash < b.pkHash ? -1 : 1));
        const op: LogOperation = {
          kind: "complete",
          stream: k.stream,
          cutoff: stamp,
          omitted,
        };
        ops.push(op);
        wireOps.push(op);
      }
    }
    const common = {
      format: LOG_FORMAT,
      ...CONTEXT,
      position,
      observedAt: position,
      base: 0,
      snapshot: null,
      refs: [],
      streams: streams.map((s) =>
        meta(s, r.next() < 0.5 ? position : undefined),
      ),
    } as const;
    segments.push({ ...common, operations: ops });
    wire.push({ ...common, operations: wireOps });
  }
  return { segments, wire, refs };
}

/** What `foldLog` returned, written the way the workspace writes a reference. */
function asWire(entries: readonly LogEntry[], refs: Map<string, LogBodyRef>) {
  return entries.map((entry): WireEntry => {
    if (entry.kind !== "upsert" || entry.value.big !== 1) return entry;
    const { value, kind: _kind, ...rest } = entry;
    return {
      ...rest,
      kind: "upsert-ref",
      body: refs.get(upsertBodyHash(value))!,
    };
  });
}

async function fold(
  db: Awaited<ReturnType<typeof database>>,
  input: {
    parts: readonly SnapshotPart<WireEntry>[];
    segments: readonly Segment<WireOperation>[];
  },
) {
  const workspace = await openFoldWorkspace(db, "pdpp.c~", "test");
  for (const part of input.parts) await workspace.addPart(part);
  for (const segment of input.segments) await workspace.addSegment(segment);
  const entries: WireEntry[] = [];
  for await (const page of workspace.pages()) entries.push(...page);
  const streams = workspace.streams();
  await workspace.close();
  return { entries, streams };
}

/** The disk fold and `foldLog` on `count` random histories drawn from `names`. */
async function agreeOnHistories(
  db: SqlDriver,
  names: Names,
  count: number,
  keys: number,
) {
  for (let seed = 1; seed <= count; seed += 1) {
    const h = history(seed, { keys, segments: 8, opsPerSegment: 6 }, names);
    // The first segments are an earlier compaction: their fold, in parts.
    const cut = rng(seed + 9000).int(h.segments.length);
    const earlier = foldLog({
      snapshot: [],
      segments: h.segments.slice(0, cut),
    });
    const parts = partitionFold(
      earlier,
      { ...CONTEXT, generation: 1, position: cut },
      120,
    ).map((p) => ({
      ...p,
      // The parts name their bodies the way a compaction did.
      entries: asWire(p.entries as LogEntry[], h.refs),
    }));
    const tail = h.segments.slice(cut);
    const oracle = foldLog({
      snapshot: parts.map((p) => ({
        ...p,
        entries: p.entries.map((e) =>
          e.kind === "upsert-ref"
            ? ({
                ...e,
                kind: "upsert" as const,
                value: valueOf(h, e.body),
              } as never)
            : e,
        ),
      })) as never,
      segments: tail,
    });
    const mine = await fold(db, {
      parts,
      segments: h.wire.slice(cut),
    });
    expect(mine.entries, `seed ${seed}`).toEqual(
      asWire(oracle.entries, h.refs),
    );
    expect(mine.streams, `seed ${seed}`).toEqual(oracle.streams);
  }
}

describe("the disk fold is foldLog", () => {
  it("agrees on 300 random histories, with a previous snapshot and bodies by reference", async () => {
    await agreeOnHistories(await database(), ASCII, 300, 8);
  });

  it("agrees on 300 random histories whose stream names and run ids sort differently by UTF-8 byte and by UTF-16 unit", async () => {
    await agreeOnHistories(await database(), WIDE, 300, 14);
  });

  it("emits parts the wire accepts, in the key order a reader checks", async () => {
    const db = await database();
    for (let seed = 1; seed <= 100; seed += 1) {
      const h = history(
        seed,
        { keys: 14, segments: 6, opsPerSegment: 8 },
        WIDE,
      );
      const mine = await fold(db, { parts: [], segments: h.wire });
      const partitioner = createPartitioner(
        mine.streams,
        { ...CONTEXT, keyCheck: "0123456789abcdef", position: 6 },
        400,
      );
      const parts = [];
      for (const entry of mine.entries) {
        const closed = partitioner.push(entry as LogEntry);
        if (closed) parts.push(closed);
      }
      parts.push(partitioner.finish());
      const entries: WireEntry[] = [];
      for (const part of parts) {
        // `encodeSnapshotPart` throws on entries out of key order.
        const decoded = decodeSnapshotPart(encodeSnapshotPart(part as never));
        expect(decoded.kind, `seed ${seed}`).toBe("ok");
        entries.push(...(part.entries as WireEntry[]));
      }
      expect(entries, `seed ${seed}`).toEqual(mine.entries);
    }
  });

  it("orders by UTF-16 unit where UTF-8 byte order disagrees (U+E000 against U+10000)", async () => {
    const db = await database();
    const at = (stream: string, run: string, id: number): WireOperation => ({
      kind: "upsert",
      stream,
      pkHash: "a".repeat(64),
      stamp: { o: 1, r: run },
      firstSeen: null,
      value: { id },
    });
    const segment: Segment<LogOperation> = {
      format: LOG_FORMAT,
      ...CONTEXT,
      position: 1,
      observedAt: 1,
      base: 0,
      snapshot: null,
      refs: [],
      streams: [meta("s\uE000"), meta("s\u{10000}")],
      operations: [
        // Two streams: the order of their entries.
        at("s\uE000", "r", 1) as LogOperation,
        at("s\u{10000}", "r", 2) as LogOperation,
        // One key at one stamp number from two runs: the greater run id wins.
        {
          ...at("s\uE000", "\uE000", 3),
          pkHash: "b".repeat(64),
        } as LogOperation,
        {
          ...at("s\uE000", "\u{10000}", 4),
          pkHash: "b".repeat(64),
        } as LogOperation,
      ],
    };
    const oracle = foldLog({ snapshot: [], segments: [segment] });
    const mine = await fold(db, {
      parts: [],
      segments: [segment as unknown as Segment<WireOperation>],
    });
    expect(mine.entries).toEqual(oracle.entries);
    // The oracle's own order: U+10000 is two UTF-16 units, both below U+E000.
    expect(oracle.entries.map((e) => e.stream)).toEqual([
      "s\u{10000}",
      "s\uE000",
      "s\uE000",
    ]);
  });

  it("agrees across many pages", async () => {
    const db = await database();
    const h = history(7, { keys: 400, segments: 6, opsPerSegment: 120 });
    const oracle = foldLog({ snapshot: [], segments: h.segments });
    expect(oracle.entries.length).toBeGreaterThan(200);
    const mine = await fold(db, { parts: [], segments: h.wire });
    expect(mine.entries).toEqual(asWire(oracle.entries, h.refs));
  });

  it("keeps the first of two upserts that are equal in every compared field", async () => {
    const db = await database();
    const stamp = { o: 1, r: "a" };
    const at = (
      firstSeen: number | null,
      position: number,
    ): Segment<LogOperation> => ({
      format: LOG_FORMAT,
      ...CONTEXT,
      position,
      observedAt: position,
      base: 0,
      snapshot: null,
      refs: [],
      streams: [meta("s0")],
      operations: [
        {
          kind: "upsert",
          stream: "s0",
          pkHash: "h0001",
          stamp,
          firstSeen,
          value: { id: 1 },
        },
      ],
    });
    const segments = [at(5, 1), at(null, 2), at(7, 3)];
    const oracle = foldLog({ snapshot: [], segments });
    const mine = await fold(db, { parts: [], segments });
    expect(mine.entries).toEqual(oracle.entries);
    expect((mine.entries[0] as { firstSeen: number | null }).firstSeen).toBe(5);
  });

  it("leaves no rows behind, and clears a crashed operation's", async () => {
    const db = await database();
    const stale = await openFoldWorkspace(db, "pdpp.c~", "test");
    await stale.addSegment(
      history(3, { keys: 4, segments: 1, opsPerSegment: 4 }).wire[0]!,
    );
    // Not closed: a crash. The next workspace of the connection and purpose starts empty.
    const next = await openFoldWorkspace(db, "pdpp.c~", "test");
    const count = async () =>
      (
        await db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM log_fold_cells",
        )
      )[0]!.n;
    expect(await count()).toBe(0);
    await next.addSegment(
      history(4, { keys: 4, segments: 1, opsPerSegment: 4 }).wire[0]!,
    );
    expect(await count()).toBeGreaterThan(0);
    await next.close();
    expect(await count()).toBe(0);
  });
});

function valueOf(h: History, body: LogBodyRef): JsonObject {
  for (const segment of h.segments)
    for (const op of segment.operations)
      if (op.kind === "upsert" && upsertBodyHash(op.value) === body.sha256)
        return op.value;
  throw new Error("a reference names no body of the history");
}

// The cuts below were computed once with `partitionFold` as it is on `main`,
// before the streaming partitioner existed, over the fixture here, and written
// down. They do not follow the code under test: a change to how parts are cut
// changes a part boundary that a reader of the log has already stored.
describe("the streaming partitioner cuts the parts main's partitionFold cut", () => {
  const stamp = (o: number, r = "a") => ({ o, r });
  const upsert = (stream: string, pkHash: string, id: number, pad = 0) => ({
    kind: "upsert" as const,
    stream,
    pkHash,
    stamp: stamp(1),
    firstSeen: null,
    value: pad ? { id, pad: "x".repeat(pad) } : { id },
  });
  const entries: WireEntry[] = [
    upsert("a", "h01", 1),
    upsert("a", "h02", 2, 120),
    upsert("a", "h03", 3, 60),
    {
      kind: "delete",
      stream: "a",
      pkHash: "h04",
      key: ["k4"],
      stamp: stamp(2),
    },
    {
      kind: "omitted",
      stream: "a",
      pkHash: "h05",
      key: ["k5"],
      stamp: stamp(2, "b"),
    },
    upsert("b", "h01", 6, 300),
    upsert("b", "h02", 7),
    upsert("b", "h03", 8, 40),
  ];
  const streams = [meta("a"), meta("b")];
  const context = { ...CONTEXT, position: 4 };

  /** [the smallest target that gives these parts, the parts as the key of each entry]. Every smaller target down to the previous row gives the previous row's parts. */
  const CUTS: readonly (readonly [number, readonly (readonly string[])[]])[] = [
    [
      1,
      [
        ["a/h01"],
        ["a/h02"],
        ["a/h03"],
        ["a/h04"],
        ["a/h05"],
        ["b/h01"],
        ["b/h02"],
        ["b/h03"],
      ],
    ],
    [
      517,
      [
        ["a/h01"],
        ["a/h02"],
        ["a/h03"],
        ["a/h04", "a/h05"],
        ["b/h01"],
        ["b/h02"],
        ["b/h03"],
      ],
    ],
    [
      586,
      [
        ["a/h01"],
        ["a/h02"],
        ["a/h03"],
        ["a/h04", "a/h05"],
        ["b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      596,
      [
        ["a/h01"],
        ["a/h02"],
        ["a/h03", "a/h04"],
        ["a/h05"],
        ["b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      650,
      [
        ["a/h01"],
        ["a/h02"],
        ["a/h03", "a/h04", "a/h05"],
        ["b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      666,
      [
        ["a/h01", "a/h02"],
        ["a/h03", "a/h04", "a/h05"],
        ["b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      799,
      [
        ["a/h01", "a/h02", "a/h03"],
        ["a/h04", "a/h05"],
        ["b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      846,
      [
        ["a/h01", "a/h02", "a/h03"],
        ["a/h04", "a/h05"],
        ["b/h01", "b/h02"],
        ["b/h03"],
      ],
    ],
    [
      853,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04"],
        ["a/h05", "b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      900,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04"],
        ["a/h05", "b/h01", "b/h02"],
        ["b/h03"],
      ],
    ],
    [
      907,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04", "a/h05"],
        ["b/h01", "b/h02"],
        ["b/h03"],
      ],
    ],
    [
      959,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04", "a/h05"],
        ["b/h01", "b/h02", "b/h03"],
      ],
    ],
    [
      1280,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04", "a/h05", "b/h01"],
        ["b/h02", "b/h03"],
      ],
    ],
    [
      1344,
      [
        ["a/h01", "a/h02", "a/h03", "a/h04", "a/h05", "b/h01", "b/h02"],
        ["b/h03"],
      ],
    ],
    [
      1457,
      [
        [
          "a/h01",
          "a/h02",
          "a/h03",
          "a/h04",
          "a/h05",
          "b/h01",
          "b/h02",
          "b/h03",
        ],
      ],
    ],
  ];

  const keys = (parts: readonly { entries: readonly WireEntry[] }[]) =>
    parts.map((part) => part.entries.map((e) => `${e.stream}/${e.pkHash}`));
  const streamed = (target: number) => {
    const partitioner = createPartitioner(streams, context, target);
    const parts = [];
    for (const entry of entries) {
      const closed = partitioner.push(entry);
      if (closed) parts.push(closed);
    }
    parts.push(partitioner.finish());
    return parts;
  };

  it("cuts at the targets where main's cut changes, and one byte before", () => {
    for (const [at, [target, expected]] of CUTS.entries()) {
      expect(keys(streamed(target)), `target ${target}`).toEqual(expected);
      expect(
        keys(partitionFold({ streams, entries }, context, target)),
        `target ${target}`,
      ).toEqual(expected);
      if (at > 0)
        expect(keys(streamed(target - 1)), `target ${target - 1}`).toEqual(
          CUTS[at - 1]![1],
        );
    }
  });

  it("gives the parts the context, their index and the stream metas of the fold", () => {
    const parts = streamed(700);
    expect(parts.map((part) => part.index)).toEqual([0, 1, 2, 3]);
    expect(parts[0]).toEqual({
      format: LOG_FORMAT,
      connector: "c",
      ns: "",
      generation: 1,
      keyCheck: "k",
      position: 4,
      index: 0,
      streams: [
        {
          stream: "a",
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          complete: true,
        },
        {
          stream: "b",
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          complete: true,
        },
      ],
      entries: [entries[0], entries[1]],
    });
    for (const part of parts) expect(part.streams).toEqual(parts[0]!.streams);
  });

  it("yields one part, with the metas and no entries, for a fold with none", () => {
    const partitioner = createPartitioner(streams, context, 400);
    expect(partitioner.finish()).toEqual({
      format: LOG_FORMAT,
      connector: "c",
      ns: "",
      generation: 1,
      keyCheck: "k",
      position: 4,
      index: 0,
      streams: [
        {
          stream: "a",
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          complete: true,
        },
        {
          stream: "b",
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          complete: true,
        },
      ],
      entries: [],
    });
  });
});

/** The bytes a query result holds: what crosses the driver, not how many rows. */
function resultBytes(rows: readonly Record<string, unknown>[]): number {
  let bytes = 0;
  for (const row of rows)
    for (const value of Object.values(row))
      bytes +=
        typeof value === "string"
          ? Buffer.byteLength(value)
          : value instanceof Uint8Array
            ? value.byteLength
            : value === null
              ? 0
              : 8;
  return bytes;
}

describe("a page of the fold is cut by the bytes it holds", () => {
  // The page budget (`PAGE_BYTES`, 2 MiB) and the largest single row below.
  const BUDGET = 2 * 1024 * 1024;
  const BODY = 150_000;

  const wide = (small: number, large: number): Segment<WireOperation> => ({
    format: LOG_FORMAT,
    ...CONTEXT,
    position: 1,
    observedAt: 1,
    base: 0,
    snapshot: null,
    refs: [],
    streams: [meta("s0")],
    operations: Array.from({ length: small + large }, (_, i) => ({
      kind: "upsert" as const,
      stream: "s0",
      pkHash: `h${String(i).padStart(5, "0")}`,
      stamp: { o: 1, r: "a" },
      firstSeen: null,
      // Small rows first, large ones after: what a size taken from the
      // previous page does not see coming.
      value: i < small ? { id: i } : { id: i, pad: "x".repeat(BODY) },
    })),
  });

  /** Fold `segment` and read it back, measuring every query of the read-back. */
  async function readBack(segment: Segment<WireOperation>) {
    const db = await database();
    let largest = 0;
    let queries = 0;
    const spy = {
      batch: (statements: Parameters<SqlDriver["batch"]>[0]) =>
        db.batch(statements),
      query: async <R extends Record<string, never>>(
        sql: string,
        params?: Parameters<SqlDriver["query"]>[1],
      ) => {
        const rows = await db.query<R>(sql, params);
        queries += 1;
        largest = Math.max(largest, resultBytes(rows));
        return rows;
      },
    } as unknown as Pick<SqlDriver, "batch" | "query">;
    const workspace = await openFoldWorkspace(spy, "pdpp.c~", "test");
    await workspace.addSegment(segment);
    queries = 0;
    const entries: WireEntry[] = [];
    for await (const page of workspace.pages()) entries.push(...page);
    await workspace.close();
    return { entries, largest, queries };
  }

  it("small rows followed by large bodies stay inside the budget plus one row", async () => {
    const segment = wide(60, 120);
    const { entries, largest } = await readBack(segment);
    const oracle = foldLog({
      snapshot: [],
      segments: [segment as unknown as Segment<LogOperation>],
    });
    expect(entries).toEqual(oracle.entries);
    // 120 bodies of 150 KB are 18 MB; no query result may hold more than the
    // budget and the one row that crosses it.
    expect(largest).toBeLessThanOrEqual(BUDGET + BODY + 1000);
  });

  it("a row larger than the budget is a page of its own", async () => {
    const segment = wide(0, 3);
    const big = segment.operations[1] as { value: { pad: string } };
    big.value.pad = "y".repeat(3 * 1024 * 1024);
    const { entries, largest } = await readBack(segment);
    expect(entries).toHaveLength(3);
    expect(largest).toBeLessThanOrEqual(3 * 1024 * 1024 + BODY + 1000);
  });
});

describe("every write of the workspace and the spool fits the phone bridge's frame", () => {
  const values = (
    count: number,
    make: (i: number) => JsonObject,
  ): Segment<WireOperation> => ({
    format: LOG_FORMAT,
    ...CONTEXT,
    position: 1,
    observedAt: 1,
    base: 0,
    snapshot: null,
    refs: [],
    streams: [meta("s0")],
    operations: Array.from({ length: count }, (_, i) => ({
      kind: "upsert" as const,
      stream: "s0",
      pkHash: `h${String(i).padStart(5, "0")}`,
      stamp: { o: 1, r: "a" },
      firstSeen: null,
      value: make(i),
    })),
  });

  /** Fold `segment` through a driver with the bridge's limits and read the winners back. */
  async function foldFramed(segment: Segment<WireOperation>) {
    const db = frameLimited(await database());
    const workspace = await openFoldWorkspace(db, "pdpp.c~", "test");
    await workspace.addSegment(segment);
    const entries: WireEntry[] = [];
    for await (const page of workspace.pages()) entries.push(...page);
    await workspace.close();
    const oracle = foldLog({
      snapshot: [],
      segments: [segment as unknown as Segment<LogOperation>],
    });
    expect(entries).toEqual(oracle.entries);
    return db.frames;
  }

  it("a segment of many 100 KB bodies is written in requests under 4 MiB", async () => {
    // 150 bodies are 15 MB: 200 operations to a batch put all of it in one request.
    const frames = await foldFramed(
      values(150, (i) => ({ id: i, pad: "x".repeat(100_000) })),
    );
    expect(frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
  });

  it("bodies over 1 MiB are staged one to a request, never more than the bridge holds", async () => {
    // Ten bodies of 1.5 MiB: a batch of all of them stages ten values, the bridge eight.
    const frames = await foldFramed(
      values(10, (i) => ({ id: i, pad: "x".repeat(1_500_000) })),
    );
    expect(frames.mostStaged).toBeLessThanOrEqual(1);
    expect(frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
  });

  it("bodies made of quotes, which the request escapes a second time, stay under the frame", async () => {
    // A stored body of 900 KB of `\"` is 1.8 MB in a request.
    const frames = await foldFramed(
      values(12, (i) => ({ id: i, pad: '"'.repeat(450_000) })),
    );
    expect(frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
  });

  it("deletes with large keys are written in requests under 4 MiB", async () => {
    const segment = values(0, () => ({}));
    segment.operations = Array.from({ length: 60 }, (_, i) => ({
      kind: "delete" as const,
      stream: "s0",
      pkHash: `h${String(i).padStart(5, "0")}`,
      stamp: { o: 1, r: "a" },
      key: ["k".repeat(200_000)],
    }));
    const frames = await foldFramed(segment);
    expect(frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
  });

  it("a spool holds objects of any size in requests and replies under 4 MiB", async () => {
    const db = frameLimited(await database());
    const spool = openSpool(db, "pdpp.c~", "op-1");
    const sizes = [0, 1, 1_048_576, 1_048_577, 4 * 1024 * 1024, 3_000_001];
    for (const [i, size] of sizes.entries())
      await spool.add(`v-${i}`, new Uint8Array(size).fill(i + 1));
    for (const [i, object] of spool.objects().entries()) {
      const bytes = await object.read();
      expect(bytes.length).toBe(sizes[i]);
      if (sizes[i]! > 0) expect(bytes[sizes[i]! - 1]).toBe(i + 1);
    }
    expect(db.frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
    expect(db.frames.largestReply).toBeLessThan(SQL_FRAME_BYTES);
    await spool.discard();
  });
});
