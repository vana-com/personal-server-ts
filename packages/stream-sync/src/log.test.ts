import { describe, expect, it } from "vitest";
import { utf8 } from "./bytes.js";
import {
  APPLY_MS_PER_SEGMENT,
  BLOB_BYTES_PER_MS,
  GET_TTFB_MS,
  PUT_MS,
  compactionCost,
  compactionRequired,
  decodeSegment,
  decodeSnapshotPart,
  digestSnapshotPart,
  encodeSnapshotPart,
  firstDeletionKeyMismatch,
  foldLog,
  partitionFold,
  shouldCompact,
  snapshotPartBlobName,
  digestSegment,
  encodeSegment,
  isSegmentBlobName,
  logScope,
  LOG_FORMAT,
  maxSegmentRefs,
  planOpsSince,
  segmentBlobName,
  stampAfter,
  verifySegment,
  type Segment,
  type SegmentRef,
  type SnapshotPart,
} from "./log.js";
import { pkHash } from "./records.js";
import { keccak256, nodePorts } from "./test-support/ports.js";

const hash = (n: number): `0x${string}` =>
  `0x${n.toString(16).padStart(64, "0")}`;
const pk = (n: number) => n.toString(16).padStart(64, "0");
/** The canonical record key a test gives key `n`; a hash is not its inverse. */
const rk = (n: number) => [`record-${n}`];
const om = (n: number) => ({ pkHash: pk(n), key: rk(n) });

function refs(from: number, to: number): SegmentRef[] {
  const out: SegmentRef[] = [];
  for (let p = from; p <= to; p += 1)
    out.push({ position: p, dataHash: hash(p), bytes: 100 + p });
  return out;
}

function segment(over: Partial<Segment> = {}): Segment {
  return {
    format: LOG_FORMAT,
    connector: "c",
    ns: "fedcba9876543210",
    generation: 1,
    keyCheck: "0123456789abcdef",
    position: 4,
    observedAt: 10,
    base: 0,
    snapshot: null,
    refs: refs(1, 3),
    streams: [
      {
        stream: "a",
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
        complete: true,
      },
      {
        stream: "b",
        primaryKey: ["id"],
        profile: { key: null, version: "1.0.0" },
        complete: false,
      },
    ],
    operations: [
      {
        kind: "upsert",
        stream: "a",
        pkHash: pk(1),
        stamp: { o: 5, r: "run-1" },
        firstSeen: 3,
        value: { id: "1", n: 1 },
      },
      {
        kind: "delete",
        stream: "b",
        pkHash: pk(2),
        key: rk(2),
        stamp: { o: 6, r: "run-1" },
      },
      {
        kind: "complete",
        stream: "a",
        cutoff: { o: 7, r: "run-2" },
        omitted: [om(3), om(4)],
      },
    ],
    ...over,
  };
}

const expected = (s: Segment, dataHash: string) => ({
  dataHash,
  connector: s.connector,
  ns: s.ns,
  keyCheck: s.keyCheck,
});

describe("segment codec", () => {
  it("round-trips and is canonical", () => {
    const s = segment();
    const bytes = encodeSegment(s);
    const decoded = decodeSegment(bytes);
    expect(decoded).toEqual({ kind: "ok", segment: s });
    expect(encodeSegment((decoded as { segment: Segment }).segment)).toEqual(
      bytes,
    );
  });

  it("rejects non-canonical bytes, other formats and unknown fields", () => {
    const bytes = encodeSegment(segment());
    const text = new TextDecoder().decode(bytes);
    expect(decodeSegment(utf8(`${text} `)).kind).toBe("malformed");
    expect(
      decodeSegment(utf8(text.replace(`"format":${LOG_FORMAT}`, '"format":9'))),
    ).toMatchObject({ kind: "unsupported_format", format: 9 });
    expect(decodeSegment(utf8(text.replace("{", '{"extra":1,'))).kind).toBe(
      "malformed",
    );
  });

  it("rejects refs with a gap or the wrong dense positions", () => {
    expect(() =>
      encodeSegment(segment({ refs: [...refs(1, 1), ...refs(3, 3)] })),
    ).toThrow(/dense/);
    expect(() => encodeSegment(segment({ base: 1 }))).toThrow(/dense/);
  });

  it("rejects an operation on a stream with no meta and the reserved log stream", () => {
    const bad = segment({
      operations: [
        {
          kind: "delete",
          stream: "zz",
          pkHash: pk(1),
          key: rk(1),
          stamp: { o: 1, r: "r" },
        },
      ],
    });
    expect(() => encodeSegment(bad)).toThrow(/no meta/);
    const reserved = segment({
      streams: [
        {
          stream: "~log",
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          complete: true,
        },
      ],
      operations: [],
    });
    expect(() => encodeSegment(reserved)).toThrow(/invalid/);
  });

  it("requires an ascending, distinct omitted set", () => {
    const bad = segment({
      operations: [
        {
          kind: "complete",
          stream: "a",
          cutoff: { o: 1, r: "r" },
          omitted: [om(4), om(3)],
        },
      ],
    });
    expect(() => encodeSegment(bad)).toThrow(/ascending/);
  });
});

describe("segment identity", () => {
  it("names the blob from the data hash and verifies it", async () => {
    const s = segment();
    const bytes = encodeSegment(s);
    const digest = await digestSegment(keccak256, bytes);
    expect(digest.blobName).toBe(segmentBlobName(digest.dataHash));
    expect(isSegmentBlobName(digest.blobName)).toBe(true);
    expect(logScope("c", "fedcba9876543210")).toMatch(/\.~log$/);
    expect(
      await verifySegment(keccak256, bytes, {
        ...expected(s, digest.dataHash),
        position: 4,
      }),
    ).toMatchObject({ kind: "ok" });
    expect(await verifySegment(keccak256, bytes, expected(s, hash(9)))).toEqual(
      { kind: "hash_mismatch" },
    );
    expect(
      await verifySegment(keccak256, bytes, {
        ...expected(s, digest.dataHash),
        position: 5,
      }),
    ).toEqual({ kind: "position_mismatch" });
    expect(
      await verifySegment(keccak256, bytes, {
        ...expected(s, digest.dataHash),
        keyCheck: "ffffffffffffffff",
      }),
    ).toEqual({ kind: "key_mismatch" });
    expect(
      await verifySegment(keccak256, bytes, {
        ...expected(s, digest.dataHash),
        connector: "other",
      }),
    ).toEqual({ kind: "name_mismatch" });
  });
});

describe("ops since", () => {
  const head = segment();
  const headRef: SegmentRef = { position: 4, dataHash: hash(4), bytes: 1 };

  it("is current at the head position", () => {
    expect(planOpsSince(head, headRef, 4)).toEqual({ kind: "current" });
  });

  it("lists only newer segments, oldest first, ending at the head", () => {
    expect(planOpsSince(head, headRef, 2)).toEqual({
      kind: "segments",
      refs: [...refs(3, 3), headRef],
    });
    expect(planOpsSince(head, headRef, 0)).toEqual({
      kind: "segments",
      refs: [...refs(1, 3), headRef],
    });
    expect(planOpsSince(head, headRef, 3)).toEqual({
      kind: "segments",
      refs: [headRef],
    });
  });

  it("answers a gap when the log cannot cover the position", () => {
    const compacted = segment({
      base: 2,
      refs: refs(3, 3),
      position: 4,
      snapshot: {
        position: 2,
        heads: [{ stream: "a", version: 1, dataHash: hash(1) }],
      },
    });
    expect(planOpsSince(compacted, headRef, 1)).toEqual({
      kind: "gap",
      reason: "behind_base",
    });
    expect(planOpsSince(head, headRef, 9)).toEqual({
      kind: "gap",
      reason: "ahead_of_head",
    });
  });
});

describe("bounds and stamps", () => {
  it("derives the ref bound from the head limit", () => {
    expect(maxSegmentRefs()).toBe(Math.floor((1024 * 1024) / 160));
    expect(compactionRequired(maxSegmentRefs() - 1)).toBe(false);
    expect(compactionRequired(maxSegmentRefs())).toBe(true);
  });

  it("orders stamps by time then run id", () => {
    expect(stampAfter({ o: 2, r: "a" }, { o: 1, r: "z" })).toBe(true);
    expect(stampAfter({ o: 1, r: "b" }, { o: 1, r: "a" })).toBe(true);
    expect(stampAfter({ o: 1, r: "a" }, { o: 1, r: "a" })).toBe(false);
  });
});

const meta = (stream: string) => ({
  stream,
  primaryKey: ["id"],
  profile: { key: null, version: "1.0.0" },
  complete: true,
});
const up = (stream: string, n: number, o: number, r = "r") => ({
  kind: "upsert" as const,
  stream,
  pkHash: pk(n),
  stamp: { o, r },
  firstSeen: o,
  value: { id: String(n), at: o },
});
const del = (stream: string, n: number, o: number, r = "r") => ({
  kind: "delete" as const,
  stream,
  pkHash: pk(n),
  key: rk(n),
  stamp: { o, r },
});
const seg = (position: number, operations: Segment["operations"]) =>
  segment({
    position,
    base: 0,
    refs: refs(1, position - 1),
    streams: [meta("a")],
    operations,
  });

describe("fold (P4)", () => {
  it("keeps the latest winner per key and a deletion that wins as a tombstone", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [
        seg(3, [up("a", 1, 9), del("a", 2, 8)]),
        seg(1, [up("a", 1, 5), up("a", 2, 4), up("a", 3, 4)]),
        seg(2, [
          up("a", 3, 6),
          {
            kind: "complete",
            stream: "a",
            cutoff: { o: 7, r: "r" },
            omitted: [om(3)],
          },
        ]),
      ],
    });
    const byKey = new Map(fold.entries.map((e) => [e.pkHash, e]));
    // key 1: the later upsert; keys 2 and 3: deleted after their last upsert
    expect(byKey.get(pk(1))).toMatchObject({ kind: "upsert", stamp: { o: 9 } });
    expect(byKey.get(pk(2))).toMatchObject({ kind: "delete", stamp: { o: 8 } });
    expect(byKey.get(pk(3))).toMatchObject({
      kind: "omitted",
      stamp: { o: 7 },
    });
    expect(fold.entries).toHaveLength(3);
  });

  it("an upsert after the deletion wins, and a tie goes to the deletion", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [
        seg(1, [del("a", 1, 5), up("a", 1, 6), up("a", 2, 5), del("a", 2, 5)]),
      ],
    });
    const byKey = new Map(fold.entries.map((e) => [e.pkHash, e.kind]));
    expect(byKey.get(pk(1))).toBe("upsert");
    expect(byKey.get(pk(2))).toBe("delete");
  });

  it("folding a snapshot with its tail equals folding everything at once", () => {
    const all = [
      seg(1, [up("a", 1, 1), up("a", 2, 1), up("a", 3, 1)]),
      seg(2, [del("a", 2, 2), up("a", 1, 2)]),
      seg(3, [up("a", 2, 3), del("a", 3, 3)]),
      seg(4, [up("a", 4, 4), del("a", 1, 4)]),
    ];
    const context = {
      connector: "c",
      ns: "fedcba9876543210",
      generation: 1,
      keyCheck: "0123456789abcdef",
      position: 2,
    };
    const prefix = partitionFold(
      foldLog({ snapshot: [], segments: all.slice(0, 2) }),
      context,
      1, // one entry per part
    );
    expect(prefix.length).toBeGreaterThan(1);
    expect(foldLog({ snapshot: prefix, segments: all.slice(2) })).toEqual(
      foldLog({ snapshot: [], segments: all }),
    );
  });

  it("splits into key-ordered parts that carry every stream meta, and an empty fold still has one", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [seg(1, [up("a", 3, 1), up("a", 1, 1), up("a", 2, 1)])],
    });
    const context = {
      connector: "c",
      ns: "fedcba9876543210",
      generation: 1,
      keyCheck: "0123456789abcdef",
      position: 1,
    };
    const parts = partitionFold(fold, context, 1);
    expect(parts.map((p) => p.index)).toEqual([0, 1, 2]);
    expect(parts.flatMap((p) => p.entries.map((e) => e.pkHash))).toEqual([
      pk(1),
      pk(2),
      pk(3),
    ]);
    for (const part of parts) expect(part.streams).toEqual(fold.streams);
    expect(
      partitionFold({ streams: fold.streams, entries: [] }, context),
    ).toHaveLength(1);
  });
});

describe("snapshot part codec", () => {
  const part = () =>
    partitionFold(
      foldLog({
        snapshot: [],
        segments: [seg(1, [up("a", 1, 1), del("a", 2, 2)])],
      }),
      {
        connector: "c",
        ns: "fedcba9876543210",
        generation: 1,
        keyCheck: "0123456789abcdef",
        position: 1,
      },
    )[0]!;

  it("round-trips, is canonical, and is addressed by its data hash", async () => {
    const bytes = encodeSnapshotPart(part());
    const decoded = decodeSnapshotPart(bytes);
    expect(decoded.kind).toBe("ok");
    if (decoded.kind === "ok")
      expect(encodeSnapshotPart(decoded.part)).toEqual(bytes);
    const digest = await digestSnapshotPart(keccak256, bytes);
    expect(digest.blobName).toBe(snapshotPartBlobName(digest.dataHash));
    expect(digest.blobName).toMatch(/^q-[0-9a-f]{64}$/);
  });

  it("rejects non-canonical bytes, other formats and completion entries", () => {
    const bytes = encodeSnapshotPart(part());
    const text = new TextDecoder().decode(bytes);
    expect(decodeSnapshotPart(utf8(`${text} `)).kind).toBe("malformed");
    expect(
      decodeSnapshotPart(
        utf8(text.replace(`"format":${LOG_FORMAT}`, '"format":9')),
      ).kind,
    ).toBe("unsupported_format");
    expect(decodeSnapshotPart(utf8("[]")).kind).toBe("malformed");
  });
});

describe("when to compact", () => {
  it("compacts when replaying the tail costs more than a snapshot fetch plus building it", () => {
    const small = (n: number) =>
      shouldCompact({ tailSegments: n, tailBytes: n * 2000, snapshotBytes: 0 });
    // Derived from the measured primitives, not a constant: the first n at
    // which the saving per catch-up exceeds the one-time cost.
    const first = Array.from({ length: 200 }, (_, i) => i + 1).find(small)!;
    expect(first).toBeGreaterThan(1);
    expect(small(first - 1)).toBe(false);
    for (let n = first; n <= 200; n++) expect(small(n)).toBe(true);
    const cost = compactionCost({
      tailSegments: first,
      tailBytes: first * 2000,
      snapshotBytes: 0,
    });
    expect(cost.replayMs - cost.snapshotMs).toBeGreaterThan(cost.compactMs);
    expect(cost.replayMs).toBeCloseTo(
      GET_TTFB_MS +
        (first * 2000) / BLOB_BYTES_PER_MS +
        first * APPLY_MS_PER_SEGMENT,
    );
    expect(cost.compactMs).toBeCloseTo(
      GET_TTFB_MS + (first * 2000) / BLOB_BYTES_PER_MS + cost.parts * PUT_MS,
    );
  });

  it("never compacts an empty tail, and a large existing snapshot raises the bar", () => {
    expect(
      shouldCompact({ tailSegments: 0, tailBytes: 0, snapshotBytes: 0 }),
    ).toBe(false);
    const tail = { tailSegments: 40, tailBytes: 80_000 };
    expect(shouldCompact({ ...tail, snapshotBytes: 0 })).toBe(true);
    expect(shouldCompact({ ...tail, snapshotBytes: 64 * 1024 * 1024 })).toBe(
      false,
    );
  });
});

const complete = (stream: string, omitted: number[], o: number, r = "r") => ({
  kind: "complete" as const,
  stream,
  cutoff: { o, r },
  omitted: omitted
    .map(om)
    .sort((x, y) => (x.pkHash < y.pkHash ? -1 : x.pkHash > y.pkHash ? 1 : 0)),
});
const kindsOf = (
  entries: readonly { kind: string; pkHash: string }[],
  n: number,
) => entries.filter((e) => e.pkHash === pk(n)).map((e) => e.kind);

describe("fold: boundary kinds (P2-1)", () => {
  it("an omission at the stamp of an upsert loses to it; an explicit delete there wins", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [
        seg(1, [up("a", 1, 5), complete("a", [1], 5)]),
        seg(2, [up("a", 2, 5), del("a", 2, 5)]),
      ],
    });
    // 1: the observation at the cutoff survives, and no tombstone is needed
    expect(kindsOf(fold.entries, 1)).toEqual(["upsert"]);
    // 2: an explicit delete at the same stamp wins
    expect(kindsOf(fold.entries, 2)).toEqual(["delete"]);
  });

  it("an omission that wins is its own entry kind, not an explicit delete", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [seg(1, [up("a", 1, 4), complete("a", [1], 5)])],
    });
    expect(kindsOf(fold.entries, 1)).toEqual(["omitted"]);
  });

  it("an explicit delete and an omission at one stamp keep the explicit delete", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [seg(1, [complete("a", [1], 5), del("a", 1, 5)])],
    });
    expect(kindsOf(fold.entries, 1)).toEqual(["delete"]);
  });

  it("the fold is the same in either order of the same operations at equality", () => {
    const ops = [
      up("a", 1, 5),
      complete("a", [1], 5),
      up("a", 2, 5),
      del("a", 2, 5),
    ];
    const forward = foldLog({ snapshot: [], segments: [seg(1, ops)] });
    const reverse = foldLog({
      snapshot: [],
      segments: [seg(1, [...ops].reverse())],
    });
    expect(reverse).toEqual(forward);
  });
});

describe("fold: the deletion frontier (P2-3)", () => {
  it("a resurrection keeps the deletion it came after, and its first-seen is the resurrection's", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [
        seg(1, [up("a", 1, 10)]),
        seg(2, [del("a", 1, 20)]),
        seg(3, [{ ...up("a", 1, 30), firstSeen: 30 }]),
      ],
    });
    expect(fold.entries.filter((e) => e.pkHash === pk(1))).toEqual([
      {
        kind: "delete",
        stream: "a",
        pkHash: pk(1),
        key: rk(1),
        stamp: { o: 20, r: "r" },
      },
      expect.objectContaining({
        kind: "upsert",
        firstSeen: 30,
        stamp: { o: 30, r: "r" },
      }),
    ]);
  });

  it("the fold carries the winner's first-seen: an unknown one stays unknown, a late delete changes nothing (P2-a, P2-b)", () => {
    const firstSeenOf = (segments: Segment[]) =>
      foldLog({ snapshot: [], segments }).entries.find(
        (e) => e.kind === "upsert",
      );
    // An unknown first-seen at the lower stamp, a known one at the higher.
    expect(
      firstSeenOf([
        seg(1, [{ ...up("a", 1, 10), firstSeen: null }]),
        seg(2, [up("a", 1, 30)]),
      ]),
    ).toMatchObject({ firstSeen: 30 });
    // The same two upserts the other way round.
    expect(
      firstSeenOf([
        seg(1, [up("a", 1, 30)]),
        seg(2, [{ ...up("a", 1, 10), firstSeen: null }]),
      ]),
    ).toMatchObject({ firstSeen: 30 });
    // The winner's own unknown first-seen is not replaced by an older known one.
    expect(
      firstSeenOf([
        seg(1, [up("a", 1, 10)]),
        seg(2, [{ ...up("a", 1, 30), firstSeen: null }]),
      ]),
    ).toMatchObject({ firstSeen: null });
    // A delete between the two upserts, applied last, leaves the winner alone.
    expect(
      firstSeenOf([
        seg(1, [up("a", 1, 10)]),
        seg(2, [up("a", 1, 30)]),
        seg(3, [del("a", 1, 20)]),
      ]),
    ).toMatchObject({ firstSeen: 30, stamp: { o: 30, r: "r" } });
  });

  it("folding in two steps keeps the frontier", () => {
    const all = [
      seg(1, [up("a", 1, 10)]),
      seg(2, [del("a", 1, 20)]),
      seg(3, [{ ...up("a", 1, 30), firstSeen: 30 }]),
      seg(4, [up("a", 2, 40)]),
    ];
    const context = {
      connector: "c",
      ns: "fedcba9876543210",
      generation: 1,
      keyCheck: "0123456789abcdef",
      position: 3,
    };
    const prefix = partitionFold(
      foldLog({ snapshot: [], segments: all.slice(0, 3) }),
      context,
      1,
    );
    expect(foldLog({ snapshot: prefix, segments: all.slice(3) })).toEqual(
      foldLog({ snapshot: [], segments: all }),
    );
  });

  it("a part holds a tombstone and the upsert of one key, in that order, and no other repeat", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [seg(1, [up("a", 1, 10), del("a", 1, 20), up("a", 1, 30)])],
    });
    const part = partitionFold(fold, {
      connector: "c",
      ns: "fedcba9876543210",
      generation: 1,
      keyCheck: "0123456789abcdef",
      position: 1,
    })[0]!;
    const decoded = decodeSnapshotPart(encodeSnapshotPart(part));
    expect(decoded.kind).toBe("ok");
    if (decoded.kind !== "ok") return;
    const twice = {
      ...decoded.part,
      entries: [part.entries[1]!, part.entries[1]!],
    };
    expect(() => encodeSnapshotPart(twice)).toThrow();
    const reversed = {
      ...decoded.part,
      entries: [part.entries[1]!, part.entries[0]!],
    };
    expect(() => encodeSnapshotPart(reversed)).toThrow();
  });

  it("a segment cannot carry a snapshot-only omission entry", () => {
    const omitted = {
      kind: "omitted" as const,
      stream: "a",
      pkHash: pk(1),
      key: rk(1),
      stamp: { o: 5, r: "r" },
    };
    expect(() =>
      encodeSegment(segment({ operations: [omitted as never] })),
    ).toThrow(/snapshot entry/);
    // Bytes that a hostile writer made by hand are refused on decode too.
    const bytes = new TextDecoder()
      .decode(encodeSegment(segment()))
      .replace('"k":"d"', '"k":"o"');
    expect(decodeSegment(utf8(bytes)).kind).toBe("malformed");
  });
});

// The canonical record key travels with every deletion, because a deletion
// has no data to derive it from (an upsert has: its value and the stream's
// primary key). A hash is one-way and drops the key's types, so a replica that
// never held the record cannot recover the key from it.
describe("deletions carry the canonical record key", () => {
  const context = {
    connector: "c",
    ns: "fedcba9876543210",
    generation: 1,
    keyCheck: "0123456789abcdef",
    position: 1,
  };
  const wireOf = (bytes: Uint8Array) =>
    JSON.parse(new TextDecoder().decode(bytes)) as {
      operations?: Record<string, unknown>[];
      entries?: Record<string, unknown>[];
    };

  it("a segment's delete and completion round-trip with their keys", () => {
    const s = segment();
    const decoded = decodeSegment(encodeSegment(s));
    expect(decoded).toEqual({ kind: "ok", segment: s });
    const ops = (decoded as { segment: Segment }).segment.operations;
    expect(ops[1]).toMatchObject({ kind: "delete", key: rk(2) });
    expect(ops[2]).toMatchObject({
      kind: "complete",
      omitted: [om(3), om(4)],
    });
    // The wire form names the key beside the hash, never instead of it.
    const wire = wireOf(encodeSegment(s)).operations!;
    expect(wire[1]).toMatchObject({ k: "d", p: pk(2), rk: rk(2) });
    expect(wire[2]).toMatchObject({
      k: "c",
      omit: [
        { p: pk(3), rk: rk(3) },
        { p: pk(4), rk: rk(4) },
      ],
    });
  });

  it("the fold keeps the key on the tombstone of a key it never saw an upsert for", () => {
    const fold = foldLog({
      snapshot: [],
      segments: [
        seg(1, [del("a", 2, 8), complete("a", [3], 7)]),
        seg(2, [up("a", 4, 1), complete("a", [4], 5)]),
      ],
    });
    const entry = (n: number) => fold.entries.find((e) => e.pkHash === pk(n));
    expect(entry(2)).toMatchObject({ kind: "delete", key: rk(2) });
    expect(entry(3)).toMatchObject({ kind: "omitted", key: rk(3) });
    expect(entry(4)).toMatchObject({ kind: "omitted", key: rk(4) });
  });

  it("a snapshot part carries the key of its delete and omitted entries, and a second fold keeps it", () => {
    const first = foldLog({
      snapshot: [],
      segments: [
        seg(1, [del("a", 2, 8), complete("a", [3], 7), up("a", 5, 1)]),
      ],
    });
    const parts = partitionFold(first, context, 1);
    const wires = parts.flatMap(
      (p) => wireOf(encodeSnapshotPart(p)).entries ?? [],
    );
    expect(wires.find((w) => w["k"] === "d")).toMatchObject({
      p: pk(2),
      rk: rk(2),
    });
    expect(wires.find((w) => w["k"] === "o")).toMatchObject({
      p: pk(3),
      rk: rk(3),
    });
    const decoded = parts.map((p) => decodeSnapshotPart(encodeSnapshotPart(p)));
    expect(decoded.every((d) => d.kind === "ok")).toBe(true);
    const reloaded = decoded.map((d) => (d as { part: SnapshotPart }).part);
    const refolded = foldLog({ snapshot: reloaded, segments: [] });
    expect(refolded.entries).toEqual(first.entries);
    expect(
      refolded.entries.filter((e) => e.kind !== "upsert").map((e) => e.key),
    ).toEqual([rk(2), rk(3)]);
  });

  it("refuses a deletion that names no key, or names it badly", () => {
    const text = new TextDecoder().decode(encodeSegment(segment()));
    const without = text.replace(`"rk":["record-2"],`, "");
    expect(without).not.toBe(text);
    expect(decodeSegment(utf8(without)).kind).toBe("malformed");
    const typed = text.replace(`"rk":["record-2"]`, '"rk":"record-2"');
    expect(typed).not.toBe(text);
    expect(decodeSegment(utf8(typed)).kind).toBe("malformed");
    for (const bad of ["[]", "[null]", "[[1]]", '[{"a":1}]']) {
      const odd = text.replace(`"rk":["record-2"]`, `"rk":${bad}`);
      expect(decodeSegment(utf8(odd)).kind).toBe("malformed");
    }
    // The old completion shape, a bare list of hashes, is not read either.
    const bare = text.replace(
      /"omit":\[[^\]]*\]/,
      `"omit":["${pk(3)}","${pk(4)}"]`,
    );
    expect(bare).not.toBe(text);
    expect(decodeSegment(utf8(bare)).kind).toBe("malformed");
    // An upsert needs none: its key derives from its value.
    expect(text).not.toMatch(/"k":"u"[^}]*"rk"/);
  });

  it("a hash-only segment of format 1 is unsupported, not read as keyless", () => {
    // What this build wrote before the key: format 1, `omit` a list of hashes.
    const old = new TextDecoder()
      .decode(encodeSegment(segment()))
      .replace(`"format":${LOG_FORMAT}`, '"format":1')
      .replace(`,"rk":["record-2"]`, "");
    expect(LOG_FORMAT).toBe(2);
    expect(decodeSegment(utf8(old))).toEqual({
      kind: "unsupported_format",
      format: 1,
    });
    const part = new TextDecoder()
      .decode(
        encodeSnapshotPart(
          partitionFold(
            foldLog({ snapshot: [], segments: [seg(1, [del("a", 2, 8)])] }),
            context,
          )[0]!,
        ),
      )
      .replace(`"format":${LOG_FORMAT}`, '"format":1');
    expect(decodeSnapshotPart(utf8(part)).kind).toBe("unsupported_format");
  });
});

describe("a deletion's key is bound to its hash", () => {
  const sha256 = nodePorts.sha256;
  const hashOf = (id: string | number) => pkHash(sha256, { id }, ["id"]);
  const metas = [meta("a")];
  const delOf = async (hashFor: string | number, key: (string | number)[]) => ({
    kind: "delete" as const,
    stream: "a",
    pkHash: await hashOf(hashFor),
    key,
    stamp: { o: 1, r: "r" },
  });

  it("accepts each form of deletion whose key is the one its hash covers, of either type", async () => {
    const ops = [
      await delOf("A", ["A"]),
      await delOf(1, [1]),
      await delOf("1", ["1"]),
      {
        kind: "omitted" as const,
        stream: "a",
        pkHash: await hashOf(2),
        key: [2],
        stamp: { o: 1, r: "r" },
      },
      {
        kind: "complete" as const,
        stream: "a",
        cutoff: { o: 2, r: "r" },
        omitted: [{ pkHash: await hashOf("3"), key: ["3"] }],
      },
    ];
    expect(await firstDeletionKeyMismatch(sha256, metas, ops)).toBeNull();
  });

  it("names the first delete, omitted entry or completion omission whose key is another's", async () => {
    const wrong = await delOf("A", ["B"]);
    expect(await firstDeletionKeyMismatch(sha256, metas, [wrong])).toEqual({
      stream: "a",
      pkHash: wrong.pkHash,
    });
    const omitted = { ...wrong, kind: "omitted" as const };
    expect(
      await firstDeletionKeyMismatch(sha256, metas, [omitted]),
    ).toMatchObject({
      pkHash: wrong.pkHash,
    });
    const complete = {
      kind: "complete" as const,
      stream: "a",
      cutoff: { o: 2, r: "r" },
      omitted: [
        { pkHash: await hashOf("ok"), key: ["ok"] },
        { pkHash: wrong.pkHash, key: ["B"] },
      ],
    };
    expect(
      await firstDeletionKeyMismatch(sha256, metas, [complete]),
    ).toMatchObject({
      pkHash: wrong.pkHash,
    });
  });

  it("does not take 1 for '1': a key of the other type names another record", async () => {
    const asNumber = await delOf("1", [1]);
    const asString = await delOf(1, ["1"]);
    expect(
      await firstDeletionKeyMismatch(sha256, metas, [asNumber]),
    ).not.toBeNull();
    expect(
      await firstDeletionKeyMismatch(sha256, metas, [asString]),
    ).not.toBeNull();
  });
});
