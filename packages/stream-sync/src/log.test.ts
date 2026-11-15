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
} from "./log.js";
import { keccak256 } from "./test-support/ports.js";

const hash = (n: number): `0x${string}` =>
  `0x${n.toString(16).padStart(64, "0")}`;
const pk = (n: number) => n.toString(16).padStart(64, "0");

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
        stamp: { o: 6, r: "run-1" },
      },
      {
        kind: "complete",
        stream: "a",
        cutoff: { o: 7, r: "run-2" },
        omitted: [pk(3), pk(4)],
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
      decodeSegment(utf8(text.replace('"format":1', '"format":2'))),
    ).toMatchObject({ kind: "unsupported_format", format: 2 });
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
          omitted: [pk(4), pk(3)],
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
            omitted: [pk(3)],
          },
        ]),
      ],
    });
    const byKey = new Map(fold.entries.map((e) => [e.pkHash, e]));
    // key 1: the later upsert; keys 2 and 3: deleted after their last upsert
    expect(byKey.get(pk(1))).toMatchObject({ kind: "upsert", stamp: { o: 9 } });
    expect(byKey.get(pk(2))).toMatchObject({ kind: "delete", stamp: { o: 8 } });
    expect(byKey.get(pk(3))).toMatchObject({ kind: "delete", stamp: { o: 7 } });
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
      decodeSnapshotPart(utf8(text.replace('"format":1', '"format":9'))).kind,
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
