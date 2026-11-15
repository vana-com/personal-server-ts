import { describe, expect, it } from "vitest";
import { utf8 } from "./bytes.js";
import {
  compactionRequired,
  decodeSegment,
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
