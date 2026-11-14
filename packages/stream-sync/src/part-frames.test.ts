import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FRAME_PIECE_BYTES, toHex, utf8, type Sha256 } from "./bytes.js";
import { InvalidPartError } from "./errors.js";
import { encodeEnvelope, type Envelope } from "./frames.js";
import { FrameReducer } from "./merge.js";
import {
  cutPieces,
  encodeFramePart,
  encodePiece,
  framesOfParts,
  linesOfParts,
  type FrameBytes,
} from "./part-frames.js";
import type { EncodedPart } from "./parts.js";
import { HEAD_FORMAT } from "./head.js";

const sha256: Sha256 = async (d) =>
  new Uint8Array(createHash("sha256").update(d).digest());
const hex = (s: string) => toHex(createHash("sha256").update(s).digest());

function frame(
  k: string,
  body: Uint8Array,
  o = 1,
  r = "run",
  f?: number | null,
): FrameBytes & { envelope: Envelope } {
  const envelope: Envelope = {
    h: toHex(createHash("sha256").update(body).digest()),
    k,
    n: body.length,
    o,
    r,
    ...(f === undefined ? {} : { f }),
  };
  const head = encodeEnvelope(envelope);
  const bytes = new Uint8Array(head.length + 1 + body.length + 1);
  bytes.set(head);
  bytes[head.length] = 10;
  bytes.set(body, head.length + 1);
  bytes[bytes.length - 1] = 10;
  return { k, bytes, envelope };
}
const key = (n: number) => n.toString(16).padStart(2, "0").repeat(32);
async function* of(b: Uint8Array) {
  yield b;
}

async function partsOf(frames: ReturnType<typeof frame>[], pieceSize = 1024) {
  const encoded: EncodedPart[] = [];
  let small: FrameBytes[] = [];
  const flush = async () => {
    const p = await encodeFramePart(sha256, "", small);
    if (p) encoded.push(p);
    small = [];
  };
  for (const f of frames) {
    if (f.bytes.length <= 2048) {
      small.push(f);
      continue;
    }
    await flush();
    let first = true;
    for await (const piece of cutPieces(of(f.bytes), pieceSize)) {
      encoded.push(await encodePiece(sha256, "", piece, first));
      first = false;
    }
  }
  await flush();
  return encoded;
}
const loader = (encoded: EncodedPart[]) => async (_p: unknown, i: number) =>
  encoded[i]!.data;
async function readAll(encoded: EncodedPart[]) {
  const out: { env: Envelope; body: string; long: boolean }[] = [];
  for await (const f of framesOfParts(
    sha256,
    encoded.map((e) => e.entry),
    loader(encoded),
  )) {
    const chunks: Uint8Array[] = [];
    for await (const c of f.body()) chunks.push(c);
    out.push({
      env: f.envelope,
      body: Buffer.concat(chunks).toString(),
      long: f.raw === null,
    });
  }
  return out;
}

describe("format-2 parts", () => {
  const bodies = [
    utf8('{"a":1}'),
    utf8('{"big":"' + "x".repeat(5000) + '"}'),
    utf8('{"b":2}'),
    utf8('{"big":"' + "y".repeat(2500) + '"}'),
  ];
  const frames = bodies.map((b, i) => frame(key(i + 1), b));

  it("round-trips small and long frames in key order", async () => {
    const encoded = await partsOf(frames);
    expect(encoded.map((e) => e.entry.count)).toEqual([
      1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0,
    ]);
    const read = await readAll(encoded);
    expect(read.map((r) => r.env.k)).toEqual(frames.map((f) => f.k));
    expect(read.map((r) => r.body)).toEqual(
      bodies.map((b) => Buffer.from(b).toString()),
    );
    expect(read.map((r) => r.long)).toEqual([false, true, false, true]);
  });

  it("does not load a long frame's later parts unless its body is read", async () => {
    const encoded = await partsOf(frames);
    const loaded: number[] = [];
    for await (const f of framesOfParts(
      sha256,
      encoded.map((e) => e.entry),
      async (_p, i) => {
        loaded.push(i);
        return encoded[i]!.data;
      },
    )) {
      void f;
    }
    expect(loaded).toEqual([0, 1, 7, 8]);
  });

  it("refuses a part whose bytes do not match the head", async () => {
    const encoded = await partsOf(frames);
    const bad = { ...encoded[0]!, data: encoded[0]!.data.slice() };
    bad.data[3] ^= 1;
    await expect(readAll([bad, ...encoded.slice(1)])).rejects.toThrow(
      InvalidPartError,
    );
  });

  it("refuses unsorted frames, a stray continuation and a short run", async () => {
    await expect(
      encodeFramePart(sha256, "", [frames[1]!, frames[0]!]),
    ).rejects.toThrow();
    const encoded = await partsOf(frames);
    await expect(readAll(encoded.slice(2))).rejects.toThrow(/never started/);
    await expect(
      readAll(encoded.slice(0, 3).concat(encoded.slice(6))),
    ).rejects.toThrow(InvalidPartError);
  });
});

describe("a frame at the piece boundary", () => {
  // A frame of exactly one piece is one part (count 1). One byte more adds a
  // second part that starts no frame (count 0), never an empty terminal part.
  it.each([
    [0, [FRAME_PIECE_BYTES], [1]],
    [1, [FRAME_PIECE_BYTES, 1], [1, 0]],
  ])("a frame %i bytes over the piece size", async (over, sizes, counts) => {
    // The envelope's own length depends on n: settle the body size by retry.
    let bodyLength = FRAME_PIECE_BYTES + over;
    const make = (n: number) => {
      const body = new Uint8Array(n).fill(0x61);
      body[0] = 0x22;
      body[n - 1] = 0x22;
      return { body, f: frame(key(1), body) };
    };
    let made = make(bodyLength);
    while (made.f.bytes.length !== FRAME_PIECE_BYTES + over) {
      bodyLength -= made.f.bytes.length - (FRAME_PIECE_BYTES + over);
      made = make(bodyLength);
    }
    const { body, f } = made;
    const encoded = await partsOf([f], FRAME_PIECE_BYTES);
    expect(encoded.map((e) => e.entry.bytes)).toEqual(sizes);
    expect(encoded.map((e) => e.entry.count)).toEqual(counts);
    const [read] = await readAll(encoded);
    expect(read!.body.length).toBe(body.length);
  });
});

describe("FrameReducer", () => {
  it("keeps the greatest stamp, the later add on a tie, and splits on small bytes only", () => {
    const r = new FrameReducer<string>("");
    r.add({ k: key(1), o: 1, r: "a", size: 10, held: true, ref: "old" });
    r.add({ k: key(1), o: 2, r: "a", size: 10, held: true, ref: "new" });
    r.add({ k: key(1), o: 1, r: "z", size: 10, held: true, ref: "stale" });
    r.add({ k: key(2), o: 5, r: "a", size: 5, held: true, ref: "tie1" });
    r.add({ k: key(2), o: 5, r: "a", size: 5, held: true, ref: "tie2" });
    r.add({
      k: key(3),
      o: 1,
      r: "a",
      size: 90 * 1024 * 1024,
      held: false,
      ref: "long",
    });
    const result = r.finish(1024);
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    expect(result.winners.map((w) => w.ref)).toEqual(["new", "tie2", "long"]);
    expect(result.smallBytes).toBe(15);
    const tight = new FrameReducer<string>("");
    tight.add({ k: key(1), o: 1, r: "a", size: 600, held: true, ref: "a" });
    tight.add({ k: key(2), o: 1, r: "a", size: 600, held: true, ref: "b" });
    expect(tight.finish(1000).kind).toBe("split");
  });
});

describe("v3 parts", () => {
  const body = utf8('{"a":1}');
  const lines = async (
    format: 1 | 2 | 3 | 4 | 5,
    encoded: EncodedPart[],
  ): Promise<unknown[]> => {
    const out: unknown[] = [];
    for await (const line of linesOfParts(
      sha256,
      {
        format,
        parts: encoded.map((e) => e.entry),
        primaryKey: ["id"],
      },
      loader(encoded),
    )) {
      out.push(line);
    }
    return out;
  };

  it("head-4-parses-and-rejects-v2-frames", async () => {
    const v3 = await partsOf([frame(key(1), body, 5, "run-1", 3)]);
    expect(await lines(4, v3)).toEqual([
      { o: 5, r: "run-1", v: { a: 1 }, f: 3 },
    ]);
    const v2 = await partsOf([frame(key(1), body, 5, "run-1")]);
    await expect(lines(4, v2)).rejects.toThrow(InvalidPartError);
    // The other direction: a v3 frame in a format 3 head.
    await expect(lines(3, v3)).rejects.toThrow(InvalidPartError);
  });

  it("head-3-reads-unknown-first-seen", async () => {
    const v2 = await partsOf([frame(key(1), body, 5, "run-1")]);
    for (const format of [2, 3] as const) {
      expect(await lines(format, v2)).toEqual([
        { o: 5, r: "run-1", v: { a: 1 }, f: null },
      ]);
    }
  });

  it("a published format 5 head reads back through the v3 reader", async () => {
    const big = utf8('{"big":"' + "z".repeat(5000) + '"}');
    const frames = [
      frame(key(1), body, 5, "run-1", 3),
      frame(key(2), big, 6, "run-2", null),
      frame(key(3), body, 7, "run-3", 0),
    ];
    const encoded = await partsOf(frames);
    expect(HEAD_FORMAT).toBe(5);
    const read = await lines(HEAD_FORMAT, encoded);
    expect(read).toEqual([
      { o: 5, r: "run-1", v: { a: 1 }, f: 3 },
      { o: 6, r: "run-2", v: JSON.parse(Buffer.from(big).toString()), f: null },
      { o: 7, r: "run-3", v: { a: 1 }, f: 0 },
    ]);
  });
  void FRAME_PIECE_BYTES;
  void hex;
});
