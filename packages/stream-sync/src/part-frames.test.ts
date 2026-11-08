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
  type FrameBytes,
} from "./part-frames.js";
import type { EncodedPart } from "./parts.js";

const sha256: Sha256 = async (d) =>
  new Uint8Array(createHash("sha256").update(d).digest());
const hex = (s: string) => toHex(createHash("sha256").update(s).digest());

function frame(
  k: string,
  body: Uint8Array,
  o = 1,
  r = "run",
): FrameBytes & { envelope: Envelope } {
  const envelope = {
    h: toHex(createHash("sha256").update(body).digest()),
    k,
    n: body.length,
    o,
    r,
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

  void FRAME_PIECE_BYTES;
  void hex;
});
