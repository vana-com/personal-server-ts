import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { toHex, utf8, type Sha256StreamFactory } from "./bytes.js";
import {
  decodeEnvelope,
  encodeEnvelope,
  frameChunks,
  measureBody,
  readFrames,
  type Envelope,
} from "./frames.js";
import { InvalidPartError } from "./errors.js";

const makeSha256: Sha256StreamFactory = () => {
  const h = createHash("sha256");
  return {
    update: (d) => void h.update(d),
    digest: () => new Uint8Array(h.digest()),
  };
};
const K = "ab".repeat(32);

async function envelopeFor(
  body: Uint8Array[],
  o = 5,
  r = "run-1",
): Promise<Envelope> {
  const { h, n } = await measureBody(makeSha256, body);
  return { h, k: K, n, o, r };
}
async function* asyncOf(pieces: Uint8Array[]) {
  for (const p of pieces) yield p;
}
async function collect(it: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
  const out: Uint8Array[] = [];
  for await (const p of it) out.push(p);
  return out;
}
function join(pieces: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(pieces.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of pieces) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}
function resplit(bytes: Uint8Array, size: number): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += size)
    out.push(bytes.subarray(i, i + size));
  return out;
}

describe("envelope", () => {
  it("is canonical and round-trips", () => {
    const e: Envelope = { h: "00".repeat(32), k: K, n: 3, o: 1, r: "x" };
    const bytes = encodeEnvelope(e);
    expect(new TextDecoder().decode(bytes)).toBe(
      `{"h":"${"00".repeat(32)}","k":"${K}","n":3,"o":1,"r":"x"}`,
    );
    expect(decodeEnvelope(bytes)).toEqual(e);
  });
  it.each([
    [
      "extra field",
      `{"h":"${"0".repeat(64)}","k":"${K}","n":3,"o":1,"r":"x","z":1}`,
    ],
    ["spaces", `{"h":"${"0".repeat(64)}", "k":"${K}","n":3,"o":1,"r":"x"}`],
    ["bad hash", `{"h":"zz","k":"${K}","n":3,"o":1,"r":"x"}`],
    ["negative n", `{"h":"${"0".repeat(64)}","k":"${K}","n":-1,"o":1,"r":"x"}`],
    ["empty run", `{"h":"${"0".repeat(64)}","k":"${K}","n":3,"o":1,"r":""}`],
  ])("rejects %s", (_name, text) => {
    expect(() => decodeEnvelope(utf8(text))).toThrow(InvalidPartError);
  });
});

describe("frames", () => {
  it("writes and reads frames of several sizes, in any piece size", async () => {
    const bodies = [
      utf8('{"id":1}'),
      utf8(""),
      utf8('{"s":"' + "é".repeat(100_000) + '"}'),
    ];
    const wire: Uint8Array[] = [];
    const envelopes: Envelope[] = [];
    for (const b of bodies) {
      const e = await envelopeFor([b]);
      envelopes.push(e);
      wire.push(...(await collect(frameChunks(e, [b]))));
    }
    for (const size of [1, 7, 4096, 1 << 20]) {
      const seen: { e: Envelope; body: Uint8Array }[] = [];
      for await (const f of readFrames(
        asyncOf(resplit(join(wire), size)),
        makeSha256,
      )) {
        seen.push({ e: f.envelope, body: join(await collect(f.body)) });
      }
      expect(seen.map((s) => s.e)).toEqual(envelopes);
      expect(seen.map((s) => toHex(s.body))).toEqual(bodies.map(toHex));
    }
  });

  it("skips a body the consumer did not read", async () => {
    const a = utf8('{"a":1}');
    const b = utf8('{"b":2}');
    const wire = join([
      ...(await collect(frameChunks(await envelopeFor([a]), [a]))),
      ...(await collect(frameChunks(await envelopeFor([b], 6), [b]))),
    ]);
    const os: number[] = [];
    for await (const f of readFrames(asyncOf([wire]), makeSha256))
      os.push(f.envelope.o);
    expect(os).toEqual([5, 6]);
  });

  it("detects a flipped body byte, a short body and a missing LF", async () => {
    const body = utf8('{"id":"abc"}');
    const e = await envelopeFor([body]);
    const wire = join(await collect(frameChunks(e, [body])));
    const flipped = wire.slice();
    flipped[flipped.length - 4] ^= 1;
    await expect(
      (async () => {
        for await (const f of readFrames(asyncOf([flipped]), makeSha256))
          await collect(f.body);
      })(),
    ).rejects.toThrow(/SHA-256/);
    await expect(
      (async () => {
        for await (const f of readFrames(
          asyncOf([wire.subarray(0, wire.length - 3)]),
          makeSha256,
        ))
          await collect(f.body);
      })(),
    ).rejects.toThrow(InvalidPartError);
    const noLf = wire.slice();
    noLf[noLf.length - 1] = 0x41;
    await expect(
      (async () => {
        for await (const f of readFrames(asyncOf([noLf]), makeSha256))
          await collect(f.body);
      })(),
    ).rejects.toThrow(/LF/);
  });

  it("refuses a writer whose body length disagrees with the envelope", async () => {
    const body = utf8("abcd");
    const e = { ...(await envelopeFor([body])), n: 9 };
    await expect(collect(frameChunks(e, [body]))).rejects.toThrow(
      InvalidPartError,
    );
  });

  it("never yields a piece larger than its source piece", async () => {
    const body = new Uint8Array(3 << 20).fill(0x61);
    const e = await envelopeFor([body]);
    const wire = join(await collect(frameChunks(e, [body])));
    let max = 0;
    for await (const f of readFrames(
      asyncOf(resplit(wire, 65_536)),
      makeSha256,
    )) {
      for await (const p of f.body) max = Math.max(max, p.length);
    }
    expect(max).toBeLessThanOrEqual(65_536);
  });
});
