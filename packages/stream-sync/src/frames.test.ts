import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { toHex, utf8, type Sha256StreamFactory } from "./bytes.js";
import {
  decodeEnvelope,
  ENVELOPE_LIMIT_BYTES,
  encodeEnvelope,
  frameChunks,
  frameBytes,
  frameOfBody,
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

  it("keeps the next frame whole when a consumer leaves a body early", async () => {
    const a = utf8('{"a":"0123456789"}');
    const b = utf8('{"b":2}');
    const wire = join([
      ...(await collect(frameChunks(await envelopeFor([a]), [a]))),
      ...(await collect(frameChunks(await envelopeFor([b], 6), [b]))),
    ]);
    const seen: { o: number; body: Uint8Array }[] = [];
    for await (const f of readFrames(asyncOf(resplit(wire, 3)), makeSha256)) {
      if (f.envelope.o === 5) {
        for await (const piece of f.body) {
          void piece;
          break;
        }
        continue;
      }
      seen.push({ o: f.envelope.o, body: join(await collect(f.body)) });
    }
    expect(seen.map((x) => x.o)).toEqual([6]);
    expect(seen[0]!.body).toEqual(b);
  });

  it("still checks the hash of a body left early", async () => {
    const a = utf8('{"a":"0123456789"}');
    const e = await envelopeFor([a]);
    const wire = join(await collect(frameChunks(e, [a])));
    wire[wire.length - 4] ^= 1;
    const frames = readFrames(asyncOf(resplit(wire, 3)), makeSha256);
    await expect(
      (async () => {
        for await (const f of frames) {
          for await (const piece of f.body) {
            void piece;
            break;
          }
        }
      })(),
    ).rejects.toThrow(InvalidPartError);
  });

  it.each([-1, 1])(
    "refuses a body whose hash matches but whose length is off by %i",
    async (off) => {
      const body = utf8('{"id":"abcdef"}');
      const e = await envelopeFor([body]);
      const next = utf8('{"z":0}');
      const lying = { ...e, n: e.n + off };
      const wire = join([
        encodeEnvelope(lying),
        Uint8Array.of(10),
        body,
        Uint8Array.of(10),
        ...(await collect(frameChunks(await envelopeFor([next], 6), [next]))),
      ]);
      const emitted: number[] = [];
      await expect(
        (async () => {
          for await (const f of readFrames(
            asyncOf(resplit(wire, 4)),
            makeSha256,
          )) {
            for await (const piece of f.body) void piece;
            emitted.push(f.envelope.o);
          }
        })(),
      ).rejects.toThrow(InvalidPartError);
      expect(emitted).not.toContain(6);
    },
  );

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

describe("frame v3", () => {
  it("frame-v3-round-trip", async () => {
    const body = utf8('{"id":1}');
    const v2 = await envelopeFor([body]);
    const v2Bytes = encodeEnvelope(v2);
    expect(decodeEnvelope(v2Bytes)).toEqual(v2);
    expect(JSON.parse(new TextDecoder().decode(v2Bytes))).not.toHaveProperty(
      "f",
    );

    for (const f of [0, -1, Number.MAX_SAFE_INTEGER, null]) {
      const envelope: Envelope = { ...v2, f };
      const encoded = encodeEnvelope(envelope);
      const expected = `{"f":${f},"h":"${envelope.h}","k":"${K}","n":${body.length},"o":5,"r":"run-1"}`;
      expect(new TextDecoder().decode(encoded)).toBe(expected);
      expect(decodeEnvelope(encoded, "v3")).toEqual(envelope);

      const wire = frameOfBody(envelope, body);
      expect(wire.length).toBe(frameBytes(envelope));
      expect(wire.subarray(0, encoded.length)).toEqual(encoded);
      const seen: { envelope: Envelope; body: Uint8Array }[] = [];
      for await (const frame of readFrames(
        asyncOf(resplit(wire, 3)),
        makeSha256,
        "v3",
      )) {
        seen.push({
          envelope: frame.envelope,
          body: join(await collect(frame.body)),
        });
      }
      expect(seen).toEqual([{ envelope, body }]);
    }

    const bounded: Envelope = { ...v2, f: null, r: "" };
    const overhead = encodeEnvelope({ ...bounded, r: "x" }).length - 1;
    const atLimit = {
      ...bounded,
      r: "x".repeat(ENVELOPE_LIMIT_BYTES - overhead),
    };
    const atLimitBytes = encodeEnvelope(atLimit);
    expect(atLimitBytes.length).toBe(ENVELOPE_LIMIT_BYTES);
    expect(decodeEnvelope(atLimitBytes, "v3")).toEqual(atLimit);
    const overLimit = { ...atLimit, r: atLimit.r + "x" };
    expect(() => encodeEnvelope(overLimit)).toThrow(InvalidPartError);
    const overLimitBytes = utf8(
      new TextDecoder().decode(atLimitBytes).replace(/"}$/, 'x"}'),
    );
    expect(() => decodeEnvelope(overLimitBytes, "v3")).toThrow(
      InvalidPartError,
    );
    const oversizedWire = join([
      overLimitBytes,
      Uint8Array.of(10),
      body,
      Uint8Array.of(10),
    ]);
    await expect(
      readFrames(asyncOf(resplit(oversizedWire, 3)), makeSha256, "v3").next(),
    ).rejects.toThrow(InvalidPartError);
  });

  it("frame versions never mix", async () => {
    const body = utf8('{"id":1}');
    const v2 = await envelopeFor([body]);
    const v3: Envelope = { ...v2, f: null };
    const v2Bytes = encodeEnvelope(v2);
    const v3Bytes = encodeEnvelope(v3);
    expect(() => decodeEnvelope(v3Bytes)).toThrow(InvalidPartError);
    expect(() => decodeEnvelope(v3Bytes, "v2")).toThrow(InvalidPartError);
    expect(() => decodeEnvelope(v2Bytes, "v3")).toThrow(InvalidPartError);
    await expect(
      readFrames(asyncOf([frameOfBody(v3, body)]), makeSha256).next(),
    ).rejects.toThrow(InvalidPartError);
    await expect(
      readFrames(asyncOf([frameOfBody(v2, body)]), makeSha256, "v3").next(),
    ).rejects.toThrow(InvalidPartError);

    const text = new TextDecoder().decode(v3Bytes);
    for (const invalid of [
      1.5,
      Number.MAX_SAFE_INTEGER + 1,
      "1",
      false,
      {},
      [],
    ]) {
      const invalidBytes = utf8(
        text.replace('"f":null', `"f":${JSON.stringify(invalid)}`),
      );
      expect(() => decodeEnvelope(invalidBytes, "v3")).toThrow(
        InvalidPartError,
      );
      expect(() => encodeEnvelope({ ...v2, f: invalid } as Envelope)).toThrow(
        InvalidPartError,
      );
    }
    expect(() =>
      encodeEnvelope({ ...v2, f: undefined } as unknown as Envelope),
    ).toThrow(InvalidPartError);
    for (const malformed of [
      text.replace('"f":null,', ""),
      text.replace('"f":null', '"f":null,"extra":0'),
      text.replace('"f":null,', '"f":null, '),
    ]) {
      expect(() => decodeEnvelope(utf8(malformed), "v3")).toThrow(
        InvalidPartError,
      );
    }
  });
});
