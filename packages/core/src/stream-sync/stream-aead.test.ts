import { createCipheriv, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  openStream,
  sealStream,
  STREAM_CHUNK_BYTES,
  StreamAeadError,
} from "./stream-aead.js";

const key = new Uint8Array(32).fill(7);
const nonce = new Uint8Array(16).map((_, i) => i + 1);
const random = () => nonce;

async function* from(...pieces: Uint8Array[]) {
  for (const p of pieces) yield p;
}
async function collect(it: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
  const out: Uint8Array[] = [];
  for await (const p of it) out.push(p);
  return Buffer.concat(out);
}
const seal = (plain: Uint8Array) =>
  collect(sealStream(key, from(plain), random));
const open = (blob: Uint8Array) => collect(openStream(key, from(blob)));
const bytesOf = (n: number) => new Uint8Array(n).map((_, i) => (i * 31) % 251);

describe("stream AEAD (age STREAM)", () => {
  it.each([
    0,
    1,
    STREAM_CHUNK_BYTES - 1,
    STREAM_CHUNK_BYTES,
    STREAM_CHUNK_BYTES + 1,
    3 * STREAM_CHUNK_BYTES,
    3 * STREAM_CHUNK_BYTES + 5,
  ])("round-trips %i bytes", async (n) => {
    const plain = bytesOf(n);
    const blob = await seal(plain);
    expect(Buffer.from(await open(blob))).toEqual(Buffer.from(plain));
  });

  it("round-trips when the input and output arrive in odd pieces", async () => {
    const plain = bytesOf(200_000);
    const pieces = [
      plain.subarray(0, 7),
      plain.subarray(7, 100_000),
      plain.subarray(100_000),
    ];
    const blob = await collect(sealStream(key, from(...pieces), random));
    const odd = [
      blob.subarray(0, 3),
      blob.subarray(3, 21),
      blob.subarray(21, 70_000),
      blob.subarray(70_000),
    ];
    expect(Buffer.from(await collect(openStream(key, from(...odd))))).toEqual(
      Buffer.from(plain),
    );
  });

  it("matches an independent implementation of the age payload layout", async () => {
    const plain = bytesOf(STREAM_CHUNK_BYTES + 10);
    const blob = await seal(plain);
    const payloadKey = Buffer.from(
      hkdfSync("sha256", key, nonce, "payload", 32),
    );
    const chunkAt = (i: number, last: boolean, data: Uint8Array) => {
      const iv = Buffer.alloc(12);
      iv.writeUIntBE(i, 5, 6);
      iv[11] = last ? 1 : 0;
      const c = createCipheriv("chacha20-poly1305", payloadKey, iv, {
        authTagLength: 16,
      });
      return Buffer.concat([c.update(data), c.final(), c.getAuthTag()]);
    };
    const expected = Buffer.concat([
      Buffer.from([0x56, 0x53, 0x41, 0x01]),
      Buffer.from(nonce),
      chunkAt(0, false, plain.subarray(0, STREAM_CHUNK_BYTES)),
      chunkAt(1, true, plain.subarray(STREAM_CHUNK_BYTES)),
    ]);
    expect(Buffer.from(blob)).toEqual(expected);
  });

  it("detects truncation at a chunk boundary", async () => {
    const blob = await seal(bytesOf(3 * STREAM_CHUNK_BYTES));
    const cut = blob.subarray(0, 20 + 2 * (STREAM_CHUNK_BYTES + 16));
    await expect(open(cut)).rejects.toBeInstanceOf(StreamAeadError);
  });

  it("detects reordered chunks", async () => {
    const blob = await seal(bytesOf(3 * STREAM_CHUNK_BYTES));
    const size = STREAM_CHUNK_BYTES + 16;
    const swapped = Buffer.concat([
      blob.subarray(0, 20),
      blob.subarray(20 + size, 20 + 2 * size),
      blob.subarray(20, 20 + size),
      blob.subarray(20 + 2 * size),
    ]);
    await expect(open(swapped)).rejects.toBeInstanceOf(StreamAeadError);
  });

  it("detects appended data and a flipped bit", async () => {
    const blob = await seal(bytesOf(100));
    await expect(
      open(Buffer.concat([blob, Buffer.from([1])])),
    ).rejects.toBeInstanceOf(StreamAeadError);
    const bad = Buffer.from(blob);
    bad[30] ^= 1;
    await expect(open(bad)).rejects.toBeInstanceOf(StreamAeadError);
  });

  it("refuses the wrong key and a non-stream blob", async () => {
    const blob = await seal(bytesOf(10));
    await expect(
      collect(openStream(new Uint8Array(32), from(blob))),
    ).rejects.toBeInstanceOf(StreamAeadError);
    await expect(
      open(Buffer.from("-----BEGIN PGP MESSAGE-----")),
    ).rejects.toBeInstanceOf(StreamAeadError);
    await expect(open(blob.subarray(0, 10))).rejects.toBeInstanceOf(
      StreamAeadError,
    );
  });

  it("holds about two chunks while sealing a large stream", async () => {
    async function* big() {
      const piece = bytesOf(1 << 20);
      for (let i = 0; i < 64; i += 1) yield piece;
    }
    let max = 0;
    for await (const c of sealStream(key, big(), random))
      max = Math.max(max, c.length);
    expect(max).toBeLessThanOrEqual(STREAM_CHUNK_BYTES + 16);
  });
});
