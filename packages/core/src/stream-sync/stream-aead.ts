/**
 * Streaming authenticated encryption for format-2 blobs: the STREAM
 * construction exactly as the age file format specifies its payload
 * (age-encryption.org/v1): ChaCha20-Poly1305 over 64 KiB chunks, a 12-byte
 * nonce made of an 11-byte big-endian chunk counter and one final-chunk flag
 * byte, and a payload key from HKDF-SHA-256(key, salt = the 16-byte header
 * nonce, info = "payload"). Reordering, dropping, truncating or extending
 * chunks fails authentication.
 *
 * Wire form: MAGIC (4) || header nonce (16) || chunk*. The first magic byte
 * has its top bit clear, so no OpenPGP packet (tag bytes have it set) and no
 * ASCII armor can be mistaken for it.
 *
 * Both directions hold at most two chunks (one of lookahead, because the
 * last chunk must be marked), whatever the payload size.
 */

import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

export const STREAM_CHUNK_BYTES = 64 * 1024;
const TAG_BYTES = 16;
const NONCE_BYTES = 16;
export const STREAM_MAGIC = Uint8Array.of(0x56, 0x53, 0x41, 0x01);
const HEADER_BYTES = STREAM_MAGIC.length + NONCE_BYTES;
const INFO = new TextEncoder().encode("payload");

export class StreamAeadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StreamAeadError";
  }
}

export function isStreamAead(head: Uint8Array): boolean {
  return (
    head.length >= STREAM_MAGIC.length &&
    STREAM_MAGIC.every((byte, i) => head[i] === byte)
  );
}

function chunkNonce(counter: number, last: boolean): Uint8Array {
  const nonce = new Uint8Array(12);
  // counter < 2^53: write it big-endian into the 11 counter bytes.
  let rest = counter;
  for (let i = 10; i >= 0 && rest > 0; i -= 1) {
    nonce[i] = rest % 256;
    rest = Math.floor(rest / 256);
  }
  nonce[11] = last ? 1 : 0;
  return nonce;
}

function payloadKey(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdf(sha256, key, nonce, INFO, 32);
}

/** Re-block a byte stream into exact `size`-byte pieces (the last may be shorter) and mark the last one. */
async function* blocks(
  source: AsyncIterable<Uint8Array>,
  size: number,
): AsyncGenerator<{ bytes: Uint8Array; last: boolean }> {
  let pending: Uint8Array | null = null;
  let fill = new Uint8Array(size);
  let used = 0;
  for await (const piece of source) {
    let at = 0;
    while (at < piece.length) {
      const take = Math.min(size - used, piece.length - at);
      fill.set(piece.subarray(at, at + take), used);
      used += take;
      at += take;
      if (used === size) {
        if (pending !== null) yield { bytes: pending, last: false };
        pending = fill;
        fill = new Uint8Array(size);
        used = 0;
      }
    }
  }
  if (used > 0 || pending === null) {
    if (pending !== null) yield { bytes: pending, last: false };
    yield { bytes: fill.slice(0, used), last: true };
  } else {
    yield { bytes: pending, last: true };
  }
}

export async function* sealStream(
  key: Uint8Array,
  source: AsyncIterable<Uint8Array>,
  random: (n: number) => Uint8Array,
): AsyncGenerator<Uint8Array> {
  const nonce = random(NONCE_BYTES);
  const sealKey = payloadKey(key, nonce);
  const header = new Uint8Array(HEADER_BYTES);
  header.set(STREAM_MAGIC);
  header.set(nonce, STREAM_MAGIC.length);
  yield header;
  let counter = 0;
  for await (const { bytes, last } of blocks(source, STREAM_CHUNK_BYTES)) {
    yield chacha20poly1305(sealKey, chunkNonce(counter, last)).encrypt(bytes);
    counter += 1;
  }
}

export async function* openStream(
  key: Uint8Array,
  source: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  // Peel the header off the front, then block the rest.
  const iterator = source[Symbol.asyncIterator]();
  let header = new Uint8Array(0);
  let spill: Uint8Array | null = null;
  while (header.length < HEADER_BYTES) {
    const next = await iterator.next();
    if (next.done === true) throw new StreamAeadError("stream is truncated");
    const joined = new Uint8Array(header.length + next.value.length);
    joined.set(header);
    joined.set(next.value, header.length);
    header = joined;
  }
  if (!isStreamAead(header)) throw new StreamAeadError("not a stream blob");
  if (header.length > HEADER_BYTES) spill = header.subarray(HEADER_BYTES);
  const openKey = payloadKey(
    key,
    header.subarray(STREAM_MAGIC.length, HEADER_BYTES),
  );
  async function* rest(): AsyncGenerator<Uint8Array> {
    if (spill !== null) yield spill;
    for (;;) {
      const next = await iterator.next();
      if (next.done === true) return;
      yield next.value;
    }
  }
  let counter = 0;
  for await (const { bytes, last } of blocks(
    rest(),
    STREAM_CHUNK_BYTES + TAG_BYTES,
  )) {
    if (bytes.length < TAG_BYTES) throw new StreamAeadError("chunk is short");
    let plain: Uint8Array;
    try {
      plain = chacha20poly1305(openKey, chunkNonce(counter, last)).decrypt(
        bytes,
      );
    } catch {
      throw new StreamAeadError(
        "chunk failed authentication (tampered, reordered or truncated)",
      );
    }
    // age: only a lone chunk may be empty.
    if (plain.length === 0 && counter > 0) {
      throw new StreamAeadError("empty final chunk after data");
    }
    yield plain;
    counter += 1;
  }
}
