import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { nobleStreamCrypto } from "../../../core/src/stream-sync/crypto-port.js";
import { createStreamSyncKeyPorts } from "../../../core/src/stream-sync/crypto.js";
import {
  openBytes,
  sealBytes,
  sealStream,
  STREAM_CHUNK_BYTES,
  StreamAeadError,
} from "../../../core/src/stream-sync/stream-aead.js";
import { nodeStreamCrypto } from "./node-stream-crypto.js";

const key = new Uint8Array(32).map((_, i) => i + 1);
const nonce = new Uint8Array(16).map((_, i) => 0xa0 + i);
const fixed = () => nonce.slice();

function bytesOf(size: number): Uint8Array {
  return Uint8Array.from(randomBytes(size));
}

// Sizes at the chunk edges: empty, one byte, one under, exact, one over, many.
const SIZES = [
  0,
  1,
  STREAM_CHUNK_BYTES - 1,
  STREAM_CHUNK_BYTES,
  STREAM_CHUNK_BYTES + 1,
  3 * STREAM_CHUNK_BYTES,
  3 * STREAM_CHUNK_BYTES + 17,
  1024 * 1024 + 5,
];

describe("the node stream-crypto port", () => {
  it("hashes the same bytes as noble", () => {
    for (const size of [0, 1, 55, 64, 65, 100_000]) {
      const data = bytesOf(size);
      expect(Buffer.from(nodeStreamCrypto.sha256(data)).toString("hex")).toBe(
        Buffer.from(nobleStreamCrypto.sha256(data)).toString("hex"),
      );
    }
  });

  it.each(SIZES)(
    "seals %i bytes to the same blob as noble, and each opens the other's",
    async (size) => {
      const clear = bytesOf(size);
      const native = await sealBytes(key, clear, fixed, nodeStreamCrypto);
      const noble = await sealBytes(key, clear, fixed, nobleStreamCrypto);
      expect(Buffer.compare(native, noble)).toBe(0);
      const viaStream: Uint8Array[] = [];
      for await (const piece of sealStream(
        key,
        (async function* () {
          yield clear;
        })(),
        fixed,
        nodeStreamCrypto,
      )) {
        viaStream.push(piece);
      }
      expect(Buffer.compare(Buffer.concat(viaStream), noble)).toBe(0);
      expect(
        Buffer.compare(await openBytes(key, native, nobleStreamCrypto), clear),
      ).toBe(0);
      expect(
        Buffer.compare(await openBytes(key, noble, nodeStreamCrypto), clear),
      ).toBe(0);
    },
  );

  it("rejects a tampered, reordered or truncated blob like noble does", async () => {
    const clear = bytesOf(3 * STREAM_CHUNK_BYTES + 9);
    const blob = await sealBytes(key, clear, fixed, nodeStreamCrypto);
    const flipped = blob.slice();
    flipped[blob.length - 40] ^= 1;
    const chunk = STREAM_CHUNK_BYTES + 16;
    const head = blob.subarray(0, 20);
    const swapped = Buffer.concat([
      head,
      blob.subarray(20 + chunk, 20 + 2 * chunk),
      blob.subarray(20, 20 + chunk),
      blob.subarray(20 + 2 * chunk),
    ]);
    const truncated = blob.subarray(0, 20 + chunk);
    for (const port of [nodeStreamCrypto, nobleStreamCrypto]) {
      for (const bad of [flipped, swapped, truncated]) {
        await expect(openBytes(key, bad, port)).rejects.toBeInstanceOf(
          StreamAeadError,
        );
      }
    }
  });

  it("gives key ports that seal with the native port and open with the default", async () => {
    const signature = `0x${"ab".repeat(64)}1b`;
    const native = createStreamSyncKeyPorts(signature, nodeStreamCrypto);
    const plain = createStreamSyncKeyPorts(signature);
    const clear = bytesOf(2 * STREAM_CHUNK_BYTES + 3);
    const sealed = await native.encryptPart("scope-a", clear);
    expect(Buffer.compare(await plain.decrypt("scope-a", sealed), clear)).toBe(
      0,
    );
    const back = await plain.encryptPart("scope-a", clear);
    expect(Buffer.compare(await native.decrypt("scope-a", back), clear)).toBe(
      0,
    );
  });
});
