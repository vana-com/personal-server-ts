import { createHash, randomBytes } from "node:crypto";
import type * as NodeCrypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
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

  it("hashes native Keccak-256 the same as noble, and not as SHA3-256", (context) => {
    try {
      const known = createHash("keccak-256").update("abc").digest("hex");
      if (
        known !==
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
      ) {
        context.skip("Runtime keccak-256 fails the Ethereum known answer");
        return;
      }
    } catch {
      context.skip("Runtime OpenSSL has no native keccak-256");
      return;
    }
    for (const size of [0, 1, 135, 136, 137, 100_000, 3 * 1024 * 1024 + 5]) {
      const data = bytesOf(size);
      expect(
        Buffer.from(nodeStreamCrypto.keccak256(data)).toString("hex"),
      ).toBe(Buffer.from(nobleStreamCrypto.keccak256(data)).toString("hex"));
    }
    // Ethereum's digest of "abc"; SHA3-256 of the same bytes is 3a985da7…
    expect(
      Buffer.from(
        nodeStreamCrypto.keccak256(new TextEncoder().encode("abc")),
      ).toString("hex"),
    ).toBe("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  });

  it.each([
    [
      "has no keccak-256",
      () => {
        throw new Error("Digest method not supported");
      },
    ],
    [
      "answers keccak-256 with SHA3-256",
      (algorithm: string) =>
        createHash(algorithm === "keccak-256" ? "sha3-256" : algorithm),
    ],
  ])("keeps noble's Keccak-256 when OpenSSL %s", async (_name, replacement) => {
    vi.resetModules();
    vi.doMock("node:crypto", async (importOriginal) => {
      const real = await importOriginal<typeof NodeCrypto>();
      return {
        ...real,
        createHash: (algorithm: string) =>
          algorithm === "keccak-256"
            ? replacement(algorithm)
            : real.createHash(algorithm),
      };
    });
    try {
      const { nodeStreamCrypto: port } =
        await import("./node-stream-crypto.js");
      const data = bytesOf(5_000);
      expect(Buffer.from(port.keccak256(data)).toString("hex")).toBe(
        Buffer.from(nobleStreamCrypto.keccak256(data)).toString("hex"),
      );
    } finally {
      vi.doUnmock("node:crypto");
      vi.resetModules();
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

it("selects and continues using a native implementation after its known-answer probe", async () => {
  const inputs: Uint8Array[] = [];
  vi.resetModules();
  vi.doMock("node:crypto", async (importOriginal) => {
    const real = await importOriginal<typeof NodeCrypto>();
    return {
      ...real,
      createHash: (algorithm: string) => {
        if (algorithm !== "keccak-256") return real.createHash(algorithm);
        let input = new Uint8Array();
        return {
          update(data: Uint8Array) {
            input = Uint8Array.from(data);
            inputs.push(input);
            return this;
          },
          digest() {
            return Buffer.from(nobleStreamCrypto.keccak256(input));
          },
        };
      },
    };
  });
  try {
    const { nodeStreamCrypto: port } = await import("./node-stream-crypto.js");
    expect(inputs).toEqual([new TextEncoder().encode("abc")]);
    for (const size of [0, 1, 137, 3 * 1024 * 1024 + 5]) {
      const data = bytesOf(size),
        before = inputs.length;
      expect(Buffer.from(port.keccak256(data))).toEqual(
        Buffer.from(nobleStreamCrypto.keccak256(data)),
      );
      expect(inputs.length).toBe(before + 1);
      expect(inputs.at(-1)).toEqual(data);
    }
  } finally {
    vi.doUnmock("node:crypto");
    vi.resetModules();
  }
});
