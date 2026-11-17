/**
 * The browser runtime's Keccak-256 comes from WebAssembly and gives the bytes
 * noble gives, or it is noble's: a log's names must not depend on the host.
 */
import { describe, expect, it } from "vitest";
import type { createKeccak } from "hash-wasm";
import { nobleStreamCrypto } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { wasmStreamCrypto } from "./wasm-stream-crypto.js";

const bytes = (n: number, seed: number) => {
  const out = new Uint8Array(n);
  let x = seed;
  for (let i = 0; i < n; i++)
    out[i] = (x = (x * 1103515245 + 12345) >>> 0) >>> 24;
  return out;
};

describe("wasmStreamCrypto", () => {
  it("hashes with WebAssembly, and every digest equals noble's, call after call", async () => {
    const port = await wasmStreamCrypto();
    expect(port.keccak256).not.toBe(nobleStreamCrypto.keccak256);
    // Empty, the Keccak-256 rate (136 bytes) and its neighbours, and a few MiB.
    const inputs = [0, 1, 135, 136, 137, 272, 4096, 3 * 1024 * 1024 + 7].map(
      (n, i) => bytes(n, i + 1),
    );
    for (const input of [...inputs, ...inputs.reverse()])
      expect(port.keccak256(input)).toEqual(nobleStreamCrypto.keccak256(input));
    // The other primitives are noble's.
    expect(port.sha256).toBe(nobleStreamCrypto.sha256);
    expect(port.open).toBe(nobleStreamCrypto.open);
  });

  it("keeps noble's when WebAssembly does not compile", async () => {
    const port = await wasmStreamCrypto(async () => {
      throw new Error("WebAssembly is not allowed");
    });
    expect(port).toBe(nobleStreamCrypto);
  });

  it("keeps noble's when the compiled Keccak does not give the known digest", async () => {
    // SHA3-256 is not Keccak-256: it differs in padding, so "abc" differs.
    const port = await wasmStreamCrypto(((bits: 256) =>
      import("hash-wasm").then(({ createSHA3 }) =>
        createSHA3(bits),
      )) as unknown as typeof createKeccak);
    expect(port).toBe(nobleStreamCrypto);
  });
});
