/**
 * The browser runtime's `StreamCryptoPort`: core's noble port with Keccak-256
 * from WebAssembly (hash-wasm). A reader hashes every byte of every log segment
 * it applies (`verifySegment`). Noble's pure-JS Keccak runs at about 22 MB/s on
 * a browser's main thread; hash-wasm's runs at about 400 MB/s, so a 277 MB first
 * load spends under a second hashing instead of about 13 s. WebCrypto has no
 * Keccak-256 (nor SHA-3) in any browser, and Keccak-256 is not SHA3-256, so the
 * browser has no native one to use.
 *
 * The WASM module compiles once, asynchronously; after that every hash is a
 * synchronous call, as the port requires. A runtime that cannot compile it
 * (no WebAssembly, a policy that forbids it) or whose digest of a known input
 * is not the known answer keeps noble's: the bytes a log is named by must not
 * depend on the host.
 */

import { createKeccak } from "hash-wasm";
import {
  nobleStreamCrypto,
  type StreamCryptoPort,
} from "@opendatalabs/personal-server-ts-core/stream-sync";

/** Keccak-256 of the bytes "abc" (Ethereum's Keccak, not SHA3-256). */
const ABC_KECCAK_256 =
  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";

let wasmPort: Promise<StreamCryptoPort> | undefined;

/** `nobleStreamCrypto` with WASM Keccak-256 when it compiles and checks out. */
export function wasmStreamCrypto(
  compile: typeof createKeccak = createKeccak,
): Promise<StreamCryptoPort> {
  if (compile !== createKeccak) return build(compile);
  wasmPort ??= build(compile);
  return wasmPort;
}

async function build(compile: typeof createKeccak): Promise<StreamCryptoPort> {
  try {
    const hasher = await compile(256);
    // One hasher serves every call: each runs init, update and digest with no
    // await between them, so two calls cannot interleave.
    const keccak256 = (data: Uint8Array): Uint8Array => {
      hasher.init();
      hasher.update(data);
      return hasher.digest("binary");
    };
    const probe = keccak256(new TextEncoder().encode("abc"));
    if (toHex(probe) !== ABC_KECCAK_256) return nobleStreamCrypto;
    return { ...nobleStreamCrypto, keccak256 };
  } catch {
    return nobleStreamCrypto;
  }
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
