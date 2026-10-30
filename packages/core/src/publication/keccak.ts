import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";

const KECCAK_CHUNK_BYTES = 256 * 1024;

/** Hashes exact bytes while yielding between bounded chunks on large payloads. */
export async function keccak256Cooperatively(
  bytes: Uint8Array,
): Promise<`0x${string}`> {
  const hash = keccak_256.create();
  for (
    let offset = 0;
    offset < bytes.byteLength;
    offset += KECCAK_CHUNK_BYTES
  ) {
    hash.update(bytes.subarray(offset, offset + KECCAK_CHUNK_BYTES));
    if (offset + KECCAK_CHUNK_BYTES < bytes.byteLength) {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
    }
  }
  return `0x${bytesToHex(hash.digest())}`;
}
