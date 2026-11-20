/**
 * The stream-sync master key (ruling R4, U1-Q1).
 *
 * The legacy master key is the raw 65 bytes of the owner signature over the
 * master-key message. One signature has more than one valid encoding: v can be
 * 0/1 or 27/28, and s can be low or its high twin n - s. Each encoding
 * verifies, but gives a different legacy master key, so a different `ns`.
 *
 * Stream sync takes its master key from the signature in one normal form:
 * r, low s, and v = 27/28. Every stream-sync key (`K_ns`, so `ns` and
 * `keyCheck`, and the head and part keys) derives from this key. Legacy scope
 * keys keep the raw signature.
 */

import { InvalidArgumentError } from "./errors.js";

/** Order of the secp256k1 group. */
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_N = N >> 1n;

function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function toBytes32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

function signatureBytes(signature: Uint8Array | string): Uint8Array {
  if (typeof signature !== "string") {
    if (signature.length !== 65) {
      throw new InvalidArgumentError(
        `owner signature must be 65 bytes, got ${signature.length}`,
      );
    }
    return signature;
  }
  if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    throw new InvalidArgumentError(
      "owner signature must be 0x followed by 130 hex characters (65 bytes)",
    );
  }
  const out = new Uint8Array(65);
  for (let i = 0; i < 65; i += 1) {
    out[i] = parseInt(signature.slice(2 + i * 2, 4 + i * 2), 16);
  }
  return out;
}

/**
 * The stream-sync master key: the 65-byte owner signature as r, low s and
 * v = 27/28. Every encoding of one signature gives the same key. Throws
 * `InvalidArgumentError` when the input is not 65 bytes, v is not 0, 1, 27
 * or 28, or r or s is outside [1, n - 1].
 */
export function streamMasterKeyFromSignature(
  signature: Uint8Array | string,
): Uint8Array {
  const bytes = signatureBytes(signature);
  const r = toBigInt(bytes.subarray(0, 32));
  let s = toBigInt(bytes.subarray(32, 64));
  const rawV = bytes[64]!;
  if (rawV !== 0 && rawV !== 1 && rawV !== 27 && rawV !== 28) {
    throw new InvalidArgumentError(
      `owner signature v must be 0, 1, 27 or 28, got ${rawV}`,
    );
  }
  if (r === 0n || r >= N || s === 0n || s >= N) {
    throw new InvalidArgumentError("owner signature r or s is out of range");
  }
  let parity = rawV >= 27 ? rawV - 27 : rawV;
  if (s > HALF_N) {
    s = N - s;
    parity ^= 1;
  }
  const out = new Uint8Array(65);
  out.set(bytes.subarray(0, 32), 0);
  out.set(toBytes32(s), 32);
  out[64] = 27 + parity;
  return out;
}
