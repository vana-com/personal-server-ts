/**
 * Ports and byte helpers. The package imports no crypto, clock, randomness or
 * I/O: hosts inject every hash and the namespace HMAC.
 */

/** SHA-256 of the exact bytes, as the 32-byte digest. */
export type Sha256 = (data: Uint8Array) => Promise<Uint8Array>;

/** Keccak-256 (Ethereum, not SHA3-256) of the exact bytes, as the 32-byte digest. */
export type Keccak256 = (data: Uint8Array) => Promise<Uint8Array>;

/**
 * HMAC-SHA256 keyed with `K_ns`, as the 32-byte digest. The host binds the key
 * inside its own closure, so `K_ns` never enters this package.
 */
export type NamespaceHmac = (message: Uint8Array) => Promise<Uint8Array>;

/** Hash ports used by codec functions. */
export interface HashPorts {
  readonly sha256: Sha256;
  readonly keccak256: Keccak256;
}

const encoder = new TextEncoder();

export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

export function utf8Length(text: string): number {
  return encoder.encode(text).length;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i]!.toString(16).padStart(2, "0");
  }
  return out;
}

/** Lowercase 64-hex SHA-256 of the bytes, no prefix. */
export async function sha256Hex(
  sha256: Sha256,
  data: Uint8Array,
): Promise<string> {
  return toHex(await sha256(data));
}

/** Registry form of a Keccak-256 hash: `0x` + 64 lowercase hex. */
export async function keccakHex(
  keccak256: Keccak256,
  data: Uint8Array,
): Promise<`0x${string}`> {
  return `0x${toHex(await keccak256(data))}`;
}

export const HEX64 = /^[0-9a-f]{64}$/;
export const HEX16 = /^[0-9a-f]{16}$/;
export const REGISTRY_HASH = /^0x[0-9a-f]{64}$/;

const MiB = 1024 * 1024;

/** §2.2: a record whose canonical line exceeds this is not published. */
export const RECORD_LINE_LIMIT_BYTES = 8 * MiB;
/** §2.2: default writer target per part. Hosts with less memory pass a smaller target. */
export const DEFAULT_PART_TARGET_BYTES = 4 * MiB;
/** §2.2: decoder limit for a clear head. */
export const HEAD_LIMIT_BYTES = 1 * MiB;
/** §2.2: decoder limit for a clear part; §2.6 bucket winners limit. */
export const PART_LIMIT_BYTES = 16 * MiB;
/** §2.1: registry scope names longer than this are a permanent error. */
export const NAME_LIMIT_BYTES = 256;
/** §2.6: the planner never splits deeper than this many bits. */
export const PLANNER_DEPTH_CAP = 16;
/** §2.6: number of spool shards (first pkHash byte). */
export const SHARD_COUNT = 256;
