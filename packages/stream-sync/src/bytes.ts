/**
 * Ports and byte helpers. The package imports no crypto, clock, randomness or
 * I/O: hosts inject every hash and the namespace HMAC.
 */

import { InvalidArgumentError } from "./errors.js";

/** SHA-256 of the exact bytes, as the 32-byte digest. */
export type Sha256 = (data: Uint8Array) => Promise<Uint8Array>;

/**
 * Incremental SHA-256: feed pieces with `update`, then read the 32-byte
 * digest once. Needed for bodies that are never held as one buffer (WebCrypto
 * has no incremental digest, so hosts supply a JavaScript implementation).
 */
export interface Sha256Stream {
  update(data: Uint8Array): void;
  digest(): Uint8Array;
}
export type Sha256StreamFactory = () => Sha256Stream;

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

/**
 * UTF-8 byte length of `text`, counted without encoding it. Lone surrogates
 * count as the 3-byte replacement character, as TextEncoder writes them.
 */
export function utf8Length(text: string): number {
  let bytes = 0;
  for (let i = 0; i < text.length; i += 1) {
    const unit = text.charCodeAt(i);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i += 1;
      } else bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

const HEX_PAIRS = Array.from({ length: 256 }, (_, byte) =>
  byte.toString(16).padStart(2, "0"),
);

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += HEX_PAIRS[bytes[i]!];
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

const BYTES32_HEX = /^(?:0[xX])?([0-9a-fA-F]{64})$/;

/**
 * The one spelling of a 32-byte digest: lowercase hex with a `0x` prefix.
 * Accepts exactly 64 hex digits, with an optional `0x` or `0X` prefix, in any
 * case. Throws on any other input, so a malformed digest never compares equal
 * to a real one.
 */
export function canonicalBytes32(value: string): `0x${string}` {
  const match = BYTES32_HEX.exec(value);
  if (!match) {
    throw new InvalidArgumentError(
      "expected a bytes32 value: 64 hex digits with an optional 0x prefix",
    );
  }
  return `0x${match[1]!.toLowerCase()}`;
}

/** Frames at most this large are held whole in memory by a reducer; larger ones are located, not held. */
export const FRAME_SMALL_BYTES = 1 * MiB;
/** Piece size for a frame longer than {@link FRAME_SMALL_BYTES}: each piece is its own part. */
export const FRAME_PIECE_BYTES = DEFAULT_PART_TARGET_BYTES;
