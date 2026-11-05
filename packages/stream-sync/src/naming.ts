/**
 * Storage names. The naming scheme is an input to this package, not a decision
 * of it: everything that needs a name takes a `StorageNaming`. The placeholder
 * below exists so the reference host and the deletion helper have something to
 * run against. The connection id is an opaque string here.
 *
 * Placeholder grammar (each segment is non-empty and uses `A-Z a-z 0-9 _ -`,
 * so it never contains a dot):
 *   stream (registry key): pdpp.<connection>.<stream>
 *   head object:           pdpp.<connection>.<stream>.head-<sha256 hex>
 *   part object:           pdpp.<connection>.<stream>.part-<sha256 hex>
 *
 * Heads and parts are both named by the hash of their own bytes. A head is
 * never stored under the fixed stream name, where a second writer or a crashed
 * write could replace the bytes of a head the registry already points at.
 */

import { InvalidNameError } from "./errors.js";
import { SHA256_HEX } from "./hash.js";

export interface StreamRef {
  readonly connectionId: string;
  readonly stream: string;
}

export type ParsedName =
  /** The registry key of the stream: the name a registry version chain is kept under. */
  | {
      readonly kind: "stream";
      readonly connectionId: string;
      readonly stream: string;
    }
  /** An immutable head object, named by the SHA-256 of its bytes. */
  | {
      readonly kind: "head";
      readonly connectionId: string;
      readonly stream: string;
      readonly hash: string;
    }
  /** An immutable part object, named by the SHA-256 of its bytes. */
  | {
      readonly kind: "part";
      readonly connectionId: string;
      readonly stream: string;
      readonly hash: string;
    };

export interface StorageNaming {
  /** The registry key. Never a storage object that a later write could replace. */
  streamName(ref: StreamRef): string;
  headName(ref: StreamRef, hash: string): string;
  partName(ref: StreamRef, hash: string): string;
  /** `null` for any name this scheme does not own. */
  parse(name: string): ParsedName | null;
}

const SEGMENT = /^[A-Za-z0-9_-]+$/;
const HEAD_PREFIX = "head-";
const PART_PREFIX = "part-";

function checkSegment(label: string, value: string): string {
  if (!SEGMENT.test(value)) {
    throw new InvalidNameError(
      `${label} is not a valid name segment: ${JSON.stringify(value)}`,
    );
  }
  return value;
}

function streamName(ref: StreamRef): string {
  return `pdpp.${checkSegment("connection id", ref.connectionId)}.${checkSegment("stream", ref.stream)}`;
}

function hashed(ref: StreamRef, prefix: string, hash: string): string {
  if (!SHA256_HEX.test(hash)) {
    throw new InvalidNameError(
      `hash is not 64 lowercase hex characters: ${hash}`,
    );
  }
  return `${streamName(ref)}.${prefix}${hash}`;
}

export const placeholderNaming: StorageNaming = {
  streamName,
  headName: (ref, hash) => hashed(ref, HEAD_PREFIX, hash),
  partName: (ref, hash) => hashed(ref, PART_PREFIX, hash),

  parse(name) {
    const segments = name.split(".");
    if (
      segments[0] !== "pdpp" ||
      (segments.length !== 3 && segments.length !== 4)
    )
      return null;
    const [, connectionId, stream, last] = segments as [
      string,
      string,
      string,
      string | undefined,
    ];
    if (!SEGMENT.test(connectionId) || !SEGMENT.test(stream)) return null;
    if (last === undefined) return { kind: "stream", connectionId, stream };
    for (const [kind, prefix] of [
      ["head", HEAD_PREFIX],
      ["part", PART_PREFIX],
    ] as const) {
      if (last.startsWith(prefix)) {
        const hash = last.slice(prefix.length);
        return SHA256_HEX.test(hash)
          ? { kind, connectionId, stream, hash }
          : null;
      }
    }
    return null;
  },
};
