/**
 * §2.2 part codec. A part is NDJSON: one canonical line per winning record,
 * sorted by pkHash, each line terminated by `\n`. A prefix with no records
 * has no part.
 */

import { PART_LIMIT_BYTES, sha256Hex, utf8, type Sha256 } from "./bytes.js";
import { InvalidArgumentError, InvalidPartError } from "./errors.js";
import type { BucketResult, Winner } from "./merge.js";
import { decodeLine, inPrefix, pkHash, type Line } from "./records.js";

/** One entry of a head's `parts` list. */
export interface HeadPart {
  readonly bytes: number;
  readonly count: number;
  /** SHA-256 of the clear part bytes, 64 lowercase hex. */
  readonly hash: string;
  /** The bucket's bit prefix, e.g. `""`, `"0"`, `"1011"`. */
  readonly prefix: string;
}

export interface EncodedPart {
  readonly entry: HeadPart;
  readonly data: Uint8Array;
}

/** Encode a reduced bucket. Returns `null` for an empty bucket. */
export async function encodePart(
  sha256: Sha256,
  bucket: Extract<BucketResult, { kind: "ok" }>,
): Promise<EncodedPart | null> {
  return encodeWinners(sha256, bucket.prefix, bucket.winners);
}

export async function encodeWinners(
  sha256: Sha256,
  prefix: string,
  winners: readonly Winner[],
): Promise<EncodedPart | null> {
  if (winners.length === 0) return null;
  let text = "";
  let previous: string | null = null;
  for (const winner of winners) {
    if (previous !== null && winner.pkHash <= previous) {
      throw new InvalidArgumentError(
        "winners must be strictly sorted by pkHash",
      );
    }
    previous = winner.pkHash;
    text += `${winner.text}\n`;
  }
  const data = utf8(text);
  if (data.length > PART_LIMIT_BYTES) {
    throw new InvalidArgumentError("part exceeds the 16 MiB part limit");
  }
  return {
    data,
    entry: {
      bytes: data.length,
      count: winners.length,
      hash: await sha256Hex(sha256, data),
      prefix,
    },
  };
}

export interface DecodedLine {
  readonly text: string;
  readonly line: Line;
}

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Verify part bytes against their head entry and decode the lines. When
 * `primaryKey` is given, also check every line is inside the part's prefix
 * and lines are strictly sorted by pkHash.
 */
export async function decodePart(
  sha256: Sha256,
  data: Uint8Array,
  entry: HeadPart,
  primaryKey?: readonly string[],
): Promise<DecodedLine[]> {
  if (data.length > PART_LIMIT_BYTES) {
    throw new InvalidPartError("part exceeds the 16 MiB decoder limit");
  }
  if (data.length !== entry.bytes) {
    throw new InvalidPartError(
      `part has ${data.length} bytes, head says ${entry.bytes}`,
    );
  }
  if ((await sha256Hex(sha256, data)) !== entry.hash) {
    throw new InvalidPartError("part SHA-256 does not match the head");
  }
  let text: string;
  try {
    text = decoder.decode(data);
  } catch {
    throw new InvalidPartError("part is not valid UTF-8");
  }
  if (!text.endsWith("\n")) {
    throw new InvalidPartError("part does not end with a line terminator");
  }
  const lines = text.slice(0, -1).split("\n");
  if (lines.length !== entry.count) {
    throw new InvalidPartError(
      `part has ${lines.length} lines, head says ${entry.count}`,
    );
  }
  const out: DecodedLine[] = [];
  let previous: string | null = null;
  for (const lineText of lines) {
    let line: Line;
    try {
      line = decodeLine(lineText);
    } catch (cause) {
      throw new InvalidPartError(`bad line: ${(cause as Error).message}`);
    }
    if (primaryKey) {
      const hash = await pkHash(sha256, line.v, primaryKey);
      if (!inPrefix(hash, entry.prefix)) {
        throw new InvalidPartError("line key is outside the part prefix");
      }
      if (previous !== null && hash <= previous) {
        throw new InvalidPartError("lines are not strictly sorted by pkHash");
      }
      previous = hash;
    }
    out.push({ text: lineText, line });
  }
  return out;
}
