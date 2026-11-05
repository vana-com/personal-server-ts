import { MalformedHeadError, UnsupportedFormatVersionError } from "./errors.js";
import { SHA256_HEX } from "./hash.js";
import { canonicalJson, hasOwn, isPlainObject } from "./json.js";
import type { Part } from "./parts.js";

/**
 * The head file of one stream of one connection. It names the exact parts of
 * one published state, in order, with their sizes. Readers trust nothing but
 * the head: they fetch only the parts it lists and check each one.
 */

/** The head format this package writes and reads. */
export const FORMAT_VERSION = 1;

/** A registry version. Opaque to the core: it is only stored and compared. */
export type Version = string;

export interface HeadPart {
  readonly hash: string;
  readonly bytes: number;
}

export interface Head {
  readonly format: number;
  readonly stream: string;
  readonly connectionId: string;
  readonly parts: readonly HeadPart[];
  readonly recordCount: number;
  /** The version this state was built from; `null` when built from nothing. */
  readonly baseVersion: Version | null;
}

const HEAD_FIELDS = [
  "baseVersion",
  "connectionId",
  "format",
  "parts",
  "recordCount",
  "stream",
];

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function buildHead(input: {
  stream: string;
  connectionId: string;
  parts: readonly Part[];
  recordCount: number;
  baseVersion: Version | null;
}): Head {
  return {
    format: FORMAT_VERSION,
    stream: input.stream,
    connectionId: input.connectionId,
    parts: input.parts.map((part) => ({
      hash: part.hash,
      bytes: part.bytes.length,
    })),
    recordCount: input.recordCount,
    baseVersion: input.baseVersion,
  };
}

export function encodeHead(head: Head): Uint8Array {
  return encoder.encode(canonicalJson(head));
}

/** Parse and validate head bytes (or text). Fails closed. */
export function decodeHead(source: Uint8Array | string): Head {
  let text: string;
  try {
    text = typeof source === "string" ? source : decoder.decode(source);
  } catch (cause) {
    throw new MalformedHeadError(`head is not valid UTF-8: ${String(cause)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (cause) {
    throw new MalformedHeadError(`head is not valid JSON: ${String(cause)}`);
  }
  return parseHead(parsed);
}

/**
 * Validate an already-parsed head. An unknown future format version is
 * reported before anything else, because its other fields may have changed.
 */
export function parseHead(value: unknown): Head {
  if (!isPlainObject(value))
    throw new MalformedHeadError("head is not a JSON object");
  const format = hasOwn(value, "format") ? value["format"] : undefined;
  if (
    typeof format === "number" &&
    Number.isInteger(format) &&
    format > FORMAT_VERSION
  ) {
    throw new UnsupportedFormatVersionError(format);
  }
  if (format !== FORMAT_VERSION) {
    throw new MalformedHeadError(`head format is not ${FORMAT_VERSION}`);
  }
  const keys = Object.keys(value).sort();
  if (
    keys.length !== HEAD_FIELDS.length ||
    keys.some((k, i) => k !== HEAD_FIELDS[i])
  ) {
    throw new MalformedHeadError(
      `head fields must be exactly: ${HEAD_FIELDS.join(", ")}`,
    );
  }
  const { stream, connectionId, parts, recordCount, baseVersion } = value;
  if (typeof stream !== "string" || stream === "") {
    throw new MalformedHeadError("head stream must be a non-empty string");
  }
  if (typeof connectionId !== "string" || connectionId === "") {
    throw new MalformedHeadError(
      "head connectionId must be a non-empty string",
    );
  }
  if (!Number.isSafeInteger(recordCount) || (recordCount as number) < 0) {
    throw new MalformedHeadError(
      "head recordCount must be a non-negative integer",
    );
  }
  if (baseVersion !== null && typeof baseVersion !== "string") {
    throw new MalformedHeadError("head baseVersion must be a string or null");
  }
  if (!Array.isArray(parts))
    throw new MalformedHeadError("head parts must be an array");
  const checked: HeadPart[] = parts.map((entry: unknown, i) => {
    if (!isPlainObject(entry))
      throw new MalformedHeadError(`head part ${i} is not an object`);
    const entryKeys = Object.keys(entry).sort();
    if (
      entryKeys.length !== 2 ||
      entryKeys[0] !== "bytes" ||
      entryKeys[1] !== "hash"
    ) {
      throw new MalformedHeadError(
        `head part ${i} must have exactly bytes and hash`,
      );
    }
    const { hash, bytes } = entry;
    if (typeof hash !== "string" || !SHA256_HEX.test(hash)) {
      throw new MalformedHeadError(
        `head part ${i} hash is not 64 lowercase hex characters`,
      );
    }
    if (!Number.isSafeInteger(bytes) || (bytes as number) < 0) {
      throw new MalformedHeadError(
        `head part ${i} bytes must be a non-negative integer`,
      );
    }
    return { hash, bytes: bytes as number };
  });
  if ((recordCount as number) === 0 && checked.length > 0) {
    throw new MalformedHeadError("head lists parts for zero records");
  }
  return {
    format: FORMAT_VERSION,
    stream,
    connectionId,
    parts: checked,
    recordCount: recordCount as number,
    baseVersion,
  };
}
