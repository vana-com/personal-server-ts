/**
 * §2.2 records and part lines.
 *
 *   pkHash = sha256(canonicalJson([pk values])), used as a bit string
 *   line   = canonicalJson({"o": <run start ms>, "r": "<runId>", "v": <record>})
 *
 * Canonical JSON sorts keys, so a line always reads `{"o":...,"r":...,"v":...}`.
 */

import { HEX64, sha256Hex, utf8, type Sha256 } from "./bytes.js";
import {
  InvalidArgumentError,
  InvalidLineError,
  InvalidRecordError,
  MissingKeyFieldError,
} from "./errors.js";
import {
  canonicalJson,
  hasOwn,
  isPlainObject,
  type JsonObject,
} from "./json.js";

/** `o` and `r` of seed lines (a host's retained history) (§2.6, §2.9). */
export const SEED_OBSERVED_AT = 0;
export const SEED_RUN_ID = "seed";

export interface Line {
  /** Run start, in milliseconds since the epoch. */
  readonly o: number;
  /** Run id. */
  readonly r: string;
  /** The record exactly as the source gave it. */
  readonly v: JsonObject;
  /**
   * First-seen checkpoint (`first_o`): milliseconds of the first run that
   * collected the record; `null` or absent = unknown. Type only until the
   * v3 frame slice reads and writes it. Spec: r5.2 1.2-1.3.
   */
  readonly f?: number | null;
}

function checkLineFields(o: unknown, r: unknown, v: unknown): void {
  if (typeof o !== "number" || !Number.isSafeInteger(o) || o < 0) {
    throw new InvalidLineError("o must be a non-negative safe integer");
  }
  if (typeof r !== "string" || r === "") {
    throw new InvalidLineError("r must be a non-empty string");
  }
  if (!isPlainObject(v)) throw new InvalidLineError("v must be a JSON object");
}

/** Canonical line text, without a line terminator. */
export function encodeLine(line: Line): string {
  checkLineFields(line.o, line.r, line.v);
  return canonicalJson({ o: line.o, r: line.r, v: line.v });
}

/** Parse one line. Fails unless the text is exactly the canonical form. */
export function decodeLine(text: string): Line {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new InvalidLineError("line is not valid JSON");
  }
  if (!isPlainObject(parsed))
    throw new InvalidLineError("line is not an object");
  const keys = Object.keys(parsed).sort();
  if (
    keys.length !== 3 ||
    keys[0] !== "o" ||
    keys[1] !== "r" ||
    keys[2] !== "v"
  ) {
    throw new InvalidLineError("line fields must be exactly o, r, v");
  }
  const line = parsed as unknown as Line;
  checkLineFields(line.o, line.r, line.v);
  if (canonicalJson(parsed) !== text) {
    throw new InvalidLineError("line is not in canonical form");
  }
  return line;
}

/** The primary-key values of a record, in primary-key order. */
export function primaryKeyValues(
  record: JsonObject,
  primaryKey: readonly string[],
): unknown[] {
  if (!isPlainObject(record))
    throw new InvalidRecordError("record is not a JSON object");
  if (primaryKey.length === 0) {
    throw new InvalidArgumentError("primaryKey must name at least one field");
  }
  return primaryKey.map((field) => {
    if (!hasOwn(record, field)) throw new MissingKeyFieldError(field);
    return record[field];
  });
}

/** sha256(canonicalJson([pk values])) as 64 lowercase hex. */
export async function pkHash(
  sha256: Sha256,
  record: JsonObject,
  primaryKey: readonly string[],
): Promise<string> {
  return sha256Hex(
    sha256,
    utf8(canonicalJson(primaryKeyValues(record, primaryKey))),
  );
}

/**
 * True when `key` is the primary-key tuple `hash` names for a stream with this
 * `primaryKey`: one value per key field, each a string, finite number or
 * boolean, and `sha256(canonicalJson(key)) === hash`. That is the same input
 * `pkHash` hashes, so a deletion that carries the tuple needs no search and
 * names exactly one record.
 */
export async function deletionKeyMatchesHash(
  sha256: Sha256,
  primaryKey: readonly string[],
  key: readonly unknown[],
  hash: string,
): Promise<boolean> {
  if (!HEX64.test(hash) || primaryKey.length === 0) return false;
  if (key.length !== primaryKey.length) return false;
  if (
    !key.every(
      (v) =>
        typeof v === "string" ||
        typeof v === "boolean" ||
        (typeof v === "number" && Number.isFinite(v)),
    )
  )
    return false;
  return (await sha256Hex(sha256, utf8(canonicalJson(key)))) === hash;
}

/** The JSON Schema type a stream declares for a primary-key field. */
export type KeyFieldType = "string" | "number" | "integer" | "boolean";

/**
 * The typed primary-key values of a record, rebuilt from its canonical record
 * key (spec-core.md §4, every component a string) and the types its stream
 * declares for the key fields; `null` when the declaration does not determine
 * them. A value is rebuilt only where the string is exactly what that type
 * prints (`7` for a number, never `7.0` or `07`). The rebuilt tuple is a guess
 * until it hashes to the record's hash (`deletionKeyMatchesHash`): a connector
 * whose data disagrees with its declared schema fails that check and is not
 * guessed at.
 */
export function keyFromRecordKey(
  primaryKey: readonly string[],
  keyTypes: readonly (KeyFieldType | null)[] | null,
  recordKey: string,
): (string | number | boolean)[] | null {
  if (keyTypes === null || keyTypes.length !== primaryKey.length) return null;
  let parts: unknown[];
  if (primaryKey.length === 1) parts = [recordKey];
  else {
    try {
      parts = JSON.parse(recordKey) as unknown[];
    } catch {
      return null;
    }
    if (!Array.isArray(parts) || parts.length !== primaryKey.length)
      return null;
  }
  const key: (string | number | boolean)[] = [];
  for (const [i, part] of parts.entries()) {
    const type = keyTypes[i];
    if (typeof part !== "string" || !type) return null;
    if (type === "string") key.push(part);
    else if (type === "boolean") {
      if (part !== "true" && part !== "false") return null;
      key.push(part === "true");
    } else {
      const n = Number(part);
      if (!Number.isFinite(n) || String(n) !== part) return null;
      key.push(n);
    }
  }
  return key;
}

function checkPkHash(hash: string): void {
  if (!HEX64.test(hash)) {
    throw new InvalidArgumentError(
      "pkHash must be 64 lowercase hex characters",
    );
  }
}

/** The spool shard of a key: its first byte (§2.6). */
export function shardOf(hash: string): number {
  checkPkHash(hash);
  return parseInt(hash.slice(0, 2), 16);
}

/** The first `bits` bits of a pkHash as a string of `0`/`1`. */
export function pkHashBits(hash: string, bits: number): string {
  checkPkHash(hash);
  if (!Number.isInteger(bits) || bits < 0 || bits > 256) {
    throw new InvalidArgumentError("bits must be an integer in [0, 256]");
  }
  let out = "";
  for (let i = 0; out.length < bits; i += 1) {
    out += parseInt(hash[i]!, 16).toString(2).padStart(4, "0");
  }
  return out.slice(0, bits);
}

export const BIT_PREFIX = /^[01]*$/;

/** True when the key's bit string starts with `prefix`. */
export function inPrefix(hash: string, prefix: string): boolean {
  if (!BIT_PREFIX.test(prefix)) {
    throw new InvalidArgumentError("prefix must be a string of 0 and 1");
  }
  return pkHashBits(hash, prefix.length) === prefix;
}
