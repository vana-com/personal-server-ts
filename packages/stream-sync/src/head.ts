/**
 * §2.5 head format 4, and the head rules of §2.4, §2.5, §2.6 and §2.7:
 * liveness, base choice, the compatible-writer rule, `complete` and no-op.
 *
 * Clear head bytes are canonical JSON:
 *
 *   {"complete":bool,"connector":c,"format":4,"generation":"<dec>",
 *    "keyCheck":"<16 hex>","lastDeleteVersion":n,"ns":ns,"observedAt":<ms>,
 *    "parts":[{"bytes":n,"count":n,"hash":"<sha256>","prefix":"<bits>"}],
 *    "primaryKey":[...],"profile":{"key":<string|null>,"version":"<v>"},
 *    "recordCount":n,"stream":s}
 *
 * The registry `dataHash` of a head is Keccak-256 of these bytes; its blob
 * name is `h-<that hash in hex>`.
 */

import {
  HEAD_LIMIT_BYTES,
  HEX16,
  HEX64,
  PART_LIMIT_BYTES,
  PLANNER_DEPTH_CAP,
  keccakHex,
  utf8,
  type Keccak256,
} from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import { canonicalJson, hasOwn, isPlainObject } from "./json.js";
import { headBlobName } from "./names.js";
import type { HeadPart } from "./parts.js";
import type { ControlState } from "./control.js";

/** The format writers build new heads with: first-seen (v3) frames. Readers also accept formats 1, 2 and 3. */
export const HEAD_FORMAT = 4;
/** Parts are NDJSON lines (§2.2). Readers still accept it; writers no longer write it. */
export const HEAD_FORMAT_PREVIOUS = 1;

export type HeadFormat = 1 | 2 | 3 | 4;

/** Format 4 and later carry the first-seen checkpoint in each record frame. */
export function framesCarryFirstSeen(format: number): boolean {
  return format >= 4;
}

export interface HeadProfile {
  /** The legacy projector's profile key, or `null`. */
  readonly key: string | null;
  /** The connector version that wrote the head. */
  readonly version: string;
}

export interface Head {
  readonly complete: boolean;
  readonly connector: string;
  readonly format: HeadFormat;
  /** Positive integer; written as a decimal string. */
  readonly generation: number;
  /** Version of the last tombstone; absent on pre-fence heads means zero. */
  readonly lastDeleteVersion?: number;
  readonly keyCheck: string;
  readonly ns: string;
  readonly observedAt: number;
  readonly parts: readonly HeadPart[];
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  readonly recordCount: number;
  readonly stream: string;
}

const HEAD_FIELDS = [
  "complete",
  "connector",
  "format",
  "generation",
  "keyCheck",
  "ns",
  "observedAt",
  "parts",
  "primaryKey",
  "profile",
  "recordCount",
  "stream",
];
const PART_FIELDS = ["bytes", "count", "hash", "prefix"];
const PROFILE_FIELDS = ["key", "version"];
const GENERATION = /^[1-9][0-9]*$/;

function exactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length && keys.every((k, i) => k === expected[i])
  );
}

function isCount(value: unknown, min: number): value is number {
  return (
    typeof value === "number" && Number.isSafeInteger(value) && value >= min
  );
}

/** Why a head is malformed, or `null` when it is valid. Fields are checked for `format`. */
function headProblem(
  value: Record<string, unknown>,
  format: HeadFormat,
): string | null {
  const fields =
    format >= 3 ? [...HEAD_FIELDS, "lastDeleteVersion"].sort() : HEAD_FIELDS;
  if (!exactKeys(value, fields)) {
    return `fields must be exactly: ${fields.join(", ")}`;
  }
  const v = value;
  if (format >= 3 && !isCount(v["lastDeleteVersion"], 0))
    return "lastDeleteVersion must be a non-negative safe integer";
  if (typeof v["complete"] !== "boolean") return "complete must be a boolean";
  const connector = v["connector"];
  if (
    typeof connector !== "string" ||
    connector === "" ||
    connector.includes("~")
  ) {
    return "connector must be non-empty with no ~";
  }
  const generation = v["generation"];
  if (
    typeof generation !== "string" ||
    !GENERATION.test(generation) ||
    !Number.isSafeInteger(Number(generation))
  ) {
    return "generation must be a positive decimal string";
  }
  if (typeof v["keyCheck"] !== "string" || !HEX16.test(v["keyCheck"])) {
    return "keyCheck must be 16 lowercase hex";
  }
  const ns = v["ns"];
  if (typeof ns !== "string" || (ns !== "" && !HEX16.test(ns))) {
    return "ns must be empty or 16 lowercase hex";
  }
  if (!isCount(v["observedAt"], 0))
    return "observedAt must be a non-negative integer";
  if (typeof v["stream"] !== "string" || v["stream"] === "") {
    return "stream must be a non-empty string";
  }
  const primaryKey = v["primaryKey"];
  if (
    !Array.isArray(primaryKey) ||
    primaryKey.length === 0 ||
    primaryKey.some((f) => typeof f !== "string" || f === "") ||
    new Set(primaryKey).size !== primaryKey.length
  ) {
    return "primaryKey must be a non-empty list of distinct non-empty strings";
  }
  const profile = v["profile"];
  if (
    !isPlainObject(profile) ||
    !exactKeys(profile, PROFILE_FIELDS) ||
    (profile["key"] !== null && typeof profile["key"] !== "string") ||
    typeof profile["version"] !== "string" ||
    profile["version"] === ""
  ) {
    return "profile must be {key: string|null, version: non-empty string}";
  }
  if (!isCount(v["recordCount"], 0))
    return "recordCount must be a non-negative integer";
  const parts = v["parts"];
  if (!Array.isArray(parts)) return "parts must be an array";
  let total = 0;
  let previous: string | null = null;
  for (let i = 0; i < parts.length; i += 1) {
    const part: unknown = parts[i];
    if (!isPlainObject(part) || !exactKeys(part, PART_FIELDS)) {
      return `part ${i} must have exactly ${PART_FIELDS.join(", ")}`;
    }
    const { bytes, count, hash, prefix } = part;
    // Format 2: a part that only continues a frame started in the part before
    // it starts no frame, so its count is 0.
    const minCount = format !== 1 ? 0 : 1;
    if (!isCount(count, minCount)) {
      return `part ${i} count must be an integer of at least ${minCount}`;
    }
    if (!isCount(bytes, 1) || bytes > PART_LIMIT_BYTES) {
      return `part ${i} bytes must be in [1, ${PART_LIMIT_BYTES}]`;
    }
    if (typeof hash !== "string" || !HEX64.test(hash)) {
      return `part ${i} hash must be 64 lowercase hex`;
    }
    if (
      typeof prefix !== "string" ||
      !/^[01]*$/.test(prefix) ||
      prefix.length > PLANNER_DEPTH_CAP
    ) {
      return `part ${i} prefix must be at most 16 bits of 0 and 1`;
    }
    if (previous !== null) {
      // Format 2: one prefix may hold several parts (frames longer than a
      // part, and the small frames around them), listed in key order.
      const same = format !== 1 && prefix === previous;
      if (!same) {
        if (prefix <= previous) return "parts must be sorted by prefix";
        if (prefix.startsWith(previous))
          return "part prefixes must be prefix-free";
      }
    }
    previous = prefix;
    total += count;
  }
  if (total !== v["recordCount"])
    return "recordCount must equal the sum of part counts";
  return null;
}

function toWire(head: Head): Record<string, unknown> {
  return {
    complete: head.complete,
    connector: head.connector,
    format: head.format,
    generation: String(head.generation),
    ...(head.format >= 3 ? { lastDeleteVersion: head.lastDeleteVersion } : {}),
    keyCheck: head.keyCheck,
    ns: head.ns,
    observedAt: head.observedAt,
    parts: head.parts.map((p) => ({
      bytes: p.bytes,
      count: p.count,
      hash: p.hash,
      prefix: p.prefix,
    })),
    primaryKey: [...head.primaryKey],
    profile: { key: head.profile.key, version: head.profile.version },
    recordCount: head.recordCount,
    stream: head.stream,
  };
}

/**
 * Canonical head bytes in the format the head carries (1–4), so frozen
 * older-format vectors re-encode byte for byte. Writers build new heads with
 * `HEAD_FORMAT`.
 */
export function encodeHead(head: Head): Uint8Array {
  if (![1, 2, 3, 4].includes(head.format)) {
    throw new InvalidArgumentError(`unsupported head format: ${head.format}`);
  }
  if (!Number.isSafeInteger(head.generation) || head.generation < 1) {
    throw new InvalidArgumentError(
      "generation must be a positive safe integer",
    );
  }
  const wire = toWire(head);
  const problem = headProblem(wire, head.format);
  if (problem) throw new InvalidArgumentError(`invalid head: ${problem}`);
  const bytes = utf8(canonicalJson(wire));
  if (bytes.length > HEAD_LIMIT_BYTES) {
    throw new InvalidArgumentError("head exceeds the 1 MiB head limit");
  }
  return bytes;
}

export interface HeadDigest {
  /** Registry form: `0x` + 64 lowercase hex. */
  readonly dataHash: `0x${string}`;
  /** `h-<hex>`. */
  readonly blobName: string;
}

export async function digestHead(
  keccak256: Keccak256,
  bytes: Uint8Array,
): Promise<HeadDigest> {
  const dataHash = await keccakHex(keccak256, bytes);
  return { dataHash, blobName: headBlobName(dataHash) };
}

export type DecodedHead =
  | { readonly kind: "ok"; readonly head: Head }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string };

const decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Parse clear head bytes. Formats outside 1–4 are `unsupported_format`.
 * A head must be canonical, so every host derives the same hash.
 */
export function decodeHead(bytes: Uint8Array): DecodedHead {
  if (bytes.length > HEAD_LIMIT_BYTES) {
    return {
      kind: "malformed",
      reason: "head exceeds the 1 MiB decoder limit",
    };
  }
  let text: string;
  let parsed: unknown;
  try {
    text = decoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return { kind: "malformed", reason: "head is not UTF-8 JSON" };
  }
  if (!isPlainObject(parsed))
    return { kind: "malformed", reason: "head is not an object" };
  const format = hasOwn(parsed, "format") ? parsed["format"] : undefined;
  if (format !== 1 && format !== 2 && format !== 3 && format !== 4) {
    return { kind: "unsupported_format", format };
  }
  const problem = headProblem(parsed, format);
  if (problem) return { kind: "malformed", reason: problem };
  if (canonicalJson(parsed) !== text) {
    return { kind: "malformed", reason: "head is not canonical JSON" };
  }
  const p = parsed as Record<string, unknown> & {
    profile: HeadProfile;
    parts: HeadPart[];
  };
  return {
    kind: "ok",
    head: {
      complete: p["complete"] as boolean,
      connector: p["connector"] as string,
      format,
      generation: Number(p["generation"]),
      ...(format >= 3
        ? { lastDeleteVersion: p["lastDeleteVersion"] as number }
        : {}),
      keyCheck: p["keyCheck"] as string,
      ns: p["ns"] as string,
      observedAt: p["observedAt"] as number,
      parts: p.parts,
      primaryKey: p["primaryKey"] as string[],
      profile: p.profile,
      recordCount: p["recordCount"] as number,
      stream: p["stream"] as string,
    },
  };
}

export type VerifiedHead =
  | { readonly kind: "ok"; readonly head: Head }
  | { readonly kind: "hash_mismatch" }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string }
  | { readonly kind: "name_mismatch" }
  | { readonly kind: "key_mismatch" };

/**
 * §2.5 reader checks on decrypted head bytes: `keccak = dataHash`, format,
 * shape, name fields against the scope, and `keyCheck`. Part SHA-256 is
 * checked per part by `decodePart`.
 */
export async function verifyHead(
  keccak256: Keccak256,
  bytes: Uint8Array,
  expected: {
    readonly dataHash: string;
    readonly connector: string;
    readonly ns: string;
    readonly stream: string;
    readonly keyCheck: string;
  },
): Promise<VerifiedHead> {
  const dataHash = await keccakHex(keccak256, bytes);
  if (dataHash !== expected.dataHash.toLowerCase())
    return { kind: "hash_mismatch" };
  const decoded = decodeHead(bytes);
  if (decoded.kind !== "ok") return decoded;
  const { head } = decoded;
  if (
    head.connector !== expected.connector ||
    head.ns !== expected.ns ||
    head.stream !== expected.stream
  ) {
    return { kind: "name_mismatch" };
  }
  if (head.keyCheck !== expected.keyCheck) return { kind: "key_mismatch" };
  return decoded;
}

/** The stream row as read from the registry. */
export type StreamRow = "absent" | "tombstoned" | "present";

/**
 * §2.4: a stream head is live iff the control is `active(g)`, the stream row
 * is not tombstoned, and the head's generation is g.
 */
export function isHeadLive(
  control: ControlState,
  streamRow: StreamRow,
  headGeneration: number | null,
): boolean {
  return (
    control.kind === "active" &&
    streamRow === "present" &&
    headGeneration === control.generation
  );
}

export type BaseChoice =
  /** The stream row's head is of the target generation: merge onto it. */
  | { readonly kind: "base"; readonly head: Head }
  /** Row absent or tombstoned, or its head is older: fresh generation. */
  | { readonly kind: "empty" }
  /**
   * The row's head is of a NEWER generation than the target: the run's start
   * snapshot is older than the registry. Do not publish; re-read control and
   * decide with phase `stale_base` (P0-RULINGS F1).
   */
  | { readonly kind: "stale_generation" };

/**
 * §2.7 with ruling F1: three outcomes, never two.
 *
 * - row absent or tombstoned, or `head.generation < target` → `empty`
 * - `head.generation == target` → `base`
 * - `head.generation > target` → `stale_generation`
 *
 * A present row needs its verified head: a host that cannot read the head of
 * a present row must not call this (it would take an empty base over data).
 */
export function chooseBase(
  streamRow: StreamRow,
  head: Head | null,
  target: number,
): BaseChoice {
  if (streamRow !== "present") return { kind: "empty" };
  if (head === null) {
    throw new InvalidArgumentError(
      "a present stream row needs its verified head",
    );
  }
  if (head.generation < target) return { kind: "empty" };
  if (head.generation === target) return { kind: "base", head };
  return { kind: "stale_generation" };
}

export type VersionOrder = "higher" | "equal" | "lower";

export type WriterCompatibility =
  /** Same primary key: merge onto the base. */
  | { readonly kind: "use_base" }
  /** Newer connector changed the primary key: empty base, base complete false. */
  | { readonly kind: "empty_base" }
  /** Older (or same-version) connector meets a changed key: do not publish. */
  | { readonly kind: "connector_update_required" };

/**
 * §2.5 compatible-writer rule. `writerVersusBase` is the host's comparison
 * of the writer's connector version with `base.profile.version`.
 */
export function writerCompatibility(
  base: Pick<Head, "primaryKey"> | null,
  writerPrimaryKey: readonly string[],
  writerVersusBase: VersionOrder,
): WriterCompatibility {
  if (base === null) return { kind: "use_base" };
  const same =
    base.primaryKey.length === writerPrimaryKey.length &&
    base.primaryKey.every((field, i) => field === writerPrimaryKey[i]);
  if (same) return { kind: "use_base" };
  return writerVersusBase === "higher"
    ? { kind: "empty_base" }
    : { kind: "connector_update_required" };
}

/**
 * §2.5: `complete` = run `full` OR base `complete` OR seed merged (a host merged its retained history).
 * An empty base (none, tombstoned, other generation, or replaced by
 * `empty_base`) counts as not complete.
 */
export function headComplete(input: {
  readonly full: boolean;
  readonly baseComplete: boolean;
  readonly seedMerged: boolean;
}): boolean {
  return input.full || input.baseComplete || input.seedMerged;
}

/**
 * §2.6: every part and `complete` unchanged against the base → skip upload and
 * POST. With `next`, the next head's primary key and profile must also equal
 * the base's: a re-projection is never a no-op.
 */
export function isNoop(
  base: Head | null,
  parts: readonly HeadPart[],
  complete: boolean,
  next?: { primaryKey: readonly string[]; profile: HeadProfile },
): boolean {
  if (base === null || base.complete !== complete) return false;
  // A changed key or projector profile is a re-projection: it publishes even
  // when every part is unchanged.
  if (next) {
    if (
      next.profile.key !== base.profile.key ||
      next.profile.version !== base.profile.version ||
      next.primaryKey.length !== base.primaryKey.length ||
      next.primaryKey.some((field, i) => field !== base.primaryKey[i])
    ) {
      return false;
    }
  }
  if (base.parts.length !== parts.length) return false;
  return base.parts.every((p, i) => {
    const q = parts[i]!;
    return (
      p.prefix === q.prefix &&
      p.hash === q.hash &&
      p.bytes === q.bytes &&
      p.count === q.count
    );
  });
}
