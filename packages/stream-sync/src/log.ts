/**
 * The stream-sync LOG: head format 6's transport tier. One immutable segment
 * per committed batch holds the operations of every stream the batch touched;
 * one registry commit per batch advances one per-connection log position.
 *
 * This file is the contract. It has no I/O: formats, names, bounds, the
 * ops-since read plan, and the codec. The writer and reader are in
 * `core/src/localdb/log-publish.ts` and `log-apply.ts`.
 *
 * ## Where the log sits
 *
 *   registry row   `pdpp.<c>~<ns>.~log`     (`logScope`)
 *   its version    the log POSITION (registry versions are dense: 1, 2, 3…)
 *   its dataHash   Keccak-256 of the clear NEWEST segment
 *   blob           `<log scope>/s-<keccak hex>` (`segmentBlobName`)
 *
 * The newest segment is the log head: it carries its position, the list of
 * the older segments (`refs`), and the snapshot pointer. A reader that holds
 * position n reads the registry row (1 request), the newest segment (1 GET),
 * and the older segments n+1..position-1 named by `refs` (parallel GETs). It
 * never lists the streams.
 *
 * ## What an operation is
 *
 * Operations reuse the vocabulary of replication profile v1
 * (`core/src/replication/envelope.ts`): `upsert`, `delete`, and a completion
 * (`stream-complete`). They differ from profile v1 in three stated ways:
 *
 * 1. ORDER. The merge winner per record is the GREATEST OBSERVATION STAMP
 *    `(o, r)`, as in `localdb/merge.ts`: not a Lamport counter, and not the
 *    log position. Position orders delivery and gap detection only. A delete
 *    wins a tie with an upsert of the same stamp (`deleteRunRecords` uses
 *    `<=`). Applying the same operations in any order, any number of times,
 *    gives the same records, once the reader keeps a tombstone per deleted key
 *    (see `LogDelete`).
 * 2. OMISSION. A full pass that dropped records is a completion operation that
 *    names the dropped keys. A cutoff alone is unsound: a record the pass saw
 *    again unchanged moves only its local SEEN stamp (`merge.ts`), publishes
 *    nothing, and so a receiver cannot tell it from a dropped one by stamp.
 *    The writer therefore names the dropped keys exactly (`LogCompletion`).
 * 3. NO PER-WRITER CHAIN. Profile v1 chains batches per writer (`sequence`,
 *    `previous`). The log has one chain per connection, ordered by the
 *    registry's compare-and-set on the log row.
 *
 * ## Bounds, derived
 *
 * `refs` is the head's list of segments, so it is bounded by the head's own
 * limit (`HEAD_LIMIT_BYTES`): `maxSegmentRefs()`. A writer whose next segment
 * would exceed it must compact first. COMPACTION IS NOT BUILT: this file only
 * names the bound (`maxSegmentRefs`) and the pointer (`SnapshotPointer`, always
 * `null` for now).
 */

import {
  HEAD_LIMIT_BYTES,
  HEX16,
  PART_LIMIT_BYTES,
  REGISTRY_HASH,
  keccakHex,
  utf8,
  type Keccak256,
} from "./bytes.js";
import { InvalidArgumentError } from "./errors.js";
import {
  canonicalJson,
  hasOwn,
  isPlainObject,
  type JsonObject,
} from "./json.js";
import { streamScope } from "./names.js";

/** The segment format this build writes and reads. */
export const LOG_FORMAT = 1;

/**
 * The reserved stream name of the log row. A connector stream is a manifest
 * name (letters, digits, underscores); `~` never occurs in one, so the log row
 * cannot collide with a stream.
 */
export const LOG_STREAM = "~log";

export function isLogStream(stream: string): boolean {
  return stream === LOG_STREAM;
}

/** Registry scope of the connection's log row. */
export function logScope(connector: string, ns: string): string {
  return streamScope(connector, ns, LOG_STREAM);
}

const SEGMENT_BLOB = /^s-([0-9a-f]{64})$/;

/** `s-<hex>`: the blob name of a segment, from its registry data hash. */
export function segmentBlobName(dataHash: string): string {
  const hex = dataHash.startsWith("0x") ? dataHash.slice(2) : dataHash;
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new InvalidArgumentError(
      `segment hash is not 64 lowercase hex characters: ${dataHash}`,
    );
  }
  return `s-${hex}`;
}

export function isSegmentBlobName(name: string): boolean {
  return SEGMENT_BLOB.test(name);
}

/** A record observation stamp: run time, then run id. Greatest wins. */
export interface LogStamp {
  readonly o: number;
  readonly r: string;
}

/** Strictly after, by `o` then `r`. */
export function stampAfter(a: LogStamp, b: LogStamp): boolean {
  return a.o !== b.o ? a.o > b.o : a.r > b.r;
}

/**
 * The record's current body at its observation stamp. `firstSeen` is the
 * record's first-seen checkpoint (`first_o`), `null` when unknown.
 */
export interface LogUpsert {
  readonly kind: "upsert";
  readonly stream: string;
  readonly pkHash: string;
  readonly stamp: LogStamp;
  readonly firstSeen: number | null;
  readonly value: JsonObject;
}

/**
 * The record is gone as of `stamp`. A reader keeps a tombstone `(stream,
 * pkHash, stamp)` so an upsert that arrives later with a stamp at or before it
 * (a re-delivered or reordered segment) does not bring the record back.
 */
export interface LogDelete {
  readonly kind: "delete";
  readonly stream: string;
  readonly pkHash: string;
  readonly stamp: LogStamp;
}

/**
 * A full pass proved these keys absent. `cutoff` is the replacing run's stamp.
 * `omitted` is every key the pass dropped, ascending, each a tombstone at
 * `cutoff`. A key the pass saw again (even unchanged) is NOT in it. A reader
 * deletes a listed record only if it has not observed the record at or after
 * `cutoff`.
 */
export interface LogCompletion {
  readonly kind: "complete";
  readonly stream: string;
  readonly cutoff: LogStamp;
  readonly omitted: readonly string[];
}

export type LogOperation = LogUpsert | LogDelete | LogCompletion;

/** What the stream's head said, carried with the batch that touched the stream. */
export interface LogStreamMeta {
  readonly stream: string;
  readonly primaryKey: readonly string[];
  readonly profile: { readonly key: string | null; readonly version: string };
  readonly complete: boolean;
}

/** One older segment of the log. */
export interface SegmentRef {
  readonly position: number;
  /** Keccak-256 of the clear segment: its registry data hash and blob name. */
  readonly dataHash: `0x${string}`;
  /** Encrypted length is not known to a reader; this is the CLEAR length. */
  readonly bytes: number;
}

/**
 * The snapshot a compacted log rests on: the per-stream heads (format 5
 * parts) that hold the state at `position`. Reserved. Writers emit `null`
 * until compaction is built; a reader that meets a non-null pointer reads the
 * heads it names before the segments after `position`.
 */
export interface SnapshotPointer {
  readonly position: number;
  readonly heads: readonly {
    readonly stream: string;
    readonly version: number;
    readonly dataHash: `0x${string}`;
  }[];
}

export interface Segment {
  readonly format: typeof LOG_FORMAT;
  readonly connector: string;
  readonly ns: string;
  readonly generation: number;
  readonly keyCheck: string;
  /** The registry version of the log row this segment is the data of. */
  readonly position: number;
  /** When the writer built the batch (ms); informational. */
  readonly observedAt: number;
  /**
   * Position before the first segment listed in `refs`: the snapshot's
   * position, or, with no snapshot, the position before the log began.
   * State at `base` is NOT in this segment's lineage; the reader has it from
   * the snapshot pointer or from the stream heads (a full check).
   */
  readonly base: number;
  readonly snapshot: SnapshotPointer | null;
  /** Older segments, positions `base+1 .. position-1`, ascending, no gap. */
  readonly refs: readonly SegmentRef[];
  readonly streams: readonly LogStreamMeta[];
  readonly operations: readonly LogOperation[];
}

/**
 * The most segments a head may list: the head limit over the largest encoded
 * ref. A derived bound (the head's own byte limit), not a tuned count.
 */
const REF_ENCODED_BOUND = 160;
export function maxSegmentRefs(): number {
  return Math.floor(HEAD_LIMIT_BYTES / REF_ENCODED_BOUND);
}

/** Why a head cannot take another segment without compaction, or `null`. */
export function compactionRequired(refs: number): boolean {
  return refs + 1 > maxSegmentRefs();
}

// ---------------------------------------------------------------------------
// Ops since: the read API.
// ---------------------------------------------------------------------------

export type OpsSincePlan =
  /** The reader holds the head's position: nothing newer. */
  | { readonly kind: "current" }
  /** Fetch these, apply in order. The last one is the head itself. */
  | { readonly kind: "segments"; readonly refs: readonly SegmentRef[] }
  /**
   * The log cannot answer "since n" from its own segments. The reader runs a
   * full check (stream heads, then the log from `base`).
   *   behind_base: n < base (compacted past it, or a new lifetime)
   *   ahead_of_head: n > head position (a restored registry)
   */
  | {
      readonly kind: "gap";
      readonly reason: "behind_base" | "ahead_of_head";
    };

/**
 * The segments a reader at position `since` must apply to reach `head`, in
 * order. Position n+1 is never applied before n: the list is the dense run
 * `since+1 .. head.position`, or it is a gap.
 */
export function planOpsSince(
  head: Segment,
  headRef: SegmentRef,
  since: number,
): OpsSincePlan {
  if (since === head.position) return { kind: "current" };
  if (since > head.position) return { kind: "gap", reason: "ahead_of_head" };
  if (since < head.base) return { kind: "gap", reason: "behind_base" };
  return {
    kind: "segments",
    refs: [...head.refs.filter((ref) => ref.position > since), headRef],
  };
}

// ---------------------------------------------------------------------------
// Codec.
// ---------------------------------------------------------------------------

const SEGMENT_FIELDS = [
  "base",
  "connector",
  "format",
  "generation",
  "keyCheck",
  "ns",
  "observedAt",
  "operations",
  "position",
  "refs",
  "snapshot",
  "streams",
];
const REF_FIELDS = ["bytes", "dataHash", "position"];
const META_FIELDS = ["complete", "primaryKey", "profile", "stream"];
const UPSERT_FIELDS = ["f", "k", "o", "p", "r", "s", "v"];
const DELETE_FIELDS = ["k", "o", "p", "r", "s"];
const COMPLETE_FIELDS = ["k", "o", "omit", "r", "s"];
const SNAPSHOT_FIELDS = ["heads", "position"];
const SNAPSHOT_HEAD_FIELDS = ["dataHash", "stream", "version"];

function exactKeys(value: object, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return (
    keys.length === expected.length && keys.every((k, i) => k === expected[i])
  );
}

const isCount = (value: unknown, min: number): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= min;

const isHex64 = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{64}$/.test(value);

const isStamp = (o: unknown, r: unknown): boolean =>
  isCount(o, 0) && typeof r === "string" && r !== "";

function refProblem(ref: unknown, at: string): string | null {
  if (!isPlainObject(ref) || !exactKeys(ref, REF_FIELDS))
    return `${at} must have exactly ${REF_FIELDS.join(", ")}`;
  if (!isCount(ref["position"], 1)) return `${at} position must be >= 1`;
  if (
    typeof ref["dataHash"] !== "string" ||
    !REGISTRY_HASH.test(ref["dataHash"])
  )
    return `${at} dataHash must be 0x + 64 lowercase hex`;
  if (!isCount(ref["bytes"], 1)) return `${at} bytes must be >= 1`;
  return null;
}

function operationProblem(op: unknown, at: string): string | null {
  if (!isPlainObject(op)) return `${at} must be an object`;
  const kind = op["k"];
  if (kind === "u") {
    if (!exactKeys(op, UPSERT_FIELDS)) return `${at} upsert fields`;
    if (!isPlainObject(op["v"])) return `${at} value must be an object`;
    if (op["f"] !== null && !isCount(op["f"], 0))
      return `${at} first-seen must be null or a count`;
  } else if (kind === "d") {
    if (!exactKeys(op, DELETE_FIELDS)) return `${at} delete fields`;
  } else if (kind === "c") {
    if (!exactKeys(op, COMPLETE_FIELDS)) return `${at} completion fields`;
    const omit = op["omit"];
    if (!Array.isArray(omit) || omit.some((k) => !isHex64(k)))
      return `${at} omit must list 64-hex keys`;
    for (let i = 1; i < omit.length; i += 1)
      if ((omit[i] as string) <= (omit[i - 1] as string))
        return `${at} omit must be ascending and distinct`;
  } else {
    return `${at} unknown operation kind`;
  }
  if (typeof op["s"] !== "string" || op["s"] === "")
    return `${at} stream must be non-empty`;
  if (isLogStream(op["s"])) return `${at} names the reserved log stream`;
  if (kind !== "c" && !isHex64(op["p"])) return `${at} pkHash must be 64 hex`;
  if (!isStamp(op["o"], op["r"])) return `${at} stamp must be (count, run id)`;
  return null;
}

function segmentProblem(value: Record<string, unknown>): string | null {
  if (!exactKeys(value, SEGMENT_FIELDS))
    return `fields must be exactly: ${SEGMENT_FIELDS.join(", ")}`;
  const v = value;
  if (typeof v["connector"] !== "string" || v["connector"] === "")
    return "connector must be non-empty";
  if (typeof v["ns"] !== "string" || (v["ns"] !== "" && !HEX16.test(v["ns"])))
    return "ns must be empty or 16 lowercase hex";
  if (!isCount(v["generation"], 1)) return "generation must be >= 1";
  if (typeof v["keyCheck"] !== "string" || !HEX16.test(v["keyCheck"]))
    return "keyCheck must be 16 lowercase hex";
  if (!isCount(v["position"], 1)) return "position must be >= 1";
  if (!isCount(v["observedAt"], 0)) return "observedAt must be a count";
  if (!isCount(v["base"], 0)) return "base must be a count";
  const base = v["base"] as number;
  const position = v["position"] as number;
  const refs = v["refs"];
  if (!Array.isArray(refs)) return "refs must be an array";
  if (refs.length > maxSegmentRefs()) return "refs exceed the head bound";
  if (base + refs.length + 1 !== position)
    return "refs must be the dense positions base+1 .. position-1";
  for (let i = 0; i < refs.length; i += 1) {
    const problem = refProblem(refs[i], `ref ${i}`);
    if (problem) return problem;
    if ((refs[i] as SegmentRef).position !== base + 1 + i)
      return `ref ${i} must be position ${base + 1 + i}`;
  }
  const snapshot = v["snapshot"];
  if (snapshot !== null) {
    if (!isPlainObject(snapshot) || !exactKeys(snapshot, SNAPSHOT_FIELDS))
      return "snapshot must be null or {heads, position}";
    if (!isCount(snapshot["position"], 1) || snapshot["position"] > base)
      return "snapshot position must be in 1..base";
    const heads = snapshot["heads"];
    if (
      !Array.isArray(heads) ||
      heads.some(
        (h) =>
          !isPlainObject(h) ||
          !exactKeys(h, SNAPSHOT_HEAD_FIELDS) ||
          typeof h["stream"] !== "string" ||
          !isCount(h["version"], 1) ||
          typeof h["dataHash"] !== "string" ||
          !REGISTRY_HASH.test(h["dataHash"]),
      )
    )
      return "snapshot heads must be {stream, version, dataHash}";
  }
  const streams = v["streams"];
  if (!Array.isArray(streams)) return "streams must be an array";
  const seen = new Set<string>();
  for (let i = 0; i < streams.length; i += 1) {
    const meta: unknown = streams[i];
    if (!isPlainObject(meta) || !exactKeys(meta, META_FIELDS))
      return `stream ${i} must have exactly ${META_FIELDS.join(", ")}`;
    const name = meta["stream"];
    if (typeof name !== "string" || name === "" || isLogStream(name))
      return `stream ${i} name is invalid`;
    if (seen.has(name)) return `stream ${i} is listed twice`;
    seen.add(name);
    if (typeof meta["complete"] !== "boolean")
      return `stream ${i} complete must be a boolean`;
    const pk = meta["primaryKey"];
    if (
      !Array.isArray(pk) ||
      pk.length === 0 ||
      pk.some((f) => typeof f !== "string" || f === "")
    )
      return `stream ${i} primaryKey must be non-empty strings`;
    const profile = meta["profile"];
    if (
      !isPlainObject(profile) ||
      !exactKeys(profile, ["key", "version"]) ||
      (profile["key"] !== null && typeof profile["key"] !== "string") ||
      typeof profile["version"] !== "string" ||
      profile["version"] === ""
    )
      return `stream ${i} profile must be {key, version}`;
  }
  const operations = v["operations"];
  if (!Array.isArray(operations)) return "operations must be an array";
  for (let i = 0; i < operations.length; i += 1) {
    const problem = operationProblem(operations[i], `operation ${i}`);
    if (problem) return problem;
    if (!seen.has((operations[i] as { s: string }).s))
      return `operation ${i} names a stream with no meta`;
  }
  return null;
}

function opToWire(op: LogOperation): Record<string, unknown> {
  switch (op.kind) {
    case "upsert":
      return {
        f: op.firstSeen,
        k: "u",
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        s: op.stream,
        v: op.value,
      };
    case "delete":
      return {
        k: "d",
        o: op.stamp.o,
        p: op.pkHash,
        r: op.stamp.r,
        s: op.stream,
      };
    case "complete":
      return {
        k: "c",
        o: op.cutoff.o,
        omit: [...op.omitted],
        r: op.cutoff.r,
        s: op.stream,
      };
  }
}

function toWire(segment: Segment): Record<string, unknown> {
  return {
    base: segment.base,
    connector: segment.connector,
    format: segment.format,
    generation: segment.generation,
    keyCheck: segment.keyCheck,
    ns: segment.ns,
    observedAt: segment.observedAt,
    operations: segment.operations.map(opToWire),
    position: segment.position,
    refs: segment.refs.map((r) => ({
      bytes: r.bytes,
      dataHash: r.dataHash,
      position: r.position,
    })),
    snapshot: segment.snapshot
      ? {
          heads: segment.snapshot.heads.map((h) => ({
            dataHash: h.dataHash,
            stream: h.stream,
            version: h.version,
          })),
          position: segment.snapshot.position,
        }
      : null,
    streams: segment.streams.map((m) => ({
      complete: m.complete,
      primaryKey: [...m.primaryKey],
      profile: { key: m.profile.key, version: m.profile.version },
      stream: m.stream,
    })),
  };
}

/** Canonical clear segment bytes. Throws on a segment that would not decode. */
export function encodeSegment(segment: Segment): Uint8Array {
  const wire = toWire(segment);
  const problem = segmentProblem(wire);
  if (problem) throw new InvalidArgumentError(`invalid segment: ${problem}`);
  const bytes = utf8(canonicalJson(wire));
  if (bytes.length > PART_LIMIT_BYTES)
    throw new InvalidArgumentError("segment exceeds the 16 MiB segment limit");
  return bytes;
}

export interface SegmentDigest {
  readonly dataHash: `0x${string}`;
  /** `s-<hex>`. */
  readonly blobName: string;
}

export async function digestSegment(
  keccak256: Keccak256,
  bytes: Uint8Array,
): Promise<SegmentDigest> {
  const dataHash = await keccakHex(keccak256, bytes);
  return { dataHash, blobName: segmentBlobName(dataHash) };
}

export type DecodedSegment =
  | { readonly kind: "ok"; readonly segment: Segment }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string };

const decoder = new TextDecoder("utf-8", { fatal: true });

function opFromWire(op: Record<string, unknown>): LogOperation {
  const stream = op["s"] as string;
  const stamp = { o: op["o"] as number, r: op["r"] as string };
  if (op["k"] === "u")
    return {
      kind: "upsert",
      stream,
      pkHash: op["p"] as string,
      stamp,
      firstSeen: op["f"] as number | null,
      value: op["v"] as JsonObject,
    };
  if (op["k"] === "d")
    return { kind: "delete", stream, pkHash: op["p"] as string, stamp };
  return {
    kind: "complete",
    stream,
    cutoff: stamp,
    omitted: op["omit"] as string[],
  };
}

export function decodeSegment(bytes: Uint8Array): DecodedSegment {
  if (bytes.length > PART_LIMIT_BYTES)
    return { kind: "malformed", reason: "segment exceeds the 16 MiB limit" };
  let text: string;
  let parsed: unknown;
  try {
    text = decoder.decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    return { kind: "malformed", reason: "segment is not UTF-8 JSON" };
  }
  if (!isPlainObject(parsed))
    return { kind: "malformed", reason: "segment is not an object" };
  const format = hasOwn(parsed, "format") ? parsed["format"] : undefined;
  if (format !== LOG_FORMAT) return { kind: "unsupported_format", format };
  const problem = segmentProblem(parsed);
  if (problem) return { kind: "malformed", reason: problem };
  if (canonicalJson(parsed) !== text)
    return { kind: "malformed", reason: "segment is not canonical JSON" };
  const p = parsed as Record<string, unknown>;
  return {
    kind: "ok",
    segment: {
      format: LOG_FORMAT,
      connector: p["connector"] as string,
      ns: p["ns"] as string,
      generation: p["generation"] as number,
      keyCheck: p["keyCheck"] as string,
      position: p["position"] as number,
      observedAt: p["observedAt"] as number,
      base: p["base"] as number,
      snapshot: p["snapshot"] as Segment["snapshot"],
      refs: p["refs"] as SegmentRef[],
      streams: p["streams"] as LogStreamMeta[],
      operations: (p["operations"] as Record<string, unknown>[]).map(
        opFromWire,
      ),
    },
  };
}

export type VerifiedSegment =
  | { readonly kind: "ok"; readonly segment: Segment; readonly bytes: number }
  | { readonly kind: "hash_mismatch" }
  | { readonly kind: "unsupported_format"; readonly format: unknown }
  | { readonly kind: "malformed"; readonly reason: string }
  | { readonly kind: "name_mismatch" }
  | { readonly kind: "key_mismatch" }
  | { readonly kind: "position_mismatch" };

/**
 * Reader checks on decrypted segment bytes: `keccak = dataHash`, format and
 * shape, connector and namespace against the scope, `keyCheck`, and, when the
 * reader knows it, the position the ref or the registry row promised.
 */
export async function verifySegment(
  keccak256: Keccak256,
  bytes: Uint8Array,
  expected: {
    readonly dataHash: string;
    readonly connector: string;
    readonly ns: string;
    readonly keyCheck: string;
    readonly position?: number;
  },
): Promise<VerifiedSegment> {
  const dataHash = await keccakHex(keccak256, bytes);
  if (dataHash !== expected.dataHash.toLowerCase())
    return { kind: "hash_mismatch" };
  const decoded = decodeSegment(bytes);
  if (decoded.kind !== "ok") return decoded;
  const { segment } = decoded;
  if (segment.connector !== expected.connector || segment.ns !== expected.ns)
    return { kind: "name_mismatch" };
  if (segment.keyCheck !== expected.keyCheck) return { kind: "key_mismatch" };
  if (expected.position !== undefined && segment.position !== expected.position)
    return { kind: "position_mismatch" };
  return { kind: "ok", segment, bytes: bytes.length };
}
