import { canonicalJson } from "./ingest-plan.js";
import { computeRecordKeyFromData, RecordKeyError } from "./record-key.js";

/**
 * Completion metadata for one native collection: "this stream's current live
 * set is exactly what the host's full-stream collection saw". It is checked
 * against the rows SQLite holds, and it writes only completion receipts.
 */

export type StreamCompletionFailure =
  /** The request is malformed. Nothing was read. */
  | "invalid_request"
  /** The trusted declarations do not know the stream. */
  | "unknown_stream"
  /** The trusted declaration for the stream cannot name a primary key. */
  | "invalid_declaration"
  /** A stored live row cannot be digested under the native key/JSON domain. */
  | "invalid_snapshot_data"
  /** The live count or digest differs from the proof. */
  | "snapshot_conflict"
  /** The proof is older than, or ambiguous against, a valid receipt. */
  | "time_conflict"
  /** A stored receipt contradicts the data it claims to describe. */
  | "invalid_prior_receipt";

export class StreamCompletionError extends Error {
  constructor(public readonly reason: StreamCompletionFailure) {
    super(reason);
  }
}

export interface StreamCompletionProof {
  stream: string;
  coverage: "full_stream";
  /** Safe integer >= 0. */
  liveCount: number;
  /** 64 lower-case hex characters. */
  snapshotSha256: string;
}

export interface StreamCompletionRequest {
  instance: string;
  sourceId: string;
  method: string;
  generation: number;
  /** UTC with exactly three fractional digits, e.g. 2026-09-10T06:30:00.000Z. */
  sourceCollectedAt: string;
  collectionTimeBasis: "host_run_finished";
  /** Nonempty, one entry per stream. */
  streams: StreamCompletionProof[];
}

/**
 * Trusted declaration lookup: the primary-key fields of a declared stream, or
 * undefined when the source does not declare it. Never built from a request.
 */
export type StreamDeclarationResolver = (
  sourceId: string,
  stream: string,
) => readonly string[] | undefined;

/** A receipt written by this operation, as stored. */
export interface NativeStreamCompletionReceipt {
  instance: string;
  stream: string;
  method: string;
  generation: number;
  sourceCollectedAt: string;
  /** The write clock when the receipt was stored. This operation never advances it. */
  writeSeq: number;
  liveCount: number;
  snapshotSha256: string;
  collectionTimeBasis: "host_run_finished";
}

const SHA256_HEX = /^[0-9a-f]{64}$/;
const UTC_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function isCompletionTime(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_MILLIS.test(value)) return false;
  // `toISOString` throws on an invalid Date, so test for one first.
  const instant = Date.parse(value);
  return !Number.isNaN(instant) && new Date(instant).toISOString() === value;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** Validates the request's shape, so the store never trusts a cast. */
export function parseCompletionRequest(
  input: StreamCompletionRequest,
): StreamCompletionRequest {
  const invalid = () => new StreamCompletionError("invalid_request");
  const request = input as Partial<StreamCompletionRequest> | null;
  if (
    !request ||
    typeof request !== "object" ||
    !nonEmptyString(request.instance) ||
    !nonEmptyString(request.sourceId) ||
    !nonEmptyString(request.method) ||
    typeof request.generation !== "number" ||
    !Number.isSafeInteger(request.generation) ||
    request.generation < 1 ||
    !isCompletionTime(request.sourceCollectedAt) ||
    request.collectionTimeBasis !== "host_run_finished" ||
    !Array.isArray(request.streams) ||
    request.streams.length === 0
  ) {
    throw invalid();
  }
  const seen = new Set<string>();
  for (const proof of request.streams as Partial<StreamCompletionProof>[]) {
    if (
      !proof ||
      typeof proof !== "object" ||
      !nonEmptyString(proof.stream) ||
      seen.has(proof.stream) ||
      proof.coverage !== "full_stream" ||
      typeof proof.liveCount !== "number" ||
      !Number.isSafeInteger(proof.liveCount) ||
      proof.liveCount < 0 ||
      typeof proof.snapshotSha256 !== "string" ||
      !SHA256_HEX.test(proof.snapshotSha256)
    ) {
      throw invalid();
    }
    seen.add(proof.stream);
  }
  return request as StreamCompletionRequest;
}

const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** JSON-native values only: no coercion of undefined, Date, NaN or Infinity. */
function assertJsonNative(value: unknown): void {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (LONE_SURROGATE.test(value)) throw badData();
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw badData();
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) assertJsonNative(item);
    return;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw badData();
    for (const [key, item] of Object.entries(value)) {
      if (LONE_SURROGATE.test(key)) throw badData();
      assertJsonNative(item);
    }
    return;
  }
  throw badData();
}

const badData = () => new StreamCompletionError("invalid_snapshot_data");

/**
 * Stored scalar keys are literal strings, so a single-key declaration never
 * reads an array-looking key as a compound one. A compound key must be the
 * exact minified string array of the declared arity.
 */
function assertKeyDomain(
  recordKey: string,
  data: Record<string, unknown>,
  primaryKey: readonly string[],
): void {
  if (primaryKey.length > 1) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(recordKey);
    } catch {
      throw badData();
    }
    if (
      !Array.isArray(parsed) ||
      parsed.length !== primaryKey.length ||
      !parsed.every((part) => typeof part === "string") ||
      JSON.stringify(parsed) !== recordKey
    ) {
      throw badData();
    }
  }
  try {
    if (computeRecordKeyFromData(data, [...primaryKey]) !== recordKey) {
      throw badData();
    }
  } catch (error) {
    if (error instanceof RecordKeyError) throw badData();
    throw error;
  }
}

export interface LiveSnapshotIdentity {
  sourceId: string;
  instance: string;
  method: string;
  generation: number;
  stream: string;
}

export interface LiveSnapshotRow {
  recordKey: string;
  /** The stored JSON text of `data`. */
  dataJson: string;
}

/**
 * UTF-8 digest input: the canonical JSON of
 * `[source_id, instance, method, generation, stream, sortedPairs]`, each pair
 * `[encodedRecordKey, parsedData]`. Pairs sort by JS UTF-16 string order. Row
 * and envelope metadata are not part of it; every `data` property is, unknown
 * ones, `blob_ref` and timestamps included. The bytes of objects follow the
 * existing `canonicalJson` (JS enumeration order after key sorting), so a
 * native producer must reuse that function rather than a second serializer.
 */
export function encodeLiveSnapshotDigestInput(
  identity: LiveSnapshotIdentity,
  primaryKey: readonly string[],
  rows: readonly LiveSnapshotRow[],
): Uint8Array<ArrayBuffer> {
  const pairs: [string, unknown][] = rows.map((row) => {
    let data: unknown;
    try {
      data = JSON.parse(row.dataJson);
    } catch {
      throw badData();
    }
    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw badData();
    }
    assertKeyDomain(row.recordKey, data as Record<string, unknown>, primaryKey);
    return [row.recordKey, data];
  });
  pairs.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (let i = 1; i < pairs.length; i++) {
    if (pairs[i][0] === pairs[i - 1][0]) throw badData();
  }
  const tuple = [
    identity.sourceId,
    identity.instance,
    identity.method,
    identity.generation,
    identity.stream,
    pairs,
  ];
  assertJsonNative(tuple);
  return new TextEncoder().encode(canonicalJson(tuple));
}

/** SHA-256 adapter; resolves to the 32 digest bytes, without a Node dependency. */
export type Sha256 = (input: Uint8Array<ArrayBuffer>) => Promise<Uint8Array>;

/** Hashes the shared validated bytes; Web Crypto is the default host adapter. */
export async function liveSnapshotDigestAsync(
  identity: LiveSnapshotIdentity,
  primaryKey: readonly string[],
  rows: readonly LiveSnapshotRow[],
  sha256: Sha256 = async (input) =>
    new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input)),
): Promise<string> {
  const bytes = encodeLiveSnapshotDigestInput(identity, primaryKey, rows);
  const digest = await sha256(bytes);
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
