import { InvalidPartSizeError } from "./errors.js";
import { sha256Hex, type Sha256 } from "./hash.js";
import { canonicalJson } from "./json.js";
import type { StampedRecord } from "./records.js";

/** Default part size limit: 4 MiB. Hosts pass their own budget. */
export const DEFAULT_PART_SIZE_BYTES = 4 * 1024 * 1024;

const encoder = new TextEncoder();
const OPEN_TIMES = encoder.encode('{"observedAt":[');
const MID = encoder.encode('],"records":[');
const CLOSE = encoder.encode("]}");
const FRAME_BYTES = OPEN_TIMES.length + MID.length + CLOSE.length;
const COMMA = 0x2c;

export interface Part {
  /** Lowercase hex SHA-256 of `bytes`. */
  readonly hash: string;
  /** The exact bytes: canonical JSON `{"observedAt":[...],"records":[...]}`. */
  readonly bytes: Uint8Array;
  readonly recordCount: number;
}

export interface OversizedRecordWarning {
  readonly code: "oversized-record";
  /** Index of the part that holds the record alone. */
  readonly partIndex: number;
  readonly partBytes: number;
  readonly limit: number;
}

export type SplitWarning = OversizedRecordWarning;

export interface SplitResult {
  readonly parts: Part[];
  readonly warnings: SplitWarning[];
}

interface Encoded {
  readonly time: Uint8Array;
  readonly record: Uint8Array;
}

/**
 * Pack stamped records, in the order given, into parts of at most
 * `partSizeBytes` bytes each. A part is canonical JSON
 * `{"observedAt":[t1,t2,...],"records":[r1,r2,...]}`: the two arrays are the
 * same length, and `observedAt[i]` is the observation time of `records[i]`.
 * The records array stays a plain `{records}` list that a reader unaware of
 * observation times can still use. A part exactly at the limit is allowed. A
 * record too large for any part gets a part of its own and an
 * `oversized-record` warning. No records gives no parts.
 *
 * The caller supplies the order; `overlay` already returns the canonical one.
 */
export async function split(
  records: readonly StampedRecord[],
  sha256: Sha256,
  partSizeBytes: number = DEFAULT_PART_SIZE_BYTES,
): Promise<SplitResult> {
  if (!Number.isSafeInteger(partSizeBytes) || partSizeBytes <= 0) {
    throw new InvalidPartSizeError(partSizeBytes);
  }
  const groups: Encoded[][] = [];
  let current: Encoded[] = [];
  let currentSize = FRAME_BYTES;
  for (const entry of records) {
    const item: Encoded = {
      time: encoder.encode(canonicalJson(entry.observedAt)),
      record: encoder.encode(canonicalJson(entry.record)),
    };
    const cost =
      item.time.length + item.record.length + (current.length > 0 ? 2 : 0);
    if (current.length > 0 && currentSize + cost > partSizeBytes) {
      groups.push(current);
      current = [];
      currentSize = FRAME_BYTES;
    }
    currentSize +=
      item.time.length + item.record.length + (current.length > 0 ? 2 : 0);
    current.push(item);
  }
  if (current.length > 0) groups.push(current);

  const parts: Part[] = [];
  const warnings: SplitWarning[] = [];
  for (const [partIndex, group] of groups.entries()) {
    const bytes = join(group);
    if (group.length === 1 && bytes.length > partSizeBytes) {
      warnings.push({
        code: "oversized-record",
        partIndex,
        partBytes: bytes.length,
        limit: partSizeBytes,
      });
    }
    parts.push({
      hash: await sha256Hex(sha256, bytes),
      bytes,
      recordCount: group.length,
    });
  }
  return { parts, warnings };
}

function join(items: readonly Encoded[]): Uint8Array {
  let total = FRAME_BYTES + 2 * (items.length - 1);
  for (const item of items) total += item.time.length + item.record.length;
  const out = new Uint8Array(total);
  let at = 0;
  const put = (bytes: Uint8Array) => {
    out.set(bytes, at);
    at += bytes.length;
  };
  put(OPEN_TIMES);
  items.forEach((item, i) => {
    if (i > 0) out[at++] = COMMA;
    put(item.time);
  });
  put(MID);
  items.forEach((item, i) => {
    if (i > 0) out[at++] = COMMA;
    put(item.record);
  });
  put(CLOSE);
  return out;
}
