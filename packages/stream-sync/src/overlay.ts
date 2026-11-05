import {
  InvalidOrderFieldError,
  InvalidPrimaryKeyError,
  InvalidRecordError,
  MissingKeyFieldError,
} from "./errors.js";
import { canonicalJson, hasOwn, isPlainObject } from "./json.js";
import { checkStamped, type StampedRecord } from "./records.js";

export interface OverlayOptions {
  /**
   * The stream declaration's source ordering (or version) field, when it has
   * one. Records are then compared by this field before observation time.
   */
  readonly orderField?: string;
}

/**
 * Overlay one run's records onto a base copy of a stream, keeping the NEWER
 * record for every key.
 *
 * - The key of a record is the tuple of its primary-key field values, compared
 *   as canonical JSON of that tuple (so `0` and `-0` are the same key and
 *   `"1"` and `1` are different keys).
 * - A new key is added.
 * - For a key that exists, the run's record replaces the base record unless the
 *   base record is strictly newer. Newer means: when the stream declares an
 *   `orderField` and both records hold a comparable value there (two numbers,
 *   or two strings), the greater value is newer; otherwise the later
 *   observation time is newer. A tie goes to the run's record.
 * - A key that repeats inside the run, or inside the base, follows the same
 *   rule in input order, so with equal times the last record wins.
 * - A record that lacks a key field fails the whole overlay with
 *   `MissingKeyFieldError`. Nothing is dropped silently.
 * - The result is ordered by the canonical key string (UTF-16 code unit
 *   order), so identical inputs always give identical output. Each surviving
 *   record keeps its own observation time.
 *
 * Records of the base that the run does not mention are kept: an incremental
 * run that sends only changes, or a windowed run that omits older history,
 * never erases the rest of the stream.
 *
 * Observation times come from device clocks. Without an `orderField`, a device
 * whose clock runs ahead can win over a genuinely later observation by a
 * correct clock, by up to the size of the skew. An `orderField` removes that
 * dependence.
 */
export function overlay(
  base: readonly StampedRecord[],
  run: readonly StampedRecord[],
  primaryKey: readonly string[],
  options: OverlayOptions = {},
): StampedRecord[] {
  const fields = validatePrimaryKey(primaryKey);
  const orderField = validateOrderField(options.orderField);
  const byKey = new Map<string, StampedRecord>();
  absorb(byKey, base, fields, orderField, "base");
  absorb(byKey, run, fields, orderField, "run");
  return [...byKey.keys()].sort().map((key) => byKey.get(key)!);
}

/** The ordered key fields of a stream declaration, checked. */
export function validatePrimaryKey(
  primaryKey: readonly string[],
): readonly string[] {
  if (!Array.isArray(primaryKey) || primaryKey.length === 0) {
    throw new InvalidPrimaryKeyError(
      "primary key must list at least one field",
    );
  }
  const seen = new Set<string>();
  for (const field of primaryKey) {
    if (typeof field !== "string" || field === "") {
      throw new InvalidPrimaryKeyError(
        "primary key fields must be non-empty strings",
      );
    }
    if (seen.has(field)) {
      throw new InvalidPrimaryKeyError(`primary key repeats field "${field}"`);
    }
    seen.add(field);
  }
  return primaryKey;
}

function validateOrderField(
  orderField: string | undefined,
): string | undefined {
  if (orderField === undefined) return undefined;
  if (typeof orderField !== "string" || orderField === "") {
    throw new InvalidOrderFieldError("order field must be a non-empty string");
  }
  return orderField;
}

/** Canonical JSON of a record's key tuple. */
export function recordKey(
  record: unknown,
  fields: readonly string[],
  source: "base" | "run",
  index: number,
): string {
  if (!isPlainObject(record)) {
    throw new InvalidRecordError(
      `${source} record ${index} is not a JSON object`,
    );
  }
  const tuple = fields.map((field) => {
    if (!hasOwn(record, field) || record[field] === undefined) {
      throw new MissingKeyFieldError(source, index, field);
    }
    return record[field];
  });
  return canonicalJson(tuple);
}

/** -1, 0 or 1 when the two values are comparable; `undefined` when not. */
function compareOrder(a: unknown, b: unknown): -1 | 0 | 1 | undefined {
  const comparable =
    (typeof a === "number" &&
      typeof b === "number" &&
      Number.isFinite(a) &&
      Number.isFinite(b)) ||
    (typeof a === "string" && typeof b === "string");
  if (!comparable) return undefined;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** True when `challenger` (later in input order) replaces `incumbent`. */
function replaces(
  incumbent: StampedRecord,
  challenger: StampedRecord,
  orderField: string | undefined,
): boolean {
  if (
    orderField !== undefined &&
    hasOwn(incumbent.record, orderField) &&
    hasOwn(challenger.record, orderField)
  ) {
    const byOrder = compareOrder(
      incumbent.record[orderField],
      challenger.record[orderField],
    );
    if (byOrder !== undefined) return byOrder <= 0;
  }
  return challenger.observedAt >= incumbent.observedAt;
}

function absorb(
  byKey: Map<string, StampedRecord>,
  records: readonly StampedRecord[],
  fields: readonly string[],
  orderField: string | undefined,
  source: "base" | "run",
): void {
  records.forEach((entry, index) => {
    const stamped = checkStamped(entry, source, index);
    const key = recordKey(stamped.record, fields, source, index);
    const incumbent = byKey.get(key);
    if (incumbent === undefined || replaces(incumbent, stamped, orderField)) {
      byKey.set(key, stamped);
    }
  });
}
