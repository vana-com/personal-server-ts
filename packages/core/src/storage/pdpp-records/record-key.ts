/**
 * Canonical record-key encoding, spec-core.md Section 4 "Compound key encoding".
 *
 * Single-field primary keys: the key is the string form of that value.
 * Multi-field (compound) primary keys: the key is the minified JSON array of
 * string-converted key values, in the order declared by the SourceDeclaration
 * `primary_key`. Every component is converted to a string before encoding,
 * even when the source value is a number, boolean, or date.
 */

import type { EnvelopeKey } from "./types.js";

/** Converts a single primary-key field value to its canonical string form. */
function toKeyComponentString(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value instanceof Date) return value.toISOString();
  if (value === null || value === undefined) {
    throw new RecordKeyError(
      "Primary key component cannot be null or undefined",
    );
  }
  // Objects/arrays are not valid primary-key component types.
  throw new RecordKeyError(
    `Primary key component has unsupported type: ${typeof value}`,
  );
}

export class RecordKeyError extends Error {}

/**
 * Encodes an envelope `key` (string or string[]) into the canonical record-key
 * string used for storage, URLs, and `resources[]` grant entries.
 */
export function encodeRecordKey(key: EnvelopeKey): string {
  if (Array.isArray(key)) {
    if (key.length === 0) {
      throw new RecordKeyError("Compound key array must not be empty");
    }
    const components = key.map(toKeyComponentString);
    return JSON.stringify(components);
  }
  return toKeyComponentString(key);
}

/**
 * Computes the canonical record key from a record's `data` object and the
 * stream's declared `primary_key` field list, independent of the envelope's
 * `key` field. Used to validate `key` <-> `data` agreement (spec §4 "Record
 * identity").
 */
export function computeRecordKeyFromData(
  data: Record<string, unknown>,
  primaryKeyFields: string[],
): string {
  if (primaryKeyFields.length === 0) {
    throw new RecordKeyError("Stream has no declared primary_key fields");
  }
  if (primaryKeyFields.length === 1) {
    const [field] = primaryKeyFields;
    if (!(field in data)) {
      throw new RecordKeyError(`data is missing primary key field "${field}"`);
    }
    return toKeyComponentString(data[field]);
  }
  const components = primaryKeyFields.map((field) => {
    if (!(field in data)) {
      throw new RecordKeyError(`data is missing primary key field "${field}"`);
    }
    return toKeyComponentString(data[field]);
  });
  return JSON.stringify(components);
}

/**
 * Validates that the envelope `key` field encodes to the same canonical
 * string as the record's `data`, per spec §4 "Record identity": "the values
 * of the `data` fields named by the stream's `primary_key` MUST match the
 * values in the `key` envelope field (in order)."
 */
export function keyMatchesData(
  envelopeKey: EnvelopeKey,
  data: Record<string, unknown>,
  primaryKeyFields: string[],
): boolean {
  const fromEnvelope = encodeRecordKey(envelopeKey);
  const fromData = computeRecordKeyFromData(data, primaryKeyFields);
  return fromEnvelope === fromData;
}
