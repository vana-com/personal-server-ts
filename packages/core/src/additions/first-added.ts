/**
 * First-added ledger: when each record of a scope first appeared.
 *
 * The Personal Server stores each data import as one envelope per scope,
 * `{ scope, collectedAt, data }`, and a re-import replaces the whole scope
 * with a fresh full snapshot. Nothing in that shape records when an
 * individual record first appeared, so this module derives a per-record
 * first-seen ledger from successive snapshots and is later stamped into the
 * envelope `data` under the reserved `$firstAdded` key, the same in-`data`
 * marker idiom as `$lineage` and `$writtenBy`.
 *
 * Everything here is pure: it never reads or writes a store, and it never
 * mutates the `data` objects it is handed.
 */

import { canonicalizeJson } from "../derivatives/e2ee/jcs.js";
import { memoryRecordRulesFor, type MemoryRecordRule } from "./record-rules.js";

/** Reserved key inside the envelope `data` record for the first-added ledger. */
export const FIRST_ADDED_KEY = "$firstAdded" as const;

/**
 * records: record key -> ISO timestamp the record was first added,
 * or null when the record already existed before tracking began.
 */
export interface FirstAddedLedger {
  version: 1;
  /** collectedAt of the first snapshot of this scope that carried a ledger. */
  trackedSince: string;
  records: Record<string, string | null>;
}

/** A PDPP `records` element, the only shape the PDPP form accepts. */
interface PdppRecord {
  stream: string;
  data: Record<string, unknown>;
}

/** Property order an object's stable id is searched in. */
const ID_PROPERTIES = ["id", "uuid", "key", "uri", "url"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(data: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(data, key);
}

export function hasReservedFirstAddedKey(
  data: Record<string, unknown>,
): boolean {
  return hasOwn(data, FIRST_ADDED_KEY);
}

/** Returns a NEW object: { ...data, [FIRST_ADDED_KEY]: ledger }. Never mutates `data`. */
export function stampFirstAdded(
  data: Record<string, unknown>,
  ledger: FirstAddedLedger,
): Record<string, unknown> {
  return { ...data, [FIRST_ADDED_KEY]: ledger };
}

/**
 * The ledger stored in `data`, or null when absent or malformed. Never throws.
 * Valid means: data[FIRST_ADDED_KEY] is a plain object with version === 1,
 * trackedSince a non-empty string, and records a plain object whose every
 * value is a string or null.
 */
export function readFirstAddedLedger(
  data: Record<string, unknown>,
): FirstAddedLedger | null {
  try {
    if (!isRecord(data) || !hasOwn(data, FIRST_ADDED_KEY)) return null;
    const value = data[FIRST_ADDED_KEY];
    if (!isRecord(value)) return null;
    if (value.version !== 1) return null;
    const trackedSince = value.trackedSince;
    if (typeof trackedSince !== "string" || trackedSince.length === 0) {
      return null;
    }
    const records = value.records;
    if (!isRecord(records)) return null;
    for (const recordValue of Object.values(records)) {
      if (recordValue !== null && typeof recordValue !== "string") return null;
    }
    return {
      version: 1,
      trackedSince,
      records: records as Record<string, string | null>,
    };
  } catch {
    return null;
  }
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  let hex = "";
  for (const byte of new Uint8Array(digest)) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/** `"h:"` + the first 32 lowercase hex chars of SHA-256 over the canonical form. */
async function hashPart(value: unknown): Promise<string> {
  let canonical: string;
  try {
    canonical = canonicalizeJson(value);
  } catch {
    canonical = JSON.stringify(value) ?? "null";
  }
  return `h:${(await sha256Hex(canonical)).slice(0, 32)}`;
}

/**
 * The value at a dotted path of plain objects, or undefined when any segment
 * is missing or not a plain object.
 */
function valueAtPath(obj: Record<string, unknown>, path: string): unknown {
  let current: unknown = obj;
  for (const segment of path.split(".")) {
    if (!isRecord(current) || !hasOwn(current, segment)) return undefined;
    current = current[segment];
  }
  return current;
}

/**
 * `"i:" + String(id)` for the first `fields` entry whose value (a non-empty
 * string or a finite number) qualifies; otherwise the content hash of `obj`.
 */
async function idPart(
  obj: Record<string, unknown>,
  fields: readonly string[],
): Promise<string> {
  for (const field of fields) {
    const value = valueAtPath(obj, field);
    if (typeof value === "string" && value.length > 0) {
      return `i:${value}`;
    }
    if (typeof value === "number" && Number.isFinite(value)) {
      return `i:${String(value)}`;
    }
  }
  return hashPart(obj);
}

function isPdppRecord(value: unknown): value is PdppRecord {
  return (
    isRecord(value) && typeof value.stream === "string" && isRecord(value.data)
  );
}

/** Every element as a PDPP record, or null when the array is not PDPP-shaped. */
function asPdppRecords(value: unknown): PdppRecord[] | null {
  if (!Array.isArray(value)) return null;
  const records: PdppRecord[] = [];
  for (const element of value) {
    if (!isPdppRecord(element)) return null;
    records.push(element);
  }
  return records;
}

function dedupe(keys: string[]): string[] {
  return Array.from(new Set(keys));
}

/** The generic rule, used only for scopes with no entry in the rules table. */
async function extractGenericRecordKeys(
  data: Record<string, unknown>,
): Promise<string[]> {
  // PDPP form: one `records` array of `{ stream, data }` envelopes.
  const pdppRecords = asPdppRecords(data.records);
  if (pdppRecords) {
    const keys: string[] = [];
    for (const record of pdppRecords) {
      keys.push(`${record.stream}:${await idPart(record.data, ID_PROPERTIES)}`);
    }
    return dedupe(keys);
  }

  // Legacy form: every non-reserved top-level array is a record collection.
  const keys: string[] = [];
  let sawArray = false;
  for (const key of Object.keys(data)) {
    if (key.startsWith("$")) continue;
    const value = data[key];
    if (!Array.isArray(value)) continue;
    sawArray = true;
    for (const element of value) {
      if (isRecord(element)) {
        keys.push(`${key}:${await idPart(element, ID_PROPERTIES)}`);
      } else {
        keys.push(`${key}:${await hashPart(element)}`);
      }
    }
  }
  // No arrays at all: the scope itself is the single record (a profile).
  if (!sawArray) return ["_"];
  return dedupe(keys);
}

/**
 * The items of a rule from a PDPP `records` array, in stream order. A
 * `streamFilter` (PDPP only) keeps a split stream's rows to one collection.
 */
function pdppItems(
  records: PdppRecord[],
  rule: MemoryRecordRule,
): Record<string, unknown>[] {
  const names = new Set<string>([rule.collection, ...(rule.aliases ?? [])]);
  return records
    .filter((record) => names.has(record.stream))
    .filter(
      (record) =>
        !rule.streamFilter ||
        record.data[rule.streamFilter.field] === rule.streamFilter.equals,
    )
    .map((r) => r.data);
}

/** The items of a rule from a legacy body; the first matching array wins. */
function legacyItems(
  data: Record<string, unknown>,
  rule: MemoryRecordRule,
): Record<string, unknown>[] {
  for (const name of [rule.collection, ...(rule.aliases ?? [])]) {
    if (!hasOwn(data, name)) continue;
    const value = data[name];
    if (!Array.isArray(value)) continue;
    return value.filter(isRecord);
  }
  return [];
}

/**
 * Stable keys for the records in an envelope `data` object, de-duplicated,
 * in first-seen order. Returns null when the data is not trackable.
 *
 * A ruled scope only produces keys for its named collections; the generic
 * rule remains the default for scopes with no rules entry.
 */
export async function extractRecordKeys(
  scope: string,
  data: Record<string, unknown>,
): Promise<string[] | null> {
  if (!isRecord(data)) return null;
  // A binary payload has no addressable records and is never tracked.
  if (hasOwn(data, "$binary")) return null;

  const rules = memoryRecordRulesFor(scope);
  if (rules === null) return extractGenericRecordKeys(data);

  const pdppRecords = asPdppRecords(data.records);
  const keys: string[] = [];
  for (const rule of rules) {
    const items = pdppRecords
      ? pdppItems(pdppRecords, rule)
      : legacyItems(data, rule);
    for (const item of items) {
      keys.push(`${rule.collection}:${await idPart(item, rule.idFields)}`);
    }
  }
  return dedupe(keys);
}

export interface BuildFirstAddedLedgerInput {
  /** Scope whose record rules select the tracked collections. */
  scope: string;
  /** `data` of the scope's previous snapshot, or null when this is the scope's first snapshot. */
  previousData: Record<string, unknown> | null;
  /** `data` about to be stored (without a ledger). */
  newData: Record<string, unknown>;
  /** collectedAt of the snapshot about to be stored (ISO string). */
  collectedAt: string;
}

/** The ledger to stamp into `newData`, or null when `newData` is not trackable. */
export async function buildFirstAddedLedger(
  input: BuildFirstAddedLedgerInput,
): Promise<FirstAddedLedger | null> {
  const newKeys = await extractRecordKeys(input.scope, input.newData);
  if (newKeys === null) return null;

  // A Map keeps arbitrary keys (including "__proto__") out of the prototype
  // chain; Object.fromEntries then defines each one as an own property.
  const records = new Map<string, string | null>();
  const previousLedger = input.previousData
    ? readFirstAddedLedger(input.previousData)
    : null;

  if (previousLedger) {
    // Case A: extend the previous ledger. Known records keep their timestamp
    // (or null), new ones get this snapshot's collectedAt, and records absent
    // from this export are kept so a gap does not re-count them.
    for (const key of Object.keys(previousLedger.records)) {
      records.set(key, previousLedger.records[key] ?? null);
    }
    for (const key of newKeys) {
      if (!records.has(key)) records.set(key, input.collectedAt);
    }
    return {
      version: 1,
      trackedSince: previousLedger.trackedSince,
      records: Object.fromEntries(records),
    };
  }

  if (input.previousData !== null) {
    // Case B: the previous snapshot predates tracking. Everything it held
    // existed before tracking began (null); genuinely new keys are dated now.
    const previousKeys =
      (await extractRecordKeys(input.scope, input.previousData)) ?? [];
    for (const key of previousKeys) {
      if (!records.has(key)) records.set(key, null);
    }
    for (const key of newKeys) {
      if (!records.has(key)) records.set(key, input.collectedAt);
    }
    return {
      version: 1,
      trackedSince: input.collectedAt,
      records: Object.fromEntries(records),
    };
  }

  // Case C: first snapshot of the scope; every record is first added now.
  for (const key of newKeys) {
    if (!records.has(key)) records.set(key, input.collectedAt);
  }
  return {
    version: 1,
    trackedSince: input.collectedAt,
    records: Object.fromEntries(records),
  };
}

/** All non-null first-added timestamps in the ledger (one per record), unsorted. */
export function listFirstAddedTimestamps(ledger: FirstAddedLedger): string[] {
  return Object.values(ledger.records).filter(
    (value): value is string => value !== null,
  );
}
