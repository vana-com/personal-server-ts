/**
 * First-seen ledger: when each record of a scope was first seen.
 *
 * The Personal Server stores each data import as one envelope per scope,
 * `{ scope, collectedAt, data }`, and a re-import replaces the whole scope
 * with a fresh full snapshot. Nothing in that shape records when an
 * individual record first appeared, so this module derives a per-record
 * first-seen ledger by folding the scope's stored versions.
 *
 * The ledger is a SIDECAR kept beside the data (see `ledger-store.ts`). It
 * is never stamped into a stored envelope, never synced as data and never
 * served to grantees: it is a cache that can always be rebuilt from the
 * retained versions.
 *
 * Everything here is pure: it never reads or writes a store and never
 * mutates the objects it is handed. Folding is order independent and
 * idempotent, so two devices that hold the same versions compute the same
 * ledger, and a version folded twice changes nothing.
 */

import { memoryRecordRulesFor, type MemoryRecordRule } from "./record-rules.js";

/** At most this many tracked keys per scope snapshot; beyond it tracking is skipped. */
export const MAX_TRACKED_KEYS = 200_000;
/** Ids longer than this are replaced by a hash so keys stay bounded. */
export const MAX_ID_LENGTH = 128;
/** A record absent from the newest version is dropped after this long. */
export const PRUNE_AFTER_MS = 90 * 24 * 60 * 60 * 1000;

export type LedgerSkipReason = "too_many_keys";

/** One document per scope, stored as a sidecar beside the data. */
export interface ScopeFirstSeenLedger {
  version: 2;
  scope: string;
  /** collectedAt of the EARLIEST version folded in. Records first seen then predate tracking. */
  baseline: string;
  /** collectedAt of the NEWEST version folded in, and that version's record total. */
  latest: { collectedAt: string; total: number; skipped?: LedgerSkipReason };
  /** record key -> [firstSeen collectedAt, lastSeen collectedAt] */
  records: Record<string, [string, string]>;
}

/** A stored version to fold: its collectedAt and the envelope `data` as stored. */
export interface VersionToFold {
  scope: string;
  collectedAt: string;
  data: Record<string, unknown>;
}

export interface RecordKeyExtraction {
  /** De-duplicated keys of the records that have a usable id, in first-seen order. */
  keys: string[];
  /** Records in the counted collections, tracked or not. */
  total: number;
}

/** Property order an object's stable id is searched in. */
const ID_PROPERTIES = ["id", "uuid", "key", "uri", "url"] as const;

/** Keys the server stamps into `data`; mirrors `storage/legacy-projection.ts`. */
const SERVER_STAMP_KEYS: ReadonlySet<string> = new Set([
  "$writtenBy",
  "$lineage",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(data: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(data, key);
}

/**
 * The stored PDPP rows form: the only key that is not server-stamped is
 * `records`, and it is an array. Mirrors `isRecordsBody` in
 * `storage/legacy-projection.ts` (which is not importable here: this module
 * must stay browser-safe).
 */
function isRowsBody(
  data: Record<string, unknown>,
): data is Record<string, unknown> & { records: unknown[] } {
  const keys = Object.keys(data).filter((key) => !SERVER_STAMP_KEYS.has(key));
  return (
    keys.length === 1 && keys[0] === "records" && Array.isArray(data.records)
  );
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

async function idToken(id: string): Promise<string> {
  return id.length > MAX_ID_LENGTH
    ? `h:${(await sha256Hex(id)).slice(0, 32)}`
    : `i:${id}`;
}

/**
 * The identity token of a record: `i:<id>` (or `h:<hash>` for a long id) for
 * the first `fields` entry that is a non-empty string or a finite number;
 * null when the record has no usable id.
 */
async function idPart(
  obj: Record<string, unknown>,
  fields: readonly string[],
): Promise<string | null> {
  for (const field of fields) {
    const value = valueAtPath(obj, field);
    if (typeof value === "string" && value.length > 0) return idToken(value);
    if (typeof value === "number" && Number.isFinite(value)) {
      return idToken(String(value));
    }
  }
  return null;
}

class KeyCollector {
  readonly keys = new Set<string>();
  total = 0;

  async addItems(
    collection: string,
    items: readonly unknown[],
    idFields: readonly string[],
  ): Promise<void> {
    this.total += items.length;
    for (const item of items) {
      if (!isRecord(item)) continue;
      const id = await idPart(item, idFields);
      if (id !== null) this.keys.add(`${collection}:${id}`);
    }
  }

  result(): RecordKeyExtraction {
    return { keys: Array.from(this.keys), total: this.total };
  }
}

/** The dataset name of a scope: everything after its first dot. */
function datasetOf(scope: string): string {
  const dot = scope.indexOf(".");
  return dot < 0 ? scope : scope.slice(dot + 1);
}

function passesStreamFilter(
  row: Record<string, unknown>,
  rule: MemoryRecordRule,
): boolean {
  return (
    !rule.streamFilter ||
    row[rule.streamFilter.field] === rule.streamFilter.equals
  );
}

/** The items of a rule from a legacy body; the first matching array wins. */
function legacyItems(
  data: Record<string, unknown>,
  rule: MemoryRecordRule,
): unknown[] {
  for (const name of [rule.collection, ...(rule.aliases ?? [])]) {
    if (!hasOwn(data, name)) continue;
    const value = data[name];
    if (!Array.isArray(value)) continue;
    return value.filter(isRecord);
  }
  return [];
}

/**
 * Stable keys for the records in an envelope `data` object, plus the number of
 * records counted. Returns null when the data is not trackable (binary).
 *
 * Both stored forms of a scope give the same keys: the PDPP rows form
 * `{ records: [row, ...] }` and the legacy keyed form `{ <collection>: [...] }`.
 * A record is tracked only when it has a usable id; records without one count
 * toward `total` but produce no key.
 */
export async function extractRecordKeys(
  scope: string,
  data: Record<string, unknown>,
): Promise<RecordKeyExtraction | null> {
  if (!isRecord(data)) return null;
  // A binary payload has no addressable records and is never tracked.
  if (hasOwn(data, "$binary")) return null;

  const collector = new KeyCollector();
  const rules = memoryRecordRulesFor(scope);
  const rows = isRowsBody(data) ? data.records : null;

  if (rules !== null) {
    if (rows !== null) {
      // The rows ARE the items of the rule named by the dataset, or of the
      // scope's only rule.
      const dataset = datasetOf(scope);
      const named = rules.filter(
        (rule) =>
          rule.collection === dataset || (rule.aliases ?? []).includes(dataset),
      );
      const chosen = named.length > 0 ? named : rules.length === 1 ? rules : [];
      if (chosen.length === 0 && rules.length > 0) {
        // Several collections and no way to tell which the rows belong to:
        // count them, track none.
        collector.total += rows.length;
      }
      for (const rule of chosen) {
        const items = rows
          .filter(isRecord)
          .filter((row) => passesStreamFilter(row, rule));
        await collector.addItems(rule.collection, items, rule.idFields);
      }
    } else {
      for (const rule of rules) {
        await collector.addItems(
          rule.collection,
          legacyItems(data, rule),
          rule.idFields,
        );
      }
    }
    return collector.result();
  }

  // Generic scope.
  if (rows !== null) {
    await collector.addItems(datasetOf(scope), rows, ID_PROPERTIES);
    return collector.result();
  }
  let sawArray = false;
  for (const key of Object.keys(data)) {
    if (key.startsWith("$")) continue;
    const value = data[key];
    if (!Array.isArray(value)) continue;
    sawArray = true;
    await collector.addItems(key, value, ID_PROPERTIES);
  }
  // No arrays at all: the scope itself is the single record (a profile).
  if (!sawArray) collector.total = 1;
  return collector.result();
}

// ---------------------------------------------------------------------------
// Fold
// ---------------------------------------------------------------------------

type Pair = [string, string];

interface Work {
  scope: string;
  baseline: string;
  baselineMs: number;
  latest: ScopeFirstSeenLedger["latest"];
  latestMs: number;
  records: Map<string, Pair>;
}

function openWork(ledger: ScopeFirstSeenLedger): Work {
  return {
    scope: ledger.scope,
    baseline: ledger.baseline,
    baselineMs: Date.parse(ledger.baseline),
    latest: { ...ledger.latest },
    latestMs: Date.parse(ledger.latest.collectedAt),
    // A Map keeps arbitrary keys (including "__proto__") out of the prototype
    // chain; Object.fromEntries defines each one as an own property again.
    records: new Map(
      Object.entries(ledger.records).map(([key, pair]) => [
        key,
        [pair[0], pair[1]] as Pair,
      ]),
    ),
  };
}

function closeWork(work: Work): ScopeFirstSeenLedger {
  return {
    version: 2,
    scope: work.scope,
    baseline: work.baseline,
    latest: work.latest,
    records: Object.fromEntries(work.records),
  };
}

async function applyVersion(
  work: Work | null,
  version: VersionToFold,
): Promise<Work | null> {
  const at = Date.parse(version.collectedAt);
  if (Number.isNaN(at)) return work;
  if (work !== null && work.scope !== version.scope) return work;

  const extraction = await extractRecordKeys(version.scope, version.data);
  const total = extraction?.total ?? 0;
  const skipped: LedgerSkipReason | undefined =
    extraction !== null && extraction.keys.length > MAX_TRACKED_KEYS
      ? "too_many_keys"
      : undefined;
  const keys = extraction !== null && !skipped ? extraction.keys : [];
  const latest = {
    collectedAt: version.collectedAt,
    total,
    ...(skipped ? { skipped } : {}),
  };

  let next = work;
  if (next === null) {
    next = {
      scope: version.scope,
      baseline: version.collectedAt,
      baselineMs: at,
      latest,
      latestMs: at,
      records: new Map(),
    };
  } else {
    if (at < next.baselineMs) {
      next.baseline = version.collectedAt;
      next.baselineMs = at;
    }
    // On a tie the version folded last describes the slot (a rewrite of the
    // same collectedAt replaces its predecessor).
    if (at >= next.latestMs) {
      next.latest = latest;
      next.latestMs = at;
    }
  }

  for (const key of keys) {
    const existing = next.records.get(key);
    if (!existing) {
      next.records.set(key, [version.collectedAt, version.collectedAt]);
      continue;
    }
    if (at < Date.parse(existing[0])) existing[0] = version.collectedAt;
    if (at > Date.parse(existing[1])) existing[1] = version.collectedAt;
  }
  return next;
}

/** Drop records that are not present and were last seen over 90 days before `latest`. */
function prune(work: Work): void {
  const cutoff = work.latestMs - PRUNE_AFTER_MS;
  for (const [key, pair] of work.records) {
    const lastMs = Date.parse(pair[1]);
    if (lastMs !== work.latestMs && lastMs < cutoff) work.records.delete(key);
  }
}

/**
 * Fold several stored versions into a ledger in one pass. Equivalent to
 * calling `foldVersion` for each, but copies the ledger and prunes once.
 * Returns null only when no version had a parseable `collectedAt` and there
 * was no starting ledger.
 */
export async function foldVersions(
  ledger: ScopeFirstSeenLedger | null,
  versions: readonly VersionToFold[],
): Promise<ScopeFirstSeenLedger | null> {
  let work = ledger ? openWork(ledger) : null;
  for (const version of versions) {
    work = await applyVersion(work, version);
  }
  if (work === null) return null;
  prune(work);
  return closeWork(work);
}

/**
 * Fold one stored version into a ledger (or start one). Order independent
 * and idempotent. A version whose `collectedAt` does not parse is ignored.
 */
export function foldVersion(
  ledger: ScopeFirstSeenLedger | null,
  version: VersionToFold,
): Promise<ScopeFirstSeenLedger | null> {
  return foldVersions(ledger, [version]);
}

/** True when the record was in the newest version folded in. */
export function isPresent(ledger: ScopeFirstSeenLedger, key: string): boolean {
  if (!hasOwn(ledger.records, key)) return false;
  return (
    Date.parse(ledger.records[key]![1]) ===
    Date.parse(ledger.latest.collectedAt)
  );
}

/** True when the record was first seen at or before the baseline version. */
export function isPreTracking(
  ledger: ScopeFirstSeenLedger,
  key: string,
): boolean {
  if (!hasOwn(ledger.records, key)) return false;
  return Date.parse(ledger.records[key]![0]) <= Date.parse(ledger.baseline);
}

/**
 * First-seen timestamps of the records that count as additions: present in
 * the newest version and first seen after the baseline. One per record.
 */
export function listAddedTimestamps(ledger: ScopeFirstSeenLedger): string[] {
  const baselineMs = Date.parse(ledger.baseline);
  const latestMs = Date.parse(ledger.latest.collectedAt);
  const added: string[] = [];
  for (const [first, last] of Object.values(ledger.records)) {
    if (Date.parse(last) !== latestMs) continue;
    if (Date.parse(first) <= baselineMs) continue;
    added.push(first);
  }
  return added;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function parseableString(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

/**
 * The ledger in `value`, or null unless it is a well-formed version-2
 * document. Never throws. The result is a fresh object.
 */
export function readScopeFirstSeenLedger(
  value: unknown,
): ScopeFirstSeenLedger | null {
  try {
    if (!isRecord(value) || value.version !== 2) return null;
    const { scope, baseline, latest, records } = value;
    if (typeof scope !== "string" || scope.length === 0) return null;
    if (!parseableString(baseline)) return null;
    if (!isRecord(latest) || !parseableString(latest.collectedAt)) return null;
    const total = latest.total;
    if (typeof total !== "number" || !Number.isInteger(total) || total < 0) {
      return null;
    }
    const skipped = latest.skipped;
    if (skipped !== undefined && skipped !== "too_many_keys") return null;
    if (!isRecord(records)) return null;

    const entries = Object.entries(records);
    if (entries.length > MAX_TRACKED_KEYS) return null;
    const copied = new Map<string, Pair>();
    for (const [key, pair] of entries) {
      if (!Array.isArray(pair) || pair.length !== 2) return null;
      if (!parseableString(pair[0]) || !parseableString(pair[1])) return null;
      copied.set(key, [pair[0], pair[1]]);
    }
    return {
      version: 2,
      scope,
      baseline,
      latest: {
        collectedAt: latest.collectedAt,
        total,
        ...(skipped ? { skipped } : {}),
      },
      records: Object.fromEntries(copied),
    };
  } catch {
    return null;
  }
}
