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

/**
 * At most this many tracked keys per scope, in one snapshot AND in the ledger
 * (the union over time). Beyond it the ledger enters a terminal skipped state.
 */
export const MAX_TRACKED_KEYS = 200_000;
/** Ids longer than this are replaced by a hash so keys stay bounded. */
export const MAX_ID_LENGTH = 64;
/** Collection names longer than this are replaced by a hash (they can be caller-controlled). */
export const MAX_COLLECTION_LENGTH = 64;
/** A record absent from the newest tracked version is dropped after this long. */
export const PRUNE_AFTER_MS = 90 * 24 * 60 * 60 * 1000;
/** Items processed between two yields to the event loop. */
export const YIELD_EVERY = 2_000;

/** Run the rest of an async loop in a later macrotask so other requests are served. */
export function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Why a ledger holds no per-record keys:
 *  - `too_many_keys`: the scope has more tracked records than `MAX_TRACKED_KEYS`
 *    (one snapshot or the union over time). Terminal: later folds keep only
 *    `latest` current and never accumulate keys again. It ends only when the
 *    sidecar is deleted (scope deleted, or its newest version removed).
 *  - `too_large`, `unreadable`: a rebuild could not read any version within
 *    its byte budget, or none could be read. A negative result persisted so
 *    it is not retried on every request; a newer retained version retries.
 */
export type LedgerSkipReason = "too_many_keys" | "too_large" | "unreadable";

/** One document per scope, stored as a sidecar beside the data. */
export interface ScopeFirstSeenLedger {
  version: 2;
  scope: string;
  /**
   * collectedAt of the EARLIEST TRACKABLE version folded in (one with records
   * that have ids, or an empty one): records first seen then predate tracking.
   * Null until a trackable version exists, so a binary, over-cap or
   * id-less first snapshot never makes everything after it look added.
   */
  baseline: string | null;
  /** collectedAt of the NEWEST trackable version: a record is present iff last seen then. */
  current: string | null;
  /** collectedAt of the NEWEST version of any kind, and its record total (a binary file counts 1). */
  latest: { collectedAt: string; total: number };
  /** Set when no per-record keys are kept (see `LedgerSkipReason`); `records` is then empty. */
  skipped?: LedgerSkipReason;
  /**
   * The ledger was rebuilt from only the newest retained versions (count or
   * byte budget). A version older than `baseline` then never moves the
   * baseline back over the versions that were not folded.
   */
  partial?: true;
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
  /** De-duplicated keys of the records that have a usable id, in first-seen order. Empty when `tooMany`. */
  keys: string[];
  /** Records in the counted collections, tracked or not. */
  total: number;
  /** More than `MAX_TRACKED_KEYS` tracked keys: extraction stopped collecting them. */
  tooMany?: true;
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

/** `i:<id>`, or `h:<32 hex of SHA-256>` when the id is longer than `MAX_ID_LENGTH`. */
async function idToken(id: string): Promise<string> {
  return id.length > MAX_ID_LENGTH
    ? `h:${(await sha256Hex(id)).slice(0, 32)}`
    : `i:${id}`;
}

/** The collection part of a key, bounded because a generic scope takes it from the caller's data. */
async function collectionToken(name: string): Promise<string> {
  return name.length > MAX_COLLECTION_LENGTH
    ? `h:${(await sha256Hex(name)).slice(0, 32)}`
    : name;
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
  tooMany = false;

  /**
   * Count `items`, and track those with an id. Once the tracked keys pass the
   * cap it stops collecting (and frees them) but still counts, so a hostile
   * body costs a bounded amount of work and memory.
   */
  async addItems(
    collection: string,
    items: readonly unknown[],
    idFields: readonly string[],
  ): Promise<void> {
    this.total += items.length;
    if (this.tooMany || idFields.length === 0) return;
    const prefix = await collectionToken(collection);
    for (let index = 0; index < items.length; index += 1) {
      if (index % YIELD_EVERY === YIELD_EVERY - 1) await yieldToEventLoop();
      const item = items[index];
      if (!isRecord(item)) continue;
      const id = await idPart(item, idFields);
      if (id === null) continue;
      this.keys.add(`${prefix}:${id}`);
      if (this.keys.size > MAX_TRACKED_KEYS) {
        this.tooMany = true;
        this.keys.clear();
        return;
      }
    }
  }

  result(): RecordKeyExtraction {
    return {
      keys: Array.from(this.keys),
      total: this.total,
      ...(this.tooMany ? { tooMany: true as const } : {}),
    };
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
 * `{ records: [row, ...] }` and the legacy keyed form `{ <collection>: [...] }`
 * (a ruled scope names the id field per form, see `record-rules.ts`). A record
 * is tracked only when it has a usable id; records without one count toward
 * `total` but produce no key. Ids and collection names over 64 characters are
 * hashed, so every key is at most about 135 characters.
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
        await collector.addItems(rule.collection, items, rule.rowIdFields);
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

function ms(value: string | null): number {
  return value === null ? Number.NaN : Date.parse(value);
}

/**
 * A version is trackable when its records could be told apart: it has records
 * with ids, or no records at all. A binary file, a snapshot over the cap and
 * a snapshot whose records have no ids are counted but are not a baseline.
 */
function isTrackable(extraction: RecordKeyExtraction | null): boolean {
  return (
    extraction !== null &&
    !extraction.tooMany &&
    (extraction.keys.length > 0 || extraction.total === 0)
  );
}

/**
 * Folds stored versions into one ledger, one at a time, so a caller can read a
 * version, `add` it and drop it before reading the next: only one parsed
 * envelope is ever alive. Order independent and idempotent for versions within
 * the 90-day pruning window of each other (pruning is relative to the newest
 * tracked version, so folding versions further apart in a different order can
 * re-date a record that was already pruned).
 */
export class LedgerFold {
  private scope: string | null;
  private baseline: string | null = null;
  private current: string | null = null;
  private latest: ScopeFirstSeenLedger["latest"] | null = null;
  private skipped: LedgerSkipReason | undefined;
  private partial = false;
  // A Map keeps arbitrary keys (including "__proto__") out of the prototype
  // chain; Object.fromEntries defines each one as an own property again.
  private records = new Map<string, Pair>();

  constructor(ledger: ScopeFirstSeenLedger | null, scope?: string) {
    this.scope = ledger?.scope ?? scope ?? null;
    if (!ledger) return;
    this.baseline = ledger.baseline;
    this.current = ledger.current;
    this.latest = { ...ledger.latest };
    this.skipped = ledger.skipped;
    this.partial = ledger.partial === true;
    // Copied, never shared: the input ledger is not mutated.
    for (const [key, pair] of Object.entries(ledger.records)) {
      this.records.set(key, [pair[0], pair[1]]);
    }
  }

  async add(version: VersionToFold): Promise<void> {
    const at = Date.parse(version.collectedAt);
    if (Number.isNaN(at)) return;
    if (this.scope === null) this.scope = version.scope;
    if (this.scope !== version.scope) return;

    const extraction = await extractRecordKeys(version.scope, version.data);
    // A binary file is one record of the scope (the owner app lists it so).
    const total = extraction?.total ?? 1;

    // On a tie the version folded last describes the slot (a rewrite of the
    // same collectedAt replaces its predecessor).
    if (this.latest === null || at >= ms(this.latest.collectedAt)) {
      this.latest = { collectedAt: version.collectedAt, total };
    }
    if (extraction?.tooMany) this.enterSkipped("too_many_keys");
    if (this.skipped !== undefined) return;
    if (!isTrackable(extraction)) return;

    if (this.baseline === null) {
      this.baseline = version.collectedAt;
    } else if (at < ms(this.baseline) && !this.partial) {
      // A partial ledger never moves its baseline back over versions it did
      // not fold: their records would then look added.
      this.baseline = version.collectedAt;
    }
    if (this.current === null || at >= ms(this.current)) {
      this.current = version.collectedAt;
    }

    const keys = extraction!.keys;
    for (let index = 0; index < keys.length; index += 1) {
      if (index % YIELD_EVERY === YIELD_EVERY - 1) await yieldToEventLoop();
      const key = keys[index]!;
      const existing = this.records.get(key);
      if (!existing) {
        this.records.set(key, [version.collectedAt, version.collectedAt]);
        if (this.records.size > MAX_TRACKED_KEYS) {
          this.enterSkipped("too_many_keys");
          return;
        }
        continue;
      }
      if (at < Date.parse(existing[0])) existing[0] = version.collectedAt;
      if (at > Date.parse(existing[1])) existing[1] = version.collectedAt;
    }
  }

  private enterSkipped(reason: LedgerSkipReason): void {
    this.skipped = reason;
    this.records = new Map();
  }

  /** Drop records that are not present and were last seen over 90 days before `current`. */
  private async prune(): Promise<void> {
    if (this.current === null || this.skipped !== undefined) return;
    const currentMs = ms(this.current);
    const cutoff = currentMs - PRUNE_AFTER_MS;
    let seen = 0;
    for (const [key, pair] of this.records) {
      seen += 1;
      if (seen % (YIELD_EVERY * 5) === 0) await yieldToEventLoop();
      const lastMs = Date.parse(pair[1]);
      if (lastMs !== currentMs && lastMs < cutoff) this.records.delete(key);
    }
  }

  /**
   * Prune and return the ledger, or null when nothing was ever folded.
   * `partial` marks a ledger rebuilt from only the newest retained versions.
   */
  async finish(
    options: { partial?: boolean } = {},
  ): Promise<ScopeFirstSeenLedger | null> {
    if (this.scope === null || this.latest === null) return null;
    await this.prune();
    const partial = this.partial || options.partial === true;
    return {
      version: 2,
      scope: this.scope,
      baseline: this.baseline,
      current: this.current,
      latest: this.latest,
      ...(this.skipped ? { skipped: this.skipped } : {}),
      ...(partial ? { partial: true as const } : {}),
      records: Object.fromEntries(this.records),
    };
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
  const fold = new LedgerFold(ledger);
  for (const version of versions) await fold.add(version);
  return fold.finish();
}

/**
 * Fold one stored version into a ledger (or start one). A version whose
 * `collectedAt` does not parse is ignored.
 */
export function foldVersion(
  ledger: ScopeFirstSeenLedger | null,
  version: VersionToFold,
): Promise<ScopeFirstSeenLedger | null> {
  return foldVersions(ledger, [version]);
}

/** True when the record was in the newest tracked version folded in. */
export function isPresent(ledger: ScopeFirstSeenLedger, key: string): boolean {
  if (ledger.current === null || !hasOwn(ledger.records, key)) return false;
  return Date.parse(ledger.records[key]![1]) === Date.parse(ledger.current);
}

/** True when the record was first seen at or before the baseline (or there is no baseline). */
export function isPreTracking(
  ledger: ScopeFirstSeenLedger,
  key: string,
): boolean {
  if (ledger.baseline === null) return true;
  if (!hasOwn(ledger.records, key)) return false;
  return Date.parse(ledger.records[key]![0]) <= Date.parse(ledger.baseline);
}

/**
 * First-seen timestamps of the records that count as additions: present in
 * the newest tracked version and first seen after the baseline. One per
 * record. A skipped ledger, or one with no baseline yet, dates nothing.
 */
export function listAddedTimestamps(ledger: ScopeFirstSeenLedger): string[] {
  if (
    ledger.skipped !== undefined ||
    ledger.baseline === null ||
    ledger.current === null
  ) {
    return [];
  }
  const baselineMs = Date.parse(ledger.baseline);
  const currentMs = Date.parse(ledger.current);
  const added: string[] = [];
  for (const [first, last] of Object.values(ledger.records)) {
    if (Date.parse(last) !== currentMs) continue;
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

function nullableParseable(value: unknown): value is string | null {
  return value === null || parseableString(value);
}

const SKIP_REASONS: ReadonlySet<unknown> = new Set([
  "too_many_keys",
  "too_large",
  "unreadable",
]);

/**
 * The ledger in `value`, or null unless it is a well-formed version-2
 * document. Never throws. The result is a fresh object.
 */
export function readScopeFirstSeenLedger(
  value: unknown,
): ScopeFirstSeenLedger | null {
  try {
    if (!isRecord(value) || value.version !== 2) return null;
    const { scope, baseline, current, latest, records, skipped, partial } =
      value;
    if (typeof scope !== "string" || scope.length === 0) return null;
    if (!nullableParseable(baseline) || !nullableParseable(current)) {
      return null;
    }
    if (!isRecord(latest) || !parseableString(latest.collectedAt)) return null;
    const total = latest.total;
    if (typeof total !== "number" || !Number.isInteger(total) || total < 0) {
      return null;
    }
    if (skipped !== undefined && !SKIP_REASONS.has(skipped)) return null;
    if (partial !== undefined && partial !== true) return null;
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
      current,
      latest: { collectedAt: latest.collectedAt, total },
      ...(skipped ? { skipped: skipped as LedgerSkipReason } : {}),
      ...(partial ? { partial: true as const } : {}),
      records: Object.fromEntries(copied),
    };
  } catch {
    return null;
  }
}
