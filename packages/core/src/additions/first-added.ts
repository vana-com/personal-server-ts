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
 * At most this many tracked keys per scope snapshot AND in the ledger (the
 * union over time). A snapshot over it is untrackable; when the union passes
 * it, keys absent from the newest tracked version are dropped, oldest first.
 */
export const MAX_TRACKED_KEYS = 200_000;
/** Ids longer than this are replaced by a hash so keys stay bounded. */
export const MAX_ID_LENGTH = 64;
/** Collection names longer than this are replaced by a hash (they can be caller-controlled). */
export const MAX_COLLECTION_LENGTH = 64;
/** A record absent from the newest tracked version is dropped after this long. */
export const PRUNE_AFTER_MS = 90 * 24 * 60 * 60 * 1000;
/** An unreadable version is read again at most this often. */
export const RETRY_UNREADABLE_MS = 60 * 60 * 1000;
/** At most this many unreadable versions are remembered for retry. */
export const MAX_RETRY_VERSIONS = 20;
/** Items processed between two yields to the event loop. */
export const YIELD_EVERY = 2_000;

/** Run the rest of an async loop in a later macrotask so other requests are served. */
export function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Why a ledger holds no per-record keys: a rebuild could not read any version
 * within its byte budget (`too_large`), or none could be read (`unreadable`).
 * A negative result persisted so it is not retried on every request; a newer
 * retained version retries it. (A snapshot over the key cap is not a state of
 * the ledger: that one version is simply untrackable, see `isTrackable`.)
 */
export type LedgerSkipReason = "too_large" | "unreadable";

/** One document per scope, stored as a sidecar beside the data. */
export interface ScopeFirstSeenLedger {
  version: 4;
  scope: string;
  /**
   * collectedAt of the EARLIEST TRACKABLE version folded in (one with records
   * that have ids, or an empty one). Its records count as added on its date
   * only when the baseline is the scope's oldest retained version AND that
   * version is the scope's first (see `partial`); otherwise their real date is
   * unknown. Null until a trackable version exists, so a binary, over-cap or
   * id-less first snapshot never becomes the baseline.
   */
  baseline: string | null;
  /** collectedAt of the NEWEST trackable version: a record is present iff last seen then. */
  current: string | null;
  /** collectedAt of the NEWEST version of any kind, and its record total (a binary file counts 1). */
  latest: { collectedAt: string; total: number };
  /**
   * The ledger is known complete up to this collectedAt: every retained
   * version at or before it has been folded. A write that folds only itself
   * advances it only when no other version is newer than it, so the owner's
   * `/additions` read knows what to catch up on.
   */
  through: string;
  /**
   * Versions that could not be read when they were folded, and when the last
   * attempt was made. They are retried at most once per `RETRY_UNREADABLE_MS`
   * and meanwhile the ledger is served as it is (the numbers of the newest
   * readable version) without reading anything. `through` has already moved
   * past them, so a poll with nothing new reads nothing.
   */
  retry?: { versions: string[]; attemptedAt: string };
  /** Set when no per-record keys are kept (see `LedgerSkipReason`); `records` is then empty. */
  skipped?: LedgerSkipReason;
  /**
   * The rebuild or catch-up folded only the newest retained versions (the
   * count window or the byte budget cut off older ones). A version older than
   * `baseline` then never moves the baseline back over versions that were not
   * folded. Persisted.
   */
  truncated?: true;
  /**
   * DERIVED, never persisted: set by `ensureScopeLedger` on the ledger it
   * returns when the baseline is not known to be the scope's first version.
   * The owner's read decides it from the index (the oldest retained version,
   * its number, whether it follows a deletion) plus `truncated`, so it follows
   * later changes of version numbers and deletions. Records first seen at the
   * baseline then keep an unknown date and are not counted as added.
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

/**
 * The id part of a key, unambiguous by its tag: `i:<id>` for a string,
 * `n:<number>` for a number (so 1 and "1" differ) and `h:<32 hex of SHA-256>`
 * for a string longer than `MAX_ID_LENGTH`. It is the last part of the key, so
 * it needs no escaping.
 */
async function idToken(id: string | number): Promise<string> {
  if (typeof id === "number") return `n:${String(id)}`;
  return id.length > MAX_ID_LENGTH
    ? `h:${(await sha256Hex(id)).slice(0, 32)}`
    : `i:${id}`;
}

/**
 * The collection part of a key: the name with `\`, `:` and `#` escaped, or
 * `#<32 hex of SHA-256>` when it is longer than `MAX_COLLECTION_LENGTH` (it
 * can come from the caller's data). The escaping keeps the first unescaped
 * `:` the only separator, and a literal name can never equal a hashed one.
 */
async function collectionToken(name: string): Promise<string> {
  if (name.length > MAX_COLLECTION_LENGTH) {
    return `#${(await sha256Hex(name)).slice(0, 32)}`;
  }
  return name.replace(/[\\:#]/g, (character) => `\\${character}`);
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
      return idToken(value);
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
 * hashed, so every key is at most about 200 characters.
 */
export async function extractRecordKeys(
  scope: string,
  data: Record<string, unknown>,
): Promise<RecordKeyExtraction | null> {
  if (!isRecord(data)) return null;
  const rules = memoryRecordRulesFor(scope);
  // A scope whose rules hold nothing counts 0, whatever it stores (a rebuild
  // reads nothing there, so a write must count the same).
  if (rules !== null && rules.length === 0) return { keys: [], total: 0 };
  // A binary payload has no addressable records and is never tracked.
  if (hasOwn(data, "$binary")) return null;

  const collector = new KeyCollector();
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
        if (rule.singleton) {
          collector.total += rows.filter(isRecord).length;
          continue;
        }
        const items = rows
          .filter(isRecord)
          .filter((row) => passesStreamFilter(row, rule));
        await collector.addItems(rule.collection, items, rule.rowIdFields);
      }
    } else {
      for (const rule of rules) {
        if (rule.singleton) {
          // The body is the record: counted once when it has any content.
          if (Object.keys(data).some((key) => !key.startsWith("$"))) {
            collector.total += 1;
          }
          continue;
        }
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
 * Whether `a` is the newer of two collectedAt strings. Instants decide
 * ("…00Z" and "…00.000Z" are the same instant); a tie is broken by the
 * greater string, so the outcome never depends on the order of folding. Equal
 * strings (a rewrite of the same slot) count as newer, so the last one wins.
 */
function isNewer(a: string, b: string | null): boolean {
  if (b === null) return true;
  const difference = Date.parse(a) - Date.parse(b);
  return difference > 0 || (difference === 0 && a >= b);
}

/** Whether `a` is strictly earlier than `b` (instant first, then the smaller string). */
function isEarlier(a: string, b: string): boolean {
  const difference = Date.parse(a) - Date.parse(b);
  return difference < 0 || (difference === 0 && a < b);
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
  private through: string | null = null;
  private retry: ScopeFirstSeenLedger["retry"];
  private skipped: LedgerSkipReason | undefined;
  private truncated = false;
  // A Map keeps arbitrary keys (including "__proto__") out of the prototype
  // chain; Object.fromEntries defines each one as an own property again.
  private records = new Map<string, Pair>();

  constructor(ledger: ScopeFirstSeenLedger | null, scope?: string) {
    this.scope = ledger?.scope ?? scope ?? null;
    if (!ledger) return;
    this.baseline = ledger.baseline;
    this.current = ledger.current;
    this.latest = { ...ledger.latest };
    this.through = ledger.through;
    this.retry = ledger.retry
      ? {
          versions: [...ledger.retry.versions],
          attemptedAt: ledger.retry.attemptedAt,
        }
      : undefined;
    this.skipped = ledger.skipped;
    this.truncated = ledger.truncated === true;
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

    if (
      this.latest === null ||
      isNewer(version.collectedAt, this.latest.collectedAt)
    ) {
      this.latest = { collectedAt: version.collectedAt, total };
    }
    if (isNewer(version.collectedAt, this.through)) {
      this.through = version.collectedAt;
    }
    // A negative-outcome marker keeps no keys; a binary file or a snapshot
    // over the key cap is counted above but contributes none.
    if (this.skipped !== undefined) return;
    if (!isTrackable(extraction)) return;

    if (this.baseline === null) {
      this.baseline = version.collectedAt;
    } else if (
      isEarlier(version.collectedAt, this.baseline) &&
      !this.truncated
    ) {
      // A truncated ledger never moves its baseline back over versions it did
      // not fold: their records would then look added.
      this.baseline = version.collectedAt;
    }
    if (isNewer(version.collectedAt, this.current)) {
      this.current = version.collectedAt;
    }

    const keys = extraction!.keys;
    const fresh: string[] = [];
    // First pass: records the ledger already knows move their first/last seen.
    for (let index = 0; index < keys.length; index += 1) {
      if (index % YIELD_EVERY === YIELD_EVERY - 1) await yieldToEventLoop();
      const key = keys[index]!;
      const existing = this.records.get(key);
      if (!existing) {
        fresh.push(key);
        continue;
      }
      if (isEarlier(version.collectedAt, existing[0])) {
        existing[0] = version.collectedAt;
      }
      if (isNewer(version.collectedAt, existing[1])) {
        existing[1] = version.collectedAt;
      }
    }
    if (fresh.length > 0)
      await this.insertFresh(fresh, keys, version.collectedAt);
  }

  /**
   * Insert the records this version brings that the ledger does not know.
   * Capacity is decided ONCE: when they do not fit, absent records are evicted
   * in a single pass (see `evict`), and whatever still does not fit is left
   * out, smallest keys first, so the result never depends on the order of the
   * ids in the version.
   */
  private async insertFresh(
    fresh: string[],
    versionKeys: readonly string[],
    collectedAt: string,
  ): Promise<void> {
    fresh.sort();
    let room = MAX_TRACKED_KEYS - this.records.size;
    if (fresh.length > room) {
      room += await this.evict(fresh.length - room, new Set(versionKeys));
    }
    const take = Math.min(fresh.length, Math.max(0, room));
    for (let index = 0; index < take; index += 1) {
      if (index % YIELD_EVERY === YIELD_EVERY - 1) await yieldToEventLoop();
      this.records.set(fresh[index]!, [collectedAt, collectedAt]);
    }
  }

  /**
   * Make room for `need` records by dropping some that are absent: not in the
   * newest tracked version, not in the version being folded, and not
   * baseline records (first seen at or before the baseline). Baseline records
   * are never dropped. Other absent records CAN be dropped (and are
   * dated as new if they return): that needs a scope near the cap, and
   * whoever can write the scope can provoke it. Among the evictable ones the
   * most recently first seen go first. Returns how many were dropped.
   */
  private async evict(
    need: number,
    inVersion: ReadonlySet<string>,
  ): Promise<number> {
    const currentMs = ms(this.current);
    const baselineMs = ms(this.baseline);
    const candidates: [number, string][] = [];
    let seen = 0;
    for (const [key, pair] of this.records) {
      seen += 1;
      if (seen % (YIELD_EVERY * 5) === 0) await yieldToEventLoop();
      if (inVersion.has(key)) continue;
      if (Date.parse(pair[1]) === currentMs) continue;
      const firstMs = Date.parse(pair[0]);
      if (firstMs <= baselineMs) continue;
      candidates.push([firstMs, key]);
    }
    candidates.sort(
      (a, b) => b[0] - a[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0),
    );
    const count = Math.min(need, candidates.length);
    for (let index = 0; index < count; index += 1) {
      this.records.delete(candidates[index]![1]);
    }
    return count;
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
   * `truncated` marks a ledger rebuilt from only the newest retained versions;
   * `through` overrides the completeness marker (see `ScopeFirstSeenLedger`).
   */
  async finish(
    options: {
      truncated?: boolean;
      through?: string;
      /** `null` clears the retry list; undefined keeps it. */
      retry?: ScopeFirstSeenLedger["retry"] | null;
    } = {},
  ): Promise<ScopeFirstSeenLedger | null> {
    if (this.scope === null || this.latest === null) return null;
    await this.prune();
    const truncated = this.truncated || options.truncated === true;
    const retry = options.retry === undefined ? this.retry : options.retry;
    return {
      version: 4,
      scope: this.scope,
      baseline: this.baseline,
      current: this.current,
      latest: this.latest,
      through: options.through ?? this.through ?? this.latest.collectedAt,
      ...(retry ? { retry } : {}),
      ...(this.skipped ? { skipped: this.skipped } : {}),
      ...(truncated ? { truncated: true as const } : {}),
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

/**
 * True when the record's first-seen date is unknown: there is no baseline, or
 * the ledger is partial and the record was first seen at or before the
 * baseline. In a complete ledger the baseline's records are dated by it.
 */
export function isPreTracking(
  ledger: ScopeFirstSeenLedger,
  key: string,
): boolean {
  if (ledger.baseline === null) return true;
  if (ledger.partial !== true || !hasOwn(ledger.records, key)) return false;
  return Date.parse(ledger.records[key]![0]) <= Date.parse(ledger.baseline);
}

/**
 * First-seen timestamps of the records that count as additions: present in
 * the newest tracked version. Records first seen at the baseline count too
 * (they entered the server then) unless the ledger is `partial`, where their
 * date is unknown. One per record. A skipped ledger, one with no baseline yet, and a scope whose newest
 * version is not its newest tracked one (a binary file or an over-cap
 * snapshot, whose `latest.total` does not describe those records) report none,
 * so `added` can never exceed `total`.
 */
export function listAddedTimestamps(ledger: ScopeFirstSeenLedger): string[] {
  if (
    ledger.skipped !== undefined ||
    ledger.baseline === null ||
    ledger.current === null ||
    Date.parse(ledger.current) !== Date.parse(ledger.latest.collectedAt)
  ) {
    return [];
  }
  const baselineMs = Date.parse(ledger.baseline);
  const currentMs = Date.parse(ledger.current);
  const added: string[] = [];
  for (const [first, last] of Object.values(ledger.records)) {
    if (Date.parse(last) !== currentMs) continue;
    if (ledger.partial === true && Date.parse(first) <= baselineMs) continue;
    added.push(first);
  }
  // Two versions at one instant can both look present; never report more
  // additions than the newest version has records.
  if (added.length > ledger.latest.total) {
    added.sort();
    added.length = ledger.latest.total;
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

const SKIP_REASONS: ReadonlySet<unknown> = new Set(["too_large", "unreadable"]);

/**
 * The ledger in `value`, or null unless it is a well-formed version-2
 * document (older versions are rejected and rebuilt). Never throws. The result is a fresh object.
 */
export function readScopeFirstSeenLedger(
  value: unknown,
): ScopeFirstSeenLedger | null {
  try {
    if (!isRecord(value) || value.version !== 4) return null;
    const {
      scope,
      baseline,
      current,
      latest,
      through,
      records,
      skipped,
      truncated,
    } = value;
    if (typeof scope !== "string" || scope.length === 0) return null;
    if (!nullableParseable(baseline) || !nullableParseable(current)) {
      return null;
    }
    if (!isRecord(latest) || !parseableString(latest.collectedAt)) return null;
    if (!parseableString(through)) return null;
    let retryValue: ScopeFirstSeenLedger["retry"];
    if (value.retry !== undefined) {
      const retry = value.retry;
      if (
        !isRecord(retry) ||
        !Array.isArray(retry.versions) ||
        retry.versions.length === 0 ||
        retry.versions.length > MAX_RETRY_VERSIONS ||
        !retry.versions.every(parseableString) ||
        !parseableString(retry.attemptedAt)
      ) {
        return null;
      }
      retryValue = {
        versions: [...(retry.versions as string[])],
        attemptedAt: retry.attemptedAt,
      };
    }
    // Completeness cannot run ahead of the newest version the ledger knows
    // (folded, or remembered as unreadable): such a marker would suppress the
    // catch-up it exists to trigger.
    const newestKnown = Math.max(
      Date.parse(latest.collectedAt),
      ...(retryValue?.versions.map((version) => Date.parse(version)) ?? []),
    );
    if (Date.parse(through) > newestKnown) return null;
    const total = latest.total;
    if (typeof total !== "number" || !Number.isInteger(total) || total < 0) {
      return null;
    }
    if (skipped !== undefined && !SKIP_REASONS.has(skipped)) return null;
    if (truncated !== undefined && truncated !== true) return null;
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
      version: 4,
      scope,
      baseline,
      current,
      latest: { collectedAt: latest.collectedAt, total },
      through,
      ...(retryValue ? { retry: retryValue } : {}),
      ...(skipped ? { skipped: skipped as LedgerSkipReason } : {}),
      ...(truncated ? { truncated: true as const } : {}),
      records: Object.fromEntries(copied),
    };
  } catch {
    return null;
  }
}
