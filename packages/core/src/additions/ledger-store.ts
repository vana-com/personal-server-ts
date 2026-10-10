/**
 * Keeps a scope's first-seen sidecar current. See `first-added.ts` for the
 * ledger itself; this module is the only code that reads and writes it.
 *
 * The sidecar is a cache derived from the scope's stored versions, so every
 * failure here is survivable: a missing or unreadable sidecar is rebuilt from
 * the retained versions the next time the owner asks for it.
 *
 * Cost rules:
 *  - The WRITE path (`recordStoredVersion`: JSON ingest, binary ingest, sync
 *    download) never reads a stored envelope. It folds ONLY the version
 *    already in memory: into an existing sidecar, or into a new one when it
 *    is the scope's only version; otherwise it leaves the sidecar absent.
 *    Whatever it did not cover stays visible to the owner's read: the
 *    ledger's `through` marker only advances over versions that were folded.
 *  - The owner's `/additions` read (`ensureScopeLedger`) does all the
 *    catching up and rebuilding. It folds ONE version at a time, at most the
 *    newest `REBUILD_VERSION_LIMIT` versions and `REBUILD_BYTE_BUDGET` bytes
 *    of envelopes (index `sizeBytes`), oldest folded first, yielding to the
 *    event loop between versions. A scope whose rules track nothing is not
 *    read at all.
 *  - Negative outcomes (too large, nothing readable) are persisted as a ledger
 *    with a `skipped` reason, so they are not retried on every request. A
 *    single unreadable version is remembered in the ledger's `retry` list and
 *    read again at most once per hour; in between nothing is read.
 *
 * Guarantee, in order of strength:
 *  1. Updates and deletions of one scope are serialized inside this process
 *     (`withScopeLock`), and after a write the sidecar is removed again if the
 *     scope has no versions left, so a delete racing a rebuild leaves nothing.
 *  2. Across processes sharing one data directory a fold can still be lost.
 *     A lost version newer than the sidecar's `through` marker is repaired by
 *     the next `/additions` read.
 *  3. A lost version at or before `through` is repaired only by a rebuild
 *     (delete the sidecar, or reimport).
 *  4. A sidecar whose `latest` version no longer exists (it was deleted) is
 *     discarded and rebuilt.
 */

import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/types.js";
import {
  LedgerFold,
  MAX_RETRY_VERSIONS,
  RETRY_UNREADABLE_MS,
  readScopeFirstSeenLedger,
  yieldToEventLoop,
  type ScopeFirstSeenLedger,
  type VersionToFold,
} from "./first-added.js";
import { memoryRecordRulesFor } from "./record-rules.js";
import { withScopeLock } from "./scope-lock.js";

/** Index rows read from the oldest end to find the scope's oldest version(s). */
const OLDEST_PAGE = 20;
/** Most recent retained versions considered when a sidecar is rebuilt or caught up. */
export const REBUILD_VERSION_LIMIT = 200;
/** Envelope bytes (from the index) read for one scope in one rebuild or catch-up. */
export const REBUILD_BYTE_BUDGET = 256 * 1024 * 1024;

export interface LedgerStoreOptions {
  /** Override `REBUILD_BYTE_BUDGET`. */
  byteBudget?: number;
  /**
   * The caller's clock, used to space the retries of unreadable versions.
   * Defaults to the current time.
   */
  now?: Date;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A scope whose rules track nothing: no envelope has to be read to fold it. */
function readsNothing(scope: string): boolean {
  return memoryRecordRulesFor(scope)?.length === 0;
}

/** The envelope data as stored (never the read-time view), or null if unreadable. */
async function readVersionData(
  storage: DataStoragePort,
  scope: string,
  collectedAt: string,
): Promise<VersionToFold | null> {
  if (readsNothing(scope)) return { scope, collectedAt, data: {} };
  try {
    // Called as methods of `storage`, never detached, to keep `this` bound.
    const envelope = storage.readStoredEnvelope
      ? await storage.readStoredEnvelope(scope, collectedAt)
      : await storage.readEnvelope(scope, collectedAt);
    if (!isRecord(envelope.data)) return null;
    return { scope, collectedAt, data: envelope.data };
  } catch {
    return null;
  }
}

/** Retained versions, newest first by instant. */
function retainedVersions(
  storage: DataStoragePort,
  scope: string,
): IndexEntry[] {
  return storage
    .listVersions(scope, { limit: REBUILD_VERSION_LIMIT })
    .filter((entry) => !Number.isNaN(Date.parse(entry.collectedAt)))
    .sort(
      (a, b) =>
        Date.parse(b.collectedAt) - Date.parse(a.collectedAt) ||
        (a.collectedAt < b.collectedAt
          ? 1
          : a.collectedAt > b.collectedAt
            ? -1
            : 0),
    );
}

/**
 * The newest prefix of `entries` (newest first) whose index sizes fit the
 * budget. A scope that reads nothing is never limited.
 */
function withinBudget(
  scope: string,
  entries: readonly IndexEntry[],
  budget: number,
): IndexEntry[] {
  if (readsNothing(scope)) return [...entries];
  const selected: IndexEntry[] = [];
  let used = 0;
  for (const entry of entries) {
    used += Math.max(0, entry.sizeBytes ?? 0);
    if (used > budget) break;
    selected.push(entry);
  }
  return selected;
}

async function readStoredLedger(
  storage: DataStoragePort,
  scope: string,
): Promise<ScopeFirstSeenLedger | null> {
  if (!storage.readFirstSeenLedger) return null;
  try {
    const ledger = readScopeFirstSeenLedger(
      await storage.readFirstSeenLedger(scope),
    );
    return ledger !== null && ledger.scope === scope ? ledger : null;
  } catch {
    // An unreadable sidecar is rebuilt, never trusted and never fatal.
    return null;
  }
}

/** Remove the sidecar of a scope that no longer has any version. */
async function dropIfScopeEmpty(
  storage: DataStoragePort,
  scope: string,
): Promise<boolean> {
  if (storage.findEntry({ scope })) return false;
  await storage.deleteFirstSeenLedger?.(scope);
  return true;
}

/** Whether the version the ledger calls its `latest` is still stored (a direct lookup, not a window). */
function latestStillStored(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
): boolean {
  return (
    storage.findEntry({ scope: ledger.scope, at: ledger.latest.collectedAt })
      ?.collectedAt === ledger.latest.collectedAt
  );
}

/**
 * Whether the baseline version still exists. A ledger whose baseline version
 * was deleted still holds that version's ids and dates; it is rebuilt, as a
 * rebuild would give.
 */
function baselineStillStored(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
): boolean {
  if (ledger.baseline === null) return true;
  return (
    storage.findEntry({ scope: ledger.scope, at: ledger.baseline })
      ?.collectedAt === ledger.baseline
  );
}

function isMarker(ledger: ScopeFirstSeenLedger): boolean {
  return ledger.skipped === "too_large" || ledger.skipped === "unreadable";
}

function newerThan(
  retained: readonly IndexEntry[],
  ledger: ScopeFirstSeenLedger,
): IndexEntry[] {
  const throughMs = Date.parse(ledger.through);
  return retained.filter((entry) => Date.parse(entry.collectedAt) > throughMs);
}

/**
 * Fold `entries` (newest first) into `fold`, oldest first, one envelope at a
 * time. Returns how many were folded and the entries that could not be read.
 */
async function foldEntries(
  storage: DataStoragePort,
  scope: string,
  entries: readonly IndexEntry[],
  fold: LedgerFold,
): Promise<{ folded: number; failed: IndexEntry[] }> {
  let folded = 0;
  const failed: IndexEntry[] = [];
  for (const entry of [...entries].reverse()) {
    const version = await readVersionData(storage, scope, entry.collectedAt);
    if (version) {
      await fold.add(version);
      folded += 1;
    } else {
      failed.push(entry);
    }
    await yieldToEventLoop();
  }
  return { folded, failed };
}

/**
 * Whether the scope's OLDEST retained version (by collectedAt) looks like its
 * first. Version numbers count a scope's versions from 1, so a higher number
 * means older versions existed and are gone (deleted, superseded, or never
 * downloaded here, which is what a second device or a reinstall gets): its
 * records did not arrive then. A version written after a deletion
 * (`afterTombstoneVersion`) starts afresh. Among versions at the oldest
 * instant the lowest number decides.
 */
function oldestStartsAtFirst(oldestInstant: IndexEntry[]): boolean {
  const lowest = oldestInstant.reduce((a, b) =>
    b.version < a.version ? b : a,
  );
  return lowest.version <= 1 || (lowest.afterTombstoneVersion ?? null) !== null;
}

/**
 * Decide, from the index alone (no envelope is read), whether the ledger's
 * baseline records have a known date: the baseline must be the oldest retained
 * version, that version must be the scope's first, and the history must not
 * have been truncated. Evaluated on every owner read, never persisted, so it
 * follows version-number rewrites, older downloads and deletions exactly as a
 * rebuild would.
 */
function baselineIsKnown(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
): boolean {
  if (ledger.baseline === null || ledger.skipped !== undefined) return true;
  if (ledger.truncated === true) return false;
  // The oldest versions are the tail of the newest-first listing.
  const count = storage.countVersions(ledger.scope);
  const tail = storage
    .listVersions(ledger.scope, {
      limit: OLDEST_PAGE,
      offset: Math.max(0, count - OLDEST_PAGE),
    })
    .filter((entry) => !Number.isNaN(Date.parse(entry.collectedAt)));
  if (tail.length === 0) return false;
  const oldestMs = Math.min(...tail.map((e) => Date.parse(e.collectedAt)));
  if (Date.parse(ledger.baseline) !== oldestMs) return false;
  return oldestStartsAtFirst(
    tail.filter((entry) => Date.parse(entry.collectedAt) === oldestMs),
  );
}

/** The ledger as the owner's read reports it, with `partial` derived from the index. */
function withDerivedPartial(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
): ScopeFirstSeenLedger {
  if (baselineIsKnown(storage, ledger)) return ledger;
  return { ...ledger, partial: true };
}

/** The retry record for versions that could not be read, or null when there are none. */
function retryOf(
  failed: readonly IndexEntry[],
  now: Date,
): ScopeFirstSeenLedger["retry"] | null {
  if (failed.length === 0) return null;
  return {
    versions: failed
      .slice(0, MAX_RETRY_VERSIONS)
      .map((entry) => entry.collectedAt),
    attemptedAt: now.toISOString(),
  };
}

/**
 * Rebuild a ledger from the scope's retained versions (see the cost rules in
 * the header). `truncated` marks a ledger that covers only part of the
 * history, so its baseline is the oldest version actually folded.
 */
async function rebuild(
  storage: DataStoragePort,
  scope: string,
  retained: readonly IndexEntry[],
  budget: number,
  now: Date,
): Promise<ScopeFirstSeenLedger | null> {
  if (retained.length === 0) return null;
  const selected = withinBudget(scope, retained, budget);
  const fold = new LedgerFold(null, scope);
  const { folded, failed } = await foldEntries(storage, scope, selected, fold);
  if (folded === 0) {
    // Persisted so the next request does not repeat the failed work.
    return {
      version: 4,
      scope,
      baseline: null,
      current: null,
      latest: { collectedAt: retained[0]!.collectedAt, total: 0 },
      through: retained[0]!.collectedAt,
      skipped: selected.length === 0 ? "too_large" : "unreadable",
      records: {},
    };
  }
  const total = storage.countVersions(scope);
  return fold.finish({
    // Truncated only when the window or the byte budget left versions out. A
    // version that could not be read is not a truncation: it is retried (see
    // `retry`), and the ledger converges once it is read or deleted.
    truncated: selected.length < retained.length || retained.length < total,
    through: retained[0]!.collectedAt,
    retry: retryOf(failed, now),
  });
}

/**
 * Catch a ledger up for the owner's read. New versions (newer than `through`)
 * are folded; a version that cannot be read is remembered in `retry` and
 * tried again at most once per `RETRY_UNREADABLE_MS`. When nothing is new and
 * no retry is due, nothing is read at all.
 */
async function catchUp(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
  retained: readonly IndexEntry[],
  budget: number,
  now: Date,
): Promise<ScopeFirstSeenLedger> {
  const newer = newerThan(retained, ledger);
  const selected = withinBudget(ledger.scope, newer, budget);

  // Unreadable versions still stored; the deleted ones are forgotten.
  const pending = (ledger.retry?.versions ?? []).filter((version) =>
    retained.some((entry) => entry.collectedAt === version),
  );
  const due =
    ledger.retry !== undefined &&
    pending.length > 0 &&
    now.getTime() - Date.parse(ledger.retry.attemptedAt) >= RETRY_UNREADABLE_MS;
  const retryEntries = due
    ? withinBudget(
        ledger.scope,
        retained.filter((entry) => pending.includes(entry.collectedAt)),
        budget,
      )
    : [];

  const forgotten = pending.length !== (ledger.retry?.versions.length ?? 0);
  if (selected.length === 0 && retryEntries.length === 0 && !forgotten) {
    return ledger;
  }

  const fold = new LedgerFold(ledger);
  const failedNew =
    selected.length > 0
      ? (await foldEntries(storage, ledger.scope, selected, fold)).failed
      : [];
  const failedRetry =
    retryEntries.length > 0
      ? (await foldEntries(storage, ledger.scope, retryEntries, fold)).failed
      : [];

  const stillFailing = due
    ? failedRetry.map((entry) => entry.collectedAt)
    : pending;
  const versions = [
    ...stillFailing,
    ...failedNew.map((entry) => entry.collectedAt),
  ].slice(0, MAX_RETRY_VERSIONS);
  const attempted = due || failedNew.length > 0;
  const retry =
    versions.length === 0
      ? null
      : {
          versions,
          attemptedAt: attempted
            ? now.toISOString()
            : ledger.retry!.attemptedAt,
        };
  // Only a window cut (more versions than the index window shows) or the
  // byte budget leaves new versions unfolded.
  const beyond = storage.listVersions(ledger.scope, {
    limit: 1,
    offset: retained.length,
  })[0];
  const windowCut =
    beyond !== undefined &&
    Date.parse(beyond.collectedAt) > Date.parse(ledger.through);
  return (
    (await fold.finish({
      truncated: windowCut || selected.length < newer.length,
      through: selected.length > 0 ? retained[0]!.collectedAt : ledger.through,
      retry,
    })) ?? ledger
  );
}

/**
 * Fold a version that was just stored AND indexed into the scope's sidecar.
 * Best-effort and cheap: any failure is swallowed (the write that triggered
 * it stays successful), and it never rebuilds. `data` is the envelope data
 * already in memory, so the previous version is never re-read.
 */
export async function recordStoredVersion(
  storage: DataStoragePort,
  version: VersionToFold,
): Promise<void> {
  if (!storage.readFirstSeenLedger || !storage.writeFirstSeenLedger) return;
  try {
    await withScopeLock(version.scope, async () => {
      const retained = retainedVersions(storage, version.scope);
      let existing = await readStoredLedger(storage, version.scope);
      if (existing && !latestStillStored(storage, existing)) {
        // Its newest version is gone: what it reports is stale.
        await storage.deleteFirstSeenLedger?.(version.scope);
        existing = null;
      }
      const others = retained.filter(
        (entry) => entry.collectedAt !== version.collectedAt,
      );
      let through = version.collectedAt;
      if (existing) {
        // A failed or oversized rebuild is retried by the owner's read.
        if (isMarker(existing)) return;
        const throughMs = Date.parse(existing.through);
        const unfolded = others.some(
          (entry) => Date.parse(entry.collectedAt) > throughMs,
        );
        // Versions this write did not fold keep the marker where it was.
        through =
          unfolded || Date.parse(version.collectedAt) < throughMs
            ? existing.through
            : version.collectedAt;
      } else if (others.length > 0) {
        // Older versions exist but no sidecar: leave it for `/additions` to
        // build, so a write never reads history.
        return;
      }
      const fold = new LedgerFold(existing, version.scope);
      await fold.add(version);
      const next = await fold.finish({ through });
      if (!next) return;
      await storage.writeFirstSeenLedger!(version.scope, next);
      await dropIfScopeEmpty(storage, version.scope);
    });
  } catch {
    // Derived data: rebuilt from the retained versions when next needed.
  }
}

/**
 * The scope's ledger for a read: the stored sidecar (caught up with any newer
 * retained version it missed), or a bounded rebuild from the retained versions
 * that is persisted when the storage can hold it. Null when the scope has no
 * version. This is the one place a read path may parse stored envelopes, and
 * only when the sidecar is absent, stale or behind.
 */
export async function ensureScopeLedger(
  storage: DataStoragePort,
  scope: string,
  options: LedgerStoreOptions = {},
): Promise<ScopeFirstSeenLedger | null> {
  const budget = options.byteBudget ?? REBUILD_BYTE_BUDGET;
  const now = options.now ?? new Date();
  return withScopeLock(scope, async () => {
    try {
      const retained = retainedVersions(storage, scope);
      if (retained.length === 0) {
        await storage.deleteFirstSeenLedger?.(scope);
        return null;
      }
      let existing = await readStoredLedger(storage, scope);
      if (
        existing &&
        (!latestStillStored(storage, existing) ||
          !baselineStillStored(storage, existing) ||
          (isMarker(existing) && newerThan(retained, existing).length > 0))
      ) {
        existing = null;
      }
      const ledger = existing
        ? await catchUp(storage, existing, retained, budget, now)
        : await rebuild(storage, scope, retained, budget, now);
      if (ledger && ledger !== existing && storage.writeFirstSeenLedger) {
        try {
          await storage.writeFirstSeenLedger(scope, ledger);
          if (await dropIfScopeEmpty(storage, scope)) return null;
        } catch {
          // Served from memory; the next read rebuilds it again.
        }
      }
      return ledger ? withDerivedPartial(storage, ledger) : ledger;
    } catch {
      return null;
    }
  });
}
