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
 *    download) never rebuilds and never reads a stored envelope to do so. It
 *    folds the version already in memory into an existing sidecar, starts a
 *    sidecar when the new version is the scope's only one, and otherwise
 *    leaves the sidecar absent for the owner-only `/additions` read.
 *  - A rebuild (`ensureScopeLedger`) folds ONE version at a time, newest
 *    `REBUILD_VERSION_LIMIT` versions at most and at most
 *    `REBUILD_BYTE_BUDGET` bytes of envelopes (index `sizeBytes`), oldest
 *    folded first, yielding to the event loop between versions. A scope whose
 *    rules track nothing is not read at all.
 *  - Negative outcomes (over the cap, too large, unreadable) are persisted
 *    as a ledger with a `skipped` reason, so they are not retried per request.
 *
 * Guarantee, in order of strength:
 *  1. Updates and deletions of one scope are serialized inside this process
 *     (`withScopeLock`), and after a write the sidecar is removed again if the
 *     scope has no versions left, so a delete racing a rebuild leaves nothing.
 *  2. Across processes sharing one data directory a fold can still be lost.
 *     Each update also folds the retained versions newer than the sidecar's
 *     `latest` (within the byte budget), so a lost NEWER version is repaired
 *     by the next update or `/additions` read.
 *  3. A lost version that is not newer than `latest` is repaired only by a
 *     rebuild (delete the sidecar, or reimport).
 *  4. A sidecar whose `latest` matches no retained version (its newest version
 *     was deleted) is discarded and rebuilt.
 */

import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/types.js";
import {
  LedgerFold,
  foldVersions,
  readScopeFirstSeenLedger,
  yieldToEventLoop,
  type ScopeFirstSeenLedger,
  type VersionToFold,
} from "./first-added.js";
import { memoryRecordRulesFor } from "./record-rules.js";
import { withScopeLock } from "./scope-lock.js";

/** Most recent retained versions considered when a sidecar is rebuilt or caught up. */
export const REBUILD_VERSION_LIMIT = 200;
/** Envelope bytes (from the index) read for one scope in one rebuild or catch-up. */
export const REBUILD_BYTE_BUDGET = 256 * 1024 * 1024;

export interface LedgerStoreOptions {
  /** Override `REBUILD_BYTE_BUDGET`. */
  byteBudget?: number;
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
    .sort((a, b) => Date.parse(b.collectedAt) - Date.parse(a.collectedAt));
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

function isMarker(ledger: ScopeFirstSeenLedger): boolean {
  return ledger.skipped === "too_large" || ledger.skipped === "unreadable";
}

function newerThan(
  retained: readonly IndexEntry[],
  ledger: ScopeFirstSeenLedger,
): IndexEntry[] {
  const latestMs = Date.parse(ledger.latest.collectedAt);
  return retained.filter((entry) => Date.parse(entry.collectedAt) > latestMs);
}

/** Fold `entries` (newest first) into `fold`, oldest first, one envelope at a time. */
async function foldEntries(
  storage: DataStoragePort,
  scope: string,
  entries: readonly IndexEntry[],
  fold: LedgerFold,
): Promise<number> {
  let folded = 0;
  for (const entry of [...entries].reverse()) {
    const version = await readVersionData(storage, scope, entry.collectedAt);
    if (version) {
      await fold.add(version);
      folded += 1;
    }
    await yieldToEventLoop();
  }
  return folded;
}

/**
 * Rebuild a ledger from the scope's retained versions (see the cost rules in
 * the header). `partial` marks a ledger that covers only part of the
 * history, so its baseline is the oldest version actually folded.
 */
async function rebuild(
  storage: DataStoragePort,
  scope: string,
  retained: readonly IndexEntry[],
  budget: number,
): Promise<ScopeFirstSeenLedger | null> {
  if (retained.length === 0) return null;
  const selected = withinBudget(scope, retained, budget);
  const fold = new LedgerFold(null, scope);
  const folded = await foldEntries(storage, scope, selected, fold);
  if (folded === 0) {
    // Persisted so the next request does not repeat the failed work.
    return {
      version: 2,
      scope,
      baseline: null,
      current: null,
      latest: { collectedAt: retained[0]!.collectedAt, total: 0 },
      skipped: selected.length === 0 ? "too_large" : "unreadable",
      records: {},
    };
  }
  const total = storage.countVersions(scope);
  return fold.finish({ partial: folded < total });
}

/**
 * Fold the retained versions newer than the ledger's `latest` (the newest
 * ones within the byte budget). A ledger that keeps no keys only needs the
 * newest one, for its `latest`.
 */
async function catchUp(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
  retained: readonly IndexEntry[],
  budget: number,
  exceptAt?: string,
): Promise<ScopeFirstSeenLedger> {
  let newer = newerThan(retained, ledger).filter(
    (entry) => entry.collectedAt !== exceptAt,
  );
  if (ledger.skipped === "too_many_keys") newer = newer.slice(0, 1);
  const selected = withinBudget(ledger.scope, newer, budget);
  if (selected.length === 0) return ledger;
  const fold = new LedgerFold(ledger);
  await foldEntries(storage, ledger.scope, selected, fold);
  return (await fold.finish()) ?? ledger;
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
  options: LedgerStoreOptions = {},
): Promise<void> {
  if (!storage.readFirstSeenLedger || !storage.writeFirstSeenLedger) return;
  const budget = options.byteBudget ?? REBUILD_BYTE_BUDGET;
  try {
    await withScopeLock(version.scope, async () => {
      const retained = retainedVersions(storage, version.scope);
      let existing = await readStoredLedger(storage, version.scope);
      if (
        existing &&
        !retained.some((e) => e.collectedAt === existing!.latest.collectedAt)
      ) {
        // Its newest version is gone: what it reports is stale.
        await storage.deleteFirstSeenLedger?.(version.scope);
        existing = null;
      }

      let base: ScopeFirstSeenLedger | null = null;
      if (existing) {
        // A failed or oversized rebuild is retried by the owner's read.
        if (isMarker(existing)) return;
        base = await catchUp(
          storage,
          existing,
          retained,
          budget,
          version.collectedAt,
        );
      } else if (
        retained.some((entry) => entry.collectedAt !== version.collectedAt)
      ) {
        // Older versions exist but no sidecar: leave it for `/additions` to
        // build, so a write never reads history.
        return;
      }
      const next = await foldVersions(base, [version]);
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
        (!retained.some(
          (e) => e.collectedAt === existing!.latest.collectedAt,
        ) ||
          (isMarker(existing) && newerThan(retained, existing).length > 0))
      ) {
        existing = null;
      }
      const ledger = existing
        ? await catchUp(storage, existing, retained, budget)
        : await rebuild(storage, scope, retained, budget);
      if (ledger && ledger !== existing && storage.writeFirstSeenLedger) {
        try {
          await storage.writeFirstSeenLedger(scope, ledger);
          if (await dropIfScopeEmpty(storage, scope)) return null;
        } catch {
          // Served from memory; the next read rebuilds it again.
        }
      }
      return ledger;
    } catch {
      return null;
    }
  });
}
