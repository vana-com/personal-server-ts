/**
 * Keeps a scope's first-seen sidecar current. See `first-added.ts` for the
 * ledger itself; this module is the only code that reads and writes it.
 *
 * The sidecar is a cache derived from the scope's stored versions, so every
 * failure here is survivable: a missing or unreadable sidecar is rebuilt from
 * the retained versions the next time it is needed, and nothing in this
 * module may fail or delay a data write.
 *
 * Guarantee, in order of strength:
 *  1. Writes to one scope are serialized inside this process (`withScopeLock`),
 *     so two ingests never lose each other's fold.
 *  2. Across processes sharing one data directory a fold can still be lost.
 *     Folding is order independent and idempotent, and each update also folds
 *     the (at most 5) newest retained versions newer than the sidecar's
 *     `latest`, so a lost NEWER version is repaired by the next update or by
 *     the next `/additions` read.
 *  3. A lost version that is not newer than `latest` is repaired only by a
 *     rebuild (delete the sidecar, or reimport).
 */

import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/types.js";
import {
  foldVersions,
  readScopeFirstSeenLedger,
  type ScopeFirstSeenLedger,
  type VersionToFold,
} from "./first-added.js";

/** Most recent retained versions folded when a sidecar is rebuilt. */
export const BACKFILL_VERSION_LIMIT = 200;
/** Newer-than-latest retained versions folded in addition to the new one. */
export const CATCH_UP_VERSION_LIMIT = 5;

const lockTails = new Map<string, Promise<void>>();

/** Serialize `fn` with every other call for the same scope in this process. */
async function withScopeLock<T>(
  scope: string,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = lockTails.get(scope) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => {
    release = resolve;
  });
  const tail = previous.then(() => mine);
  lockTails.set(scope, tail);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (lockTails.get(scope) === tail) lockTails.delete(scope);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The envelope data as stored (never the read-time view), or null if unreadable. */
async function readVersionData(
  storage: DataStoragePort,
  scope: string,
  collectedAt: string,
): Promise<VersionToFold | null> {
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
  limit: number,
): IndexEntry[] {
  return storage
    .listVersions(scope, { limit })
    .filter((entry) => !Number.isNaN(Date.parse(entry.collectedAt)))
    .sort((a, b) => Date.parse(b.collectedAt) - Date.parse(a.collectedAt));
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

/** Read the retained versions (oldest first) as fold inputs, skipping unreadable ones. */
async function readOldestFirst(
  storage: DataStoragePort,
  scope: string,
  entries: readonly IndexEntry[],
): Promise<VersionToFold[]> {
  const versions: VersionToFold[] = [];
  for (const entry of [...entries].reverse()) {
    const version = await readVersionData(storage, scope, entry.collectedAt);
    if (version) versions.push(version);
  }
  return versions;
}

/**
 * Rebuild a ledger from the scope's retained versions: the
 * `BACKFILL_VERSION_LIMIT` most recent, oldest first, skipping the version at
 * `exceptAt` (the caller folds that one from memory).
 */
async function backfill(
  storage: DataStoragePort,
  scope: string,
  exceptAt?: string,
): Promise<ScopeFirstSeenLedger | null> {
  const entries = retainedVersions(
    storage,
    scope,
    BACKFILL_VERSION_LIMIT,
  ).filter((entry) => entry.collectedAt !== exceptAt);
  return foldVersions(null, await readOldestFirst(storage, scope, entries));
}

/** Fold retained versions newer than the ledger's `latest` that it may have missed. */
async function catchUp(
  storage: DataStoragePort,
  ledger: ScopeFirstSeenLedger,
  exceptAt?: string,
): Promise<ScopeFirstSeenLedger> {
  const latestMs = Date.parse(ledger.latest.collectedAt);
  const newer = retainedVersions(
    storage,
    ledger.scope,
    CATCH_UP_VERSION_LIMIT + 1,
  )
    .filter(
      (entry) =>
        Date.parse(entry.collectedAt) > latestMs &&
        entry.collectedAt !== exceptAt,
    )
    .slice(0, CATCH_UP_VERSION_LIMIT);
  if (newer.length === 0) return ledger;
  const versions = await readOldestFirst(storage, ledger.scope, newer);
  return (await foldVersions(ledger, versions)) ?? ledger;
}

/**
 * Fold a version that was just stored AND indexed into the scope's sidecar.
 * Best-effort: any failure is swallowed (the write that triggered it stays
 * successful) because a missing sidecar is rebuilt later. `data` is the
 * envelope data already in memory, so the previous version is never re-read.
 */
export async function recordStoredVersion(
  storage: DataStoragePort,
  version: VersionToFold,
): Promise<void> {
  if (!storage.readFirstSeenLedger || !storage.writeFirstSeenLedger) return;
  try {
    await withScopeLock(version.scope, async () => {
      const existing = await readStoredLedger(storage, version.scope);
      const base = existing
        ? await catchUp(storage, existing, version.collectedAt)
        : await backfill(storage, version.scope, version.collectedAt);
      const next = await foldVersions(base, [version]);
      if (next) await storage.writeFirstSeenLedger!(version.scope, next);
    });
  } catch {
    // Derived data: rebuilt from the retained versions when next needed.
  }
}

/**
 * The scope's ledger for a read: the stored sidecar (caught up with any newer
 * retained version it missed), or a rebuild from the retained versions that is
 * persisted when the storage can hold it. Null when the scope has no readable
 * version. This is the one place a read path may parse stored envelopes, and
 * only when the sidecar is absent or behind.
 */
export async function ensureScopeLedger(
  storage: DataStoragePort,
  scope: string,
): Promise<ScopeFirstSeenLedger | null> {
  return withScopeLock(scope, async () => {
    try {
      const existing = await readStoredLedger(storage, scope);
      const ledger = existing
        ? await catchUp(storage, existing)
        : await backfill(storage, scope);
      if (ledger && ledger !== existing && storage.writeFirstSeenLedger) {
        try {
          await storage.writeFirstSeenLedger(scope, ledger);
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
