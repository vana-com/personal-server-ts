/**
 * Upload limits and bounded retry for unsynced entries.
 *
 * Why this exists: both storage endpoints sit behind Cloudflare, which rejects
 * request bodies over 100 MB with an HTML 413 that carries no CORS headers. A
 * browser or WebView reports that as "Failed to fetch". An entry whose body
 * can never fit used to be read, encoded and encrypted whole on every sync
 * cycle, then fail the same way (a phone with one ~337 MiB scope spent its
 * renderer memory on this each cycle). Any other failing entry was retried
 * every cycle with no backoff and no cap.
 *
 * Two rules, both owner-visible through `SyncStatus.uploads`:
 *  - An entry whose upload body would exceed `MAX_UPLOAD_BODY_BYTES` is
 *    "too large to sync": it is never read, encoded, encrypted or sent. It
 *    stays local and readable. The decision uses the stored size only, so it
 *    needs no memory to stay correct.
 *  - An entry with no usable stored size (missing, NaN, zero, negative) is
 *    "unsizable": it cannot be shown to fit, so it is treated the same way
 *    and reported under its own reason. No storage port offers an exact size
 *    without reading the body, so the check fails closed instead.
 *  - Any other failure backs off: attempt n waits `BASE * 2^(n-1)` (capped),
 *    and after `MAX_UPLOAD_FAILURES` failures the entry is "stopped" until new
 *    data arrives for its scope or the owner retries.
 *
 * An attempt that kills the process is invisible to the counters here; those
 * are counted by the durable markers in `upload-attempts.ts`.
 *
 * The index has no column for failure counts, and changing it is a storage
 * change in every host, so the counters live in memory per sync manager (as
 * the other retry trackers here do). A restart gives a stopped entry a fresh
 * budget of `MAX_UPLOAD_FAILURES` attempts spread over the backoff schedule,
 * not one attempt per cycle.
 */

import { CRASHED_UPLOAD_REASON } from "./upload-attempts.js";

/**
 * Cloudflare rejects request bodies over 100 MB. Stay under it with margin.
 * Decimal megabytes, because the provider's limit is stated in MB.
 */
export const MAX_UPLOAD_BODY_BYTES = 95_000_000;

/** Fixed OpenPGP framing allowance added to every estimate. */
const ENCRYPTION_FIXED_OVERHEAD_BYTES = 64 * 1024;
/** Proportional allowance; encryption can only add packet framing. */
const ENCRYPTION_PROPORTIONAL_OVERHEAD = 0.02;

/**
 * Conservative upper bound of the encrypted request body for an entry whose
 * stored file is `storedBytes` long. The envelope is re-serialised before
 * encryption, so the stored size is an estimate of the plaintext, padded.
 */
export function estimateUploadBodyBytes(storedBytes: number): number {
  return (
    Math.ceil(storedBytes * (1 + ENCRYPTION_PROPORTIONAL_OVERHEAD)) +
    ENCRYPTION_FIXED_OVERHEAD_BYTES
  );
}

/**
 * Whether the stored size is a usable measurement: a finite, positive number.
 * A stored envelope is never empty, so a missing, NaN, zero or negative size
 * is bad metadata, not a small file.
 */
export function isUsableUploadSize(
  storedBytes: unknown,
): storedBytes is number {
  return (
    typeof storedBytes === "number" &&
    Number.isFinite(storedBytes) &&
    storedBytes > 0
  );
}

/**
 * Whether an entry of `storedBytes` could exceed the upload body cap. Fails
 * closed: a size that is not usable cannot be shown to fit, so it counts as
 * over the cap.
 */
export function exceedsUploadCap(storedBytes: number): boolean {
  if (!isUsableUploadSize(storedBytes)) return true;
  return estimateUploadBodyBytes(storedBytes) > MAX_UPLOAD_BODY_BYTES;
}

export const UPLOAD_BACKOFF_BASE_MS = 60_000;
export const UPLOAD_BACKOFF_MAX_MS = 60 * 60_000;
/** Failures allowed before an entry stops retrying (1m, 2m, 4m ... 1h). */
export const MAX_UPLOAD_FAILURES = 8;

/**
 * What makes a row the same row: a path can be rewritten with a new id (a
 * replacement) or a repaired size. State held for the old row must not apply
 * to the new one.
 */
export interface RowIdentity {
  id: string | number;
  /** Compared with `Object.is`, so NaN equals NaN. */
  sizeBytes: unknown;
}

/** Row ids `afterId < id <= throughId` were all listed by the scan. */
export interface ScannedRange {
  afterId: number;
  throughId: number;
}

export interface UploadStateEntry {
  scope: string;
  path: string;
  /** The row this state was recorded for; absent for path-only callers. */
  identity?: RowIdentity;
}

export interface TooLargeUpload extends UploadStateEntry {
  /** Stored size of the entry. */
  sizeBytes: number;
  /** The cap the upload body would exceed. */
  maxBodyBytes: number;
}

/** Stored size was missing or not a positive finite number. */
export type UnsizableUpload = UploadStateEntry;

export interface RetryingUpload extends UploadStateEntry {
  failures: number;
  lastError: string;
  /** ISO time before which the entry is not attempted. */
  nextAttemptAt: string;
}

export interface StoppedUpload extends UploadStateEntry {
  failures: number;
  lastError: string;
  stoppedAt: string;
}

/** Owner-visible upload problems; every list is empty when nothing is owed. */
export interface UploadStateSnapshot {
  /** Local entries that can never fit one upload; kept locally, not synced. */
  tooLarge: TooLargeUpload[];
  /** Local entries with no usable stored size; never read, kept locally. */
  unsizable: UnsizableUpload[];
  /** Failed entries waiting for their next attempt. */
  retrying: RetryingUpload[];
  /** Entries that used every attempt; new data or an owner retry resets. */
  stopped: StoppedUpload[];
}

export interface UploadStateTracker {
  /** Record an entry as too large; true the first time (log once). */
  markTooLarge(entry: UploadStateEntry, sizeBytes: number): boolean;
  /** Record an entry as having no usable size; true the first time. */
  markUnsizable(entry: UploadStateEntry): boolean;
  /** Whether the entry may be attempted now (not backing off, not stopped). */
  shouldAttempt(path: string, nowMs: number): boolean;
  /**
   * Record an entry as quarantined after attempts that killed the process
   * (see `upload-attempts.ts`). Not released by new data for its scope: the
   * attempt ledger decides. Safe to call every cycle.
   */
  markCrashed(
    entry: UploadStateEntry,
    interrupted: number,
    nowMs: number,
  ): void;
  /** Count one failed attempt. */
  recordFailure(entry: UploadStateEntry, error: string, nowMs: number): void;
  /** Whether any state is held for the entry. */
  has(path: string): boolean;
  /**
   * Forget the state of every entry that is no longer one of `rows`: its path
   * is absent (the row is gone) or its row identity or size changed (the path
   * was rewritten). State recorded without an identity is kept while the path
   * exists.
   *
   * `rows` is normally the whole unsynced set. After a partial (paged) scan,
   * pass the row-id range that was scanned: an entry is then judged missing
   * only when its row id lies inside that range, so state for rows the scan
   * did not reach is never pruned against an incomplete view.
   */
  reconcile(
    rows: readonly (RowIdentity & { path: string })[],
    scanned?: ScannedRange,
  ): void;
  /** Where the next paged scan of the unsynced rows resumes (row id, 0 = start). */
  scanCursor(): number;
  setScanCursor(afterId: number): void;
  /**
   * Highest row id the current sweep may scan, fixed when the sweep starts
   * (`null` between sweeps). Rows above it join the next sweep.
   */
  scanFence(): number | null;
  setScanFence(throughId: number | null): void;
  /** New data arrived for `scope`: stopped entries there try again. */
  releaseStopped(scope: string): void;
  /** The entry synced or was removed: forget it. */
  clear(path: string): void;
  /** Forget every entry of `scope` (owner retry, scope deletion). */
  clearScope(scope: string): void;
  snapshot(): UploadStateSnapshot;
}

interface Tracked extends UploadStateEntry {
  tooLargeBytes?: number;
  unsizable?: true;
  crashed?: true;
  failures: number;
  lastError: string;
  nextAttemptMs: number;
  stoppedAtMs: number | null;
}

export function createUploadStateTracker(
  options: { maxFailures?: number } = {},
): UploadStateTracker {
  const maxFailures = options.maxFailures ?? MAX_UPLOAD_FAILURES;
  const states = new Map<string, Tracked>();
  let scanAfterId = 0;
  let scanFenceId: number | null = null;
  const iso = (ms: number) => new Date(ms).toISOString();

  return {
    markTooLarge(entry, sizeBytes) {
      const known = states.get(entry.path);
      if (known?.tooLargeBytes !== undefined) return false;
      states.set(entry.path, {
        ...entry,
        tooLargeBytes: sizeBytes,
        failures: 0,
        lastError: "",
        nextAttemptMs: 0,
        stoppedAtMs: null,
      });
      return true;
    },
    markUnsizable(entry) {
      if (states.get(entry.path)?.unsizable) return false;
      states.set(entry.path, {
        ...entry,
        unsizable: true,
        failures: 0,
        lastError: "",
        nextAttemptMs: 0,
        stoppedAtMs: null,
      });
      return true;
    },
    markCrashed(entry, interrupted, nowMs) {
      if (states.get(entry.path)?.crashed) return;
      states.set(entry.path, {
        ...entry,
        crashed: true,
        failures: interrupted,
        lastError: CRASHED_UPLOAD_REASON,
        nextAttemptMs: 0,
        stoppedAtMs: nowMs,
      });
    },
    shouldAttempt(path, nowMs) {
      const state = states.get(path);
      if (!state) return true;
      if (state.tooLargeBytes !== undefined || state.unsizable) return false;
      if (state.stoppedAtMs !== null) return false;
      return nowMs >= state.nextAttemptMs;
    },
    recordFailure(entry, error, nowMs) {
      const failures = (states.get(entry.path)?.failures ?? 0) + 1;
      const delay = Math.min(
        UPLOAD_BACKOFF_BASE_MS * 2 ** (failures - 1),
        UPLOAD_BACKOFF_MAX_MS,
      );
      states.set(entry.path, {
        ...entry,
        failures,
        lastError: error,
        nextAttemptMs: nowMs + delay,
        stoppedAtMs: failures >= maxFailures ? nowMs : null,
      });
    },
    clear(path) {
      states.delete(path);
    },
    has(path) {
      return states.has(path);
    },
    reconcile(rows, scanned) {
      const current = new Map<string, RowIdentity>();
      for (const row of rows) current.set(row.path, row);
      for (const [path, state] of states) {
        const row = current.get(path);
        if (row) {
          if (
            state.identity &&
            (state.identity.id !== row.id ||
              !Object.is(state.identity.sizeBytes, row.sizeBytes))
          )
            states.delete(path);
          continue;
        }
        // Not listed: gone, unless the scan never looked where it would be.
        const id = state.identity?.id;
        const covered =
          !scanned ||
          (typeof id === "number" &&
            id > scanned.afterId &&
            id <= scanned.throughId);
        if (covered) states.delete(path);
      }
    },
    scanCursor() {
      return scanAfterId;
    },
    setScanCursor(afterId) {
      scanAfterId = afterId;
    },
    scanFence() {
      return scanFenceId;
    },
    setScanFence(throughId) {
      scanFenceId = throughId;
    },
    releaseStopped(scope) {
      for (const [path, state] of states) {
        if (
          state.scope === scope &&
          state.stoppedAtMs !== null &&
          !state.crashed
        )
          states.delete(path);
      }
    },
    clearScope(scope) {
      for (const [path, state] of states) {
        if (state.scope === scope) states.delete(path);
      }
    },
    snapshot() {
      const snapshot: UploadStateSnapshot = {
        tooLarge: [],
        unsizable: [],
        retrying: [],
        stopped: [],
      };
      for (const state of states.values()) {
        const base = { scope: state.scope, path: state.path };
        if (state.tooLargeBytes !== undefined) {
          snapshot.tooLarge.push({
            ...base,
            sizeBytes: state.tooLargeBytes,
            maxBodyBytes: MAX_UPLOAD_BODY_BYTES,
          });
        } else if (state.unsizable) {
          snapshot.unsizable.push(base);
        } else if (state.stoppedAtMs !== null) {
          snapshot.stopped.push({
            ...base,
            failures: state.failures,
            lastError: state.lastError,
            stoppedAt: iso(state.stoppedAtMs),
          });
        } else {
          snapshot.retrying.push({
            ...base,
            failures: state.failures,
            lastError: state.lastError,
            nextAttemptAt: iso(state.nextAttemptMs),
          });
        }
      }
      return snapshot;
    },
  };
}
