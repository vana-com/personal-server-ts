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
 *  - Any other failure backs off: attempt n waits `BASE * 2^(n-1)` (capped),
 *    and after `MAX_UPLOAD_FAILURES` failures the entry is "stopped" until new
 *    data arrives for its scope or the owner retries.
 *
 * The index has no column for failure counts, and changing it is a storage
 * change in every host, so the counters live in memory per sync manager (as
 * the other retry trackers here do). A restart gives a stopped entry a fresh
 * budget of `MAX_UPLOAD_FAILURES` attempts spread over the backoff schedule,
 * not one attempt per cycle.
 */

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

/** Whether an entry of `storedBytes` could exceed the upload body cap. */
export function exceedsUploadCap(storedBytes: number): boolean {
  return estimateUploadBodyBytes(storedBytes) > MAX_UPLOAD_BODY_BYTES;
}

export const UPLOAD_BACKOFF_BASE_MS = 60_000;
export const UPLOAD_BACKOFF_MAX_MS = 60 * 60_000;
/** Failures allowed before an entry stops retrying (1m, 2m, 4m ... 1h). */
export const MAX_UPLOAD_FAILURES = 8;

export interface UploadStateEntry {
  scope: string;
  path: string;
}

export interface TooLargeUpload extends UploadStateEntry {
  /** Stored size of the entry. */
  sizeBytes: number;
  /** The cap the upload body would exceed. */
  maxBodyBytes: number;
}

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
  /** Failed entries waiting for their next attempt. */
  retrying: RetryingUpload[];
  /** Entries that used every attempt; new data or an owner retry resets. */
  stopped: StoppedUpload[];
}

export interface UploadStateTracker {
  /** Record an entry as too large; true the first time (log once). */
  markTooLarge(entry: UploadStateEntry, sizeBytes: number): boolean;
  /** Whether the entry may be attempted now (not backing off, not stopped). */
  shouldAttempt(path: string, nowMs: number): boolean;
  /** Count one failed attempt. */
  recordFailure(entry: UploadStateEntry, error: string, nowMs: number): void;
  /** The entry synced or was removed: forget it. */
  clear(path: string): void;
  /** New data arrived for `scope`: forget its other entries' state. */
  clearScopeExcept(scope: string, keepPath: string): void;
  /** Forget every entry of `scope` (owner retry, scope deletion). */
  clearScope(scope: string): void;
  snapshot(): UploadStateSnapshot;
}

interface Tracked extends UploadStateEntry {
  tooLargeBytes?: number;
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
    shouldAttempt(path, nowMs) {
      const state = states.get(path);
      if (!state) return true;
      if (state.tooLargeBytes !== undefined) return false;
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
    clearScopeExcept(scope, keepPath) {
      for (const [path, state] of states) {
        if (state.scope === scope && path !== keepPath) states.delete(path);
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
