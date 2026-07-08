// Cross-cycle download retry memory.
//
// downloadAll re-lists the owner's data points every sync cycle (the cursor
// only advances past fully-successful pages, and a single-page listing has no
// nextCursor at all), so without memory a record whose blob fails to download
// is re-fetched on every cycle. With the DCR page triggering a sync per
// readiness poll, one missing blob produced a 700+ request 404 storm against
// storage (2026-07-08 prod incident).
//
// Policy:
//   - non-retryable failures (deterministic — e.g. HTTP 404: the blob is not
//     there and waiting cannot heal it): never attempt again for the lifetime
//     of this memory (one attempt per boot session).
//   - retryable failures (transient — 5xx, network): exponential backoff,
//     capped at DEFAULT_MAX_TRANSIENT_ATTEMPTS attempts, then give up for the
//     session.
//
// Keys pair the record id with its expectedVersion (`downloadRetryKey`), so a
// re-registered version — new bytes under a new blob key — always gets a
// fresh set of attempts.

export type DownloadAttemptDecision = "attempt" | "backoff" | "give-up";

export interface DownloadRetryMemoryOptions {
  /** Attempt cap for retryable failures (default 5). */
  maxTransientAttempts?: number;
  /** Base backoff, doubled per failed attempt (default 30s). */
  backoffBaseMs?: number;
  /** Clock override for tests. */
  now?: () => number;
}

export const DEFAULT_MAX_TRANSIENT_ATTEMPTS = 5;
export const DEFAULT_BACKOFF_BASE_MS = 30_000;

export interface DownloadRetryMemory {
  /** Whether the next download of `key` should run, wait, or never happen. */
  decide(key: string): DownloadAttemptDecision;
  /** Record a failed attempt; `retryable` follows the issue classification. */
  recordFailure(key: string, retryable: boolean): void;
  /** Clear the failure history after a successful download. */
  recordSuccess(key: string): void;
}

/** Retry-memory key for a data-point record: id + version. */
export function downloadRetryKey(record: {
  id: string;
  expectedVersion: string;
}): string {
  return `${record.id}@${record.expectedVersion}`;
}

interface RetryEntry {
  attempts: number;
  nextRetryAtMs: number;
  permanent: boolean;
}

export function createDownloadRetryMemory(
  options: DownloadRetryMemoryOptions = {},
): DownloadRetryMemory {
  const maxTransientAttempts =
    options.maxTransientAttempts ?? DEFAULT_MAX_TRANSIENT_ATTEMPTS;
  const backoffBaseMs = options.backoffBaseMs ?? DEFAULT_BACKOFF_BASE_MS;
  const now = options.now ?? Date.now;
  // DPv2 keys one record per (owner, scope), so the map stays small — no
  // eviction needed.
  const entries = new Map<string, RetryEntry>();

  return {
    decide(key) {
      const entry = entries.get(key);
      if (!entry) return "attempt";
      if (entry.permanent || entry.attempts >= maxTransientAttempts) {
        return "give-up";
      }
      return now() < entry.nextRetryAtMs ? "backoff" : "attempt";
    },

    recordFailure(key, retryable) {
      if (!retryable) {
        entries.set(key, { attempts: 0, nextRetryAtMs: 0, permanent: true });
        return;
      }
      const attempts = (entries.get(key)?.attempts ?? 0) + 1;
      entries.set(key, {
        attempts,
        nextRetryAtMs: now() + backoffBaseMs * 2 ** (attempts - 1),
        permanent: false,
      });
    },

    recordSuccess(key) {
      entries.delete(key);
    },
  };
}
