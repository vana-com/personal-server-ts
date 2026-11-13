/**
 * Bounded, retrying access to storage blobs.
 *
 * Stream-sync blob names are content addressed, so a read or a write of the
 * same key can be repeated without changing the outcome (a second upload of a
 * key keeps the stored copy). That makes a retry of a transient failure safe.
 *
 * Retry follows the usual client practice (AWS SDK "standard" mode, Stripe's
 * idempotent retries): only failures that can pass by themselves are retried
 * (HTTP 5xx and 429, network errors), never other 4xx, with capped exponential
 * backoff and full jitter, and a small fixed number of attempts.
 */

export interface StorageAccessPolicy {
  /** Operations in flight at once, across every caller sharing the limiter. */
  readonly maxConcurrent: number;
  /**
   * Uploads in flight at once, a limit under `maxConcurrent` that only uploads
   * pass through. vana-storage answers fast HTTP 500s while one owner has two
   * or more uploads in flight; keep this at 1 until that is fixed there. Reads,
   * the gateway and the other uploads' share of `maxConcurrent` are unaffected.
   */
  readonly maxConcurrentPuts: number;
  /** Total tries per operation, the first one included. */
  readonly maxAttempts: number;
  /** Upper bound of the wait before the second try; it doubles each time. */
  readonly baseDelayMs: number;
  /** No wait is longer than this. */
  readonly maxDelayMs: number;
  /** Replaceable, with `sleep`, so tests need not wait. */
  readonly now: () => number;
  readonly sleep: (ms: number) => Promise<void>;
  /** Replaceable so tests can pin jitter. Returns a value in [0, 1). */
  readonly random: () => number;
}

export const DEFAULT_STORAGE_ACCESS_POLICY: StorageAccessPolicy = {
  maxConcurrent: 2,
  maxConcurrentPuts: 1,
  maxAttempts: 6,
  baseDelayMs: 250,
  maxDelayMs: 4_000,
  now: Date.now,
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  random: Math.random,
};

const NETWORK_FAILURE =
  /network error|fetch failed|socket hang up|ECONNRESET|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|EPIPE|UND_ERR_/i;
// The SDK and the audience adapter put the HTTP status only in the message:
// "vana-storage download failed: 500 ...", "Storage GET failed (503)".
const STATUS_IN_MESSAGE = /failed[:\s(]+(\d{3})\b/i;

function statusOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const record = error as Record<string, unknown>;
  for (const key of ["status", "statusCode"]) {
    if (typeof record[key] === "number") return record[key];
  }
  const message = typeof record.message === "string" ? record.message : "";
  const match = STATUS_IN_MESSAGE.exec(message);
  return match ? Number(match[1]) : undefined;
}

/**
 * True when repeating the same call can succeed: HTTP 429 and 5xx, network
 * failures and timeouts. Any other status (including every other 4xx) and any
 * failure that is not a transport failure is final. A cancelled call is final.
 */
export function isTransientStorageError(error: unknown, depth = 0): boolean {
  if (typeof error !== "object" || error === null || depth > 2) return false;
  const name = (error as { name?: unknown }).name;
  if (name === "AbortError") return false;
  if (name === "TimeoutError") return true;
  const status = statusOf(error);
  if (status !== undefined) return status === 429 || status >= 500;
  const message = (error as { message?: unknown }).message;
  const code = (error as { code?: unknown }).code;
  if (typeof message === "string" && NETWORK_FAILURE.test(message)) return true;
  if (typeof code === "string" && NETWORK_FAILURE.test(code)) return true;
  return isTransientStorageError(
    (error as { cause?: unknown }).cause,
    depth + 1,
  );
}

/** Full jitter: a uniform wait up to the capped exponential bound. */
export function backoffDelayMs(
  attempt: number,
  policy: Pick<StorageAccessPolicy, "baseDelayMs" | "maxDelayMs" | "random">,
): number {
  const bound = Math.min(
    policy.maxDelayMs,
    policy.baseDelayMs * 2 ** (attempt - 1),
  );
  return Math.floor(policy.random() * bound);
}

/**
 * One shared gate for every storage call of a blob store: at most
 * `maxConcurrent` calls run at once, and a transient failure is repeated, up to
 * `maxAttempts` tries in all (the last error is thrown unchanged).
 *
 * The backoff is shared. When storage signals overload, the wait that follows
 * a failure holds back every caller, not only the one that failed. Otherwise
 * the calls that did not fail yet keep sending, drain whatever capacity storage
 * regains, and the failed call spends its few attempts without a chance.
 */
export function createStorageAccess(
  policy: StorageAccessPolicy,
): <T>(operation: () => Promise<T>) => Promise<T> {
  const limit = createConcurrencyLimit(policy.maxConcurrent);
  let resumeAt = 0;
  return (operation) =>
    limit(async () => {
      for (let attempt = 1; ; attempt++) {
        const wait = resumeAt - policy.now();
        if (wait > 0) await policy.sleep(wait);
        try {
          return await operation();
        } catch (error) {
          if (attempt >= policy.maxAttempts || !isTransientStorageError(error))
            throw error;
          resumeAt = Math.max(
            resumeAt,
            policy.now() + backoffDelayMs(attempt, policy),
          );
        }
      }
    });
}

/** A counting semaphore: at most `limit` operations run, the rest queue. */
export function createConcurrencyLimit(
  limit: number,
): <T>(operation: () => Promise<T>) => Promise<T> {
  let active = 0;
  const waiting: (() => void)[] = [];
  const release = () => {
    const next = waiting.shift();
    if (next) next();
    else active--;
  };
  return async (operation) => {
    if (active < limit) active++;
    else await new Promise<void>((resolve) => waiting.push(resolve));
    try {
      return await operation();
    } finally {
      release();
    }
  };
}
