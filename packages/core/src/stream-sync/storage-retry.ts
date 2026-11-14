import type {
  QuotaListener,
  QuotaPolicy,
} from "../storage/adapters/rate-limit-policy.js";
import {
  createByteBudget,
  createSendGate,
  realAfter,
  type GateTicket,
  type RequestKind,
  type SendGateStats,
} from "./send-gate.js";

/**
 * Bounded, retrying, rate-governed access to storage blobs.
 *
 * Stream-sync blob names are content addressed, so a read or a write of the
 * same key can be repeated without changing the outcome (a second upload of a
 * key keeps the stored copy). That makes a retry of a transient failure safe.
 *
 * Three separate layers (see `send-gate.ts` for the first):
 *  1. the send gate: one gate in front of every request, with a quota input
 *     (429 and a published `RateLimit-Policy`) and a congestion input (503);
 *  2. the retry layer here: only failures that can pass by themselves are
 *     retried (HTTP 5xx and 429, network errors), never other 4xx, with
 *     capped exponential backoff and full jitter, a Retry-After answer as a
 *     floor, and a deadline per operation that covers its wait at the gate and
 *     every transfer. At the deadline the wait ends, the transfer is aborted
 *     and `StorageDeferredError` is thrown, which the publish loop reads as
 *     "leave this work in the durable queue", not as a failure of the data;
 *  3. the byte budget for encoded data not yet uploaded.
 * A wait after a failure is a shared resume time, so every caller waits, and
 * the retry then passes through the gate again like any other request.
 */

export interface StorageAccessPolicy {
  /**
   * A quota known before any response (for tests, or a configured store).
   * The service's own `RateLimit-Policy` replaces it. It paces every kind.
   */
  readonly quota?: QuotaPolicy;
  /**
   * The deadline of one operation, counted from its first request for a place
   * at the gate: its queue wait, its transfers and its waits between tries all
   * spend it. It is a time and not a try count, so a 60 s Retry-After
   * (vana-storage's 429) fits in it. At the deadline a queued request leaves
   * the queue, a running transfer is aborted through its `AbortSignal`, and
   * `StorageDeferredError` is thrown. There is no separate per-request timeout.
   * It also bounds how long one Retry-After may hold the whole gate.
   */
  readonly retryBudgetMs: number;
  /** Upper bound of the wait before the second try; it doubles each time. */
  readonly baseDelayMs: number;
  /** No backoff wait is longer than this. */
  readonly maxDelayMs: number;
  /**
   * Bytes of data not yet uploaded that may sit in memory at once. A part
   * counts twice, as an attachment does: its plain encoded bytes and its
   * ciphertext are both held while the PUT runs. So the default 64 MiB holds
   * 8 parts of 4 MiB. It is the memory ceiling the send gate works under, so
   * a store that is slow or stalled cannot pile up parts. It also caps the
   * send gate's in-flight window: this many bytes over `partBytes`.
   */
  readonly maxBytesInFlight: number;
  /** The usual part size, which turns the byte budget into a window cap. */
  readonly partBytes: number;
  /**
   * The largest object the store accepts. It is storage's own limit, not ours:
   * vana-storage refuses a larger body with PAYLOAD_TOO_LARGE
   * (`DEFAULT_MAX_BLOB_SIZE` in vana-storage `src/config.ts`, set to
   * 104857600 by `MAX_BLOB_SIZE` in its `wrangler.toml`). A reservation for
   * a larger object is refused, since it could never be uploaded.
   */
  readonly maxObjectBytes: number;
  /** Replaceable, with `after`, so tests need not wait. */
  readonly now: () => number;
  /** Runs `fn` after `ms`; the returned function cancels it. */
  readonly after: (ms: number, fn: () => void) => () => void;
  /** Replaceable so tests can pin jitter. Returns a value in [0, 1). */
  readonly random: () => number;
}

export const DEFAULT_STORAGE_ACCESS_POLICY: StorageAccessPolicy = {
  retryBudgetMs: 180_000,
  baseDelayMs: 250,
  maxDelayMs: 4_000,
  maxBytesInFlight: 64 * 1024 * 1024,
  partBytes: 4 * 1024 * 1024,
  maxObjectBytes: 100 * 1024 * 1024,
  now: Date.now,
  after: realAfter,
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
 * A Retry-After header as milliseconds: whole or fractional seconds, or an
 * HTTP date (measured from `nowMs`). `undefined` when it is absent or unreadable.
 */
export function parseRetryAfterHeader(
  value: string | null | undefined,
  nowMs: number,
): number | undefined {
  const text = value?.trim();
  if (!text) return undefined;
  if (/^\d+(\.\d+)?$/.test(text)) return finiteMs(Number(text) * 1000);
  const date = Date.parse(text);
  return Number.isFinite(date) ? Math.max(0, date - nowMs) : undefined;
}

const RETRY_AFTER_IN_BODY = /"retryAfter"\s*:\s*"?(\d+(?:\.\d+)?)"?/;

/** The JSON body's `retryAfter` (seconds), for a browser that cannot read the header. */
export function parseRetryAfterBody(
  text: string | null | undefined,
): number | undefined {
  const match = text ? RETRY_AFTER_IN_BODY.exec(text) : null;
  return match ? finiteMs(Number(match[1]) * 1000) : undefined;
}

/** A wait from the wire is a whole number of milliseconds or nothing. */
function finiteMs(ms: number): number | undefined {
  return Number.isFinite(ms) ? Math.round(ms) : undefined;
}

/**
 * Whether the storage service answered "slow down" (HTTP 429 or 503), which
 * one, and how long it asked to wait. The adapters put `retryAfterMs` on the
 * error they throw; the SDK's own errors carry the JSON body in the message
 * and the adapter's error is its `cause`, so the whole chain is read.
 */
export function throttleOf(
  error: unknown,
  depth = 0,
): { readonly status: 429 | 503; readonly retryAfterMs?: number } | undefined {
  if (typeof error !== "object" || error === null || depth > 3)
    return undefined;
  const record = error as Record<string, unknown>;
  const message = typeof record.message === "string" ? record.message : "";
  const status = statusOf(error);
  const inner = throttleOf(record.cause, depth + 1);
  const own = status === 429 || status === 503 ? status : inner?.status;
  if (own === undefined) return undefined;
  const retryAfterMs =
    typeof record.retryAfterMs === "number" &&
    Number.isFinite(record.retryAfterMs) &&
    record.retryAfterMs >= 0
      ? record.retryAfterMs
      : (parseRetryAfterBody(message) ?? inner?.retryAfterMs);
  return retryAfterMs === undefined
    ? { status: own }
    : { status: own, retryAfterMs };
}

/** What the governor did over one publish, for its single log line. */
export interface SendWindowStats {
  /** The in-flight window when the publish ended. */
  readonly window: number;
  /** The published quota in requests per second, when the service published one. */
  readonly quotaPerSec?: SendGateStats["quotaPerSec"];
  readonly requests: number;
  readonly throttles: number;
  /** Time the shared resume time was pushed out by Retry-After answers. */
  readonly retryAfterWaitMs: number;
  /** Most bytes reserved at once while the window was open. */
  readonly peakBytesInFlight: number;
}

export interface SendRequest {
  /** The kind of request: the quota a service names for it is the one that paces it. */
  readonly kind: RequestKind;
  /** Runs after every wait at the gate, so a stale caller does not send. Its throw is final. */
  readonly beforeAttempt?: () => void;
}

export interface SendGovernor {
  /**
   * One storage request, through the gate, within the retry budget. A
   * transient failure waits (a shared wait, Retry-After as its floor) and goes
   * through the gate again. `operation` gets a signal that aborts at the
   * deadline; it must pass it to the transfer. At the deadline this throws
   * `StorageDeferredError` and no transfer of this call is left running.
   */
  run<T>(
    request: SendRequest,
    operation: (signal: AbortSignal) => Promise<T>,
  ): Promise<T>;
  /**
   * Hold `bytes` of the memory budget until the returned function is called.
   * `objectBytes` is the size of the object this memory becomes, when that
   * differs (an attachment is held twice, as plain and as encrypted bytes).
   * Rejects with `StorageObjectTooLargeError` when that object is over the
   * store's limit.
   */
  reserve(bytes: number, objectBytes?: number): Promise<() => void>;
  /** Watch the governor; `end()` reports what happened since this call. */
  window(): { end(): SendWindowStats };
  /** Follow the quota a service publishes. Returns a function that stops it. */
  follow(source: {
    onRateLimitPolicy?: (l: QuotaListener) => () => void;
  }): () => void;
}

/**
 * Storage did not answer within the retry budget. The data is not at fault:
 * the work stays in the durable queue and the next cycle tries again. Callers
 * must not report it as a failure of the data.
 */
export class StorageDeferredError extends Error {
  readonly status?: number;
  constructor(
    readonly budgetMs: number,
    readonly last?: unknown,
  ) {
    const seconds = Math.round(budgetMs / 1000);
    super(
      last === undefined
        ? `storage unavailable: no answer within ${seconds} s`
        : `storage unavailable: still failing after ${seconds} s of retries (${last instanceof Error ? last.message : String(last)})`,
      last === undefined ? undefined : { cause: last },
    );
    this.name = "StorageDeferredError";
    const status = statusOf(last);
    if (status !== undefined) this.status = status;
  }
}

/** An object larger than the store accepts: it can never be uploaded. */
export class StorageObjectTooLargeError extends Error {
  constructor(
    readonly objectBytes: number,
    readonly limitBytes: number,
  ) {
    super(
      `object of ${objectBytes} bytes is over the storage limit of ${limitBytes} bytes`,
    );
    this.name = "StorageObjectTooLargeError";
  }
}

/** Resolves or rejects with `work`, or rejects with the signal's reason once it aborts. */
function untilAborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    work.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/**
 * One governor: a gate, a retry layer and a byte budget. It stands for one
 * store, so there is one per store (`createStorageStreamSyncBlobs` keeps it
 * with the adapter instance).
 */
export function createStorageAccess(policy: StorageAccessPolicy): SendGovernor {
  const gate = createSendGate({
    maxWindow: Math.max(
      1,
      Math.floor(policy.maxBytesInFlight / policy.partBytes),
    ),
    maxHoldMs: policy.retryBudgetMs,
    now: policy.now,
    after: policy.after,
  });
  if (policy.quota) gate.setQuota({ named: {}, unnamed: policy.quota });
  const windows = new Set<{ peak: number }>();
  const budget = createByteBudget(policy.maxBytesInFlight, (inUse) => {
    for (const open of windows) open.peak = Math.max(open.peak, inUse);
  });
  return {
    reserve(bytes, objectBytes = bytes) {
      if (objectBytes > policy.maxObjectBytes) {
        return Promise.reject(
          new StorageObjectTooLargeError(objectBytes, policy.maxObjectBytes),
        );
      }
      return budget.reserve(bytes);
    },
    follow: (source) =>
      source.onRateLimitPolicy?.((quota) => gate.setQuota(quota)) ?? (() => {}),
    window() {
      const open = { peak: budget.inUse() };
      const before = gate.stats();
      windows.add(open);
      return {
        end() {
          windows.delete(open);
          const after = gate.stats();
          return {
            window: after.window,
            ...(after.quotaPerSec === undefined
              ? {}
              : { quotaPerSec: after.quotaPerSec }),
            requests: after.requests - before.requests,
            throttles: after.throttles - before.throttles,
            retryAfterWaitMs: after.retryAfterWaitMs - before.retryAfterWaitMs,
            peakBytesInFlight: open.peak,
          };
        },
      };
    },
    async run(request, operation) {
      const deadline = policy.now() + policy.retryBudgetMs;
      const expiry = new AbortController();
      const cancelExpiry = policy.after(policy.retryBudgetMs, () =>
        expiry.abort(),
      );
      const { signal } = expiry;
      let last: unknown;
      const deferred = () =>
        new StorageDeferredError(policy.retryBudgetMs, last);
      try {
        for (let attempt = 1; ; attempt++) {
          let ticket: GateTicket;
          try {
            ticket = await gate.admit(request.kind, signal);
          } catch (error) {
            throw signal.aborted ? deferred() : error;
          }
          // The deadline is checked before every attempt, not only after a failure.
          if (signal.aborted || policy.now() >= deadline) {
            ticket.abandon();
            throw deferred();
          }
          // After every wait, so a call that queued or slept while the caller
          // went stale does not start. Its throw is final: it is not retried.
          try {
            request.beforeAttempt?.();
          } catch (error) {
            ticket.abandon();
            throw error;
          }
          try {
            const result = await untilAborted(operation(signal), signal);
            ticket.success();
            return result;
          } catch (error) {
            if (signal.aborted) {
              ticket.abandon();
              throw deferred();
            }
            if (!isTransientStorageError(error)) {
              ticket.abandon();
              throw error;
            }
            last = error;
            const throttle = throttleOf(error);
            if (throttle?.status === 429) {
              ticket.quotaExceeded(throttle.retryAfterMs);
            } else if (throttle?.status === 503) {
              ticket.congested(throttle.retryAfterMs);
            } else {
              ticket.abandon();
            }
            // Backoff and Retry-After are one shared wait, the longer of the
            // two. A wait that would pass the deadline is not waited for.
            const wait = Math.max(
              backoffDelayMs(attempt, policy),
              throttle?.retryAfterMs ?? 0,
            );
            if (policy.now() + wait > deadline) throw deferred();
            gate.holdFor(wait);
          }
        }
      } finally {
        cancelExpiry();
      }
    },
  };
}
