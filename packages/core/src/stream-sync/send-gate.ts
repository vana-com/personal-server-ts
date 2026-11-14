/**
 * The send gate of one blob store: the one place a storage request waits
 * before it leaves this device, and the byte budget that bounds memory.
 *
 * The gate takes two inputs, because the server gives two different signals
 * and they need different responses:
 *
 *  - Quota (HTTP 429, and the `RateLimit-Policy` header when the service
 *    publishes one). Quota is a rate the server will accept: when a policy is
 *    known, requests are paced to it with tokens, never above it. The policy
 *    names the kind of request it limits, so each kind has its own tokens and
 *    a kind no policy names is not paced. A 429 only
 *    delays every caller until its Retry-After: it says the quota is spent,
 *    not that the path is congested, so it does not shrink the window.
 *    Tokens are spent when a request is sent, so a reply that arrives out of
 *    order cannot give back tokens already spent. With no policy known there
 *    is nothing to pace to, so there are no tokens.
 *  - Congestion (HTTP 503). The in-flight window is how many requests may be
 *    open at once. It follows TCP congestion control (RFC 5681). It starts at 1
 *    and doubles after each window's worth of successes (slow start) until the
 *    first 503 or the first 429. A 503 halves it and sets the slow start
 *    threshold there; a 429 sets the threshold at the window as it is. From
 *    the threshold on, the window grows by one after a window's worth of
 *    successes and halves on a 503 (AIMD, congestion avoidance). The ramp is
 *    not re-entered. Its cap is the memory budget divided by the part size.
 *    Latency is not a signal yet: that needs a measured baseline from the real
 *    store.
 *
 * A request waits in one FIFO queue, served by one loop, and leaves when all
 * three hold: the window has a free slot, the shared resume time has passed
 * (Retry-After, and the retry layer's backoff), and a token is free if a
 * policy is known. A retry enters the same queue, so it cannot skip any of
 * them. A caller's wait in the queue ends when its signal aborts.
 *
 * Retry is a separate layer, in `storage-retry.ts`: it decides what to do
 * after a failure and then re-enters this gate.
 */

import {
  quotaFor,
  type QuotaPolicies,
  type QuotaPolicy,
} from "../storage/adapters/rate-limit-policy.js";

/**
 * The kinds of request the gate paces. A service's quota names the kind it
 * limits (vana-storage: `put` and `delete`), so a request waits only for the
 * quota of its own kind. There is no `delete` here: nothing deletes through
 * the gate.
 */
export type RequestKind = "put" | "get" | "head";
const REQUEST_KINDS: readonly RequestKind[] = ["put", "get", "head"];

export interface SendGatePolicy {
  /**
   * The largest in-flight window: the memory budget divided by the part size.
   * It is a ceiling that protects memory, not an estimate of what the server
   * can take; the window earns its way up to it.
   */
  readonly maxWindow: number;
  /**
   * The longest a wait the server asked for (Retry-After) may hold every
   * caller. A longer ask is cut to this, so one answer cannot stall the store
   * for longer than a caller is willing to wait; the caller that needs more
   * than its own deadline allows defers.
   */
  readonly maxHoldMs: number;
  /** Replaceable, with `after`, so tests need not wait. */
  readonly now: () => number;
  /** Runs `fn` after `ms`; the returned function cancels it. */
  readonly after: (ms: number, fn: () => void) => () => void;
}

/** A timer that does not keep the process alive. */
export const realAfter: SendGatePolicy["after"] = (ms, fn) => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return () => clearTimeout(timer);
};

export const DEFAULT_SEND_GATE_POLICY: SendGatePolicy = {
  maxWindow: 16,
  maxHoldMs: 180_000,
  now: Date.now,
  after: realAfter,
};

/** What one request was sent under. Settle it exactly once; later calls do nothing. */
export interface GateTicket {
  /** It succeeded: the window may grow. */
  success(): void;
  /**
   * HTTP 429: the quota is spent. Every caller waits for `retryAfterMs`; the
   * window does not change.
   */
  quotaExceeded(retryAfterMs?: number): void;
  /**
   * HTTP 503: congestion. The window halves (once per decrease epoch, so the
   * answers to requests sent before the first halving do not compound it),
   * and every caller waits for `retryAfterMs`.
   */
  congested(retryAfterMs?: number): void;
  /** It ended with no signal about the server (a final error, or a cancel): the slot is freed. */
  abandon(): void;
}

export interface SendGateStats {
  /** The in-flight window now. */
  readonly window: number;
  /** Requests that left the gate. */
  readonly requests: number;
  /** HTTP 429 and 503 answers seen. */
  readonly throttles: number;
  /** Time the shared resume time was pushed out by Retry-After answers. */
  readonly retryAfterWaitMs: number;
  /** The quota that paces each kind, in requests per second; a kind no quota paces is absent. */
  readonly quotaPerSec?: Readonly<Partial<Record<RequestKind, number>>>;
}

export interface SendGate {
  /**
   * Resolves when the request may leave; waiters leave in the order they
   * asked. Rejects with the signal's reason, and leaves the queue, if the
   * signal aborts first.
   */
  admit(kind: RequestKind, signal?: AbortSignal): Promise<GateTicket>;
  /** The quotas the service published, or `undefined` for none. */
  setQuota(quotas: QuotaPolicies | undefined): void;
  /** No request leaves before `now + ms`, whoever asks. Never moves it earlier. Not counted as a server ask. */
  holdFor(ms: number): void;
  stats(): SendGateStats;
}

export function createSendGate(
  overrides: Partial<SendGatePolicy> = {},
): SendGate {
  const policy = { ...DEFAULT_SEND_GATE_POLICY, ...overrides };
  if (!Number.isInteger(policy.maxWindow) || policy.maxWindow < 1) {
    throw new RangeError("send gate: maxWindow must be a whole number above 0");
  }
  if (!(policy.maxHoldMs >= 0) || !Number.isFinite(policy.maxHoldMs)) {
    throw new RangeError("send gate: maxHoldMs must be a finite time");
  }
  // Congestion state. The window doubles while it is below `ssthresh` (slow
  // start) and grows by one from there (congestion avoidance). The threshold
  // is unset until the first throttle answer.
  let window = 1;
  let ssthresh = Infinity;
  let epoch = 0;
  let streak = 0;
  let inFlight = 0;
  // Quota state, one bucket per kind a quota paces: tokens are spent when a
  // request leaves and never given back.
  let quotas: QuotaPolicies | undefined;
  const buckets = new Map<string, Bucket>();
  // Shared wait.
  let resumeAt = 0;
  // Counters.
  let requests = 0;
  let throttles = 0;
  let retryAfterWaitMs = 0;

  interface Bucket {
    quota: QuotaPolicy;
    tokens: number;
    refilledAt: number;
  }
  interface Waiter {
    readonly kind: RequestKind;
    resolve: (ticket: GateTicket) => void;
    reject: (reason: unknown) => void;
    leave?: () => void;
  }
  const queue: Waiter[] = [];
  let pumping = false;
  let wake: (() => void) | undefined;

  const refill = (bucket: Bucket) => {
    const now = policy.now();
    bucket.tokens = Math.min(
      1,
      bucket.tokens +
        ((now - bucket.refilledAt) * bucket.quota.limit) /
          bucket.quota.windowMs,
    );
    bucket.refilledAt = now;
  };

  // The bucket that paces `kind`, or none when no quota names it. A bucket
  // seen for the first time starts with its one token free.
  const bucketFor = (kind: RequestKind): Bucket | undefined => {
    const found = quotas && quotaFor(quotas, kind);
    if (!found) return undefined;
    let bucket = buckets.get(found.bucket);
    if (!bucket) {
      bucket = { quota: found.quota, tokens: 1, refilledAt: policy.now() };
      buckets.set(found.bucket, bucket);
    }
    refill(bucket);
    return bucket;
  };

  // Waits until `wakeLoop` is called, or `ms` have passed.
  const idle = (ms?: number) =>
    new Promise<void>((resolve) => {
      let cancel: (() => void) | undefined;
      wake = () => {
        cancel?.();
        wake = undefined;
        resolve();
      };
      if (ms !== undefined) cancel = policy.after(Math.ceil(ms), wake);
    });

  const wakeLoop = () => wake?.();

  // One loop releases the waiters, so every condition is read again after
  // every wait: a Retry-After that arrives while waiters sleep holds all of
  // them, and they leave one token apart afterwards, never as one burst. A
  // change of quota, window or resume time wakes it, so no wait outlives the
  // state it was computed from.
  async function pump(): Promise<void> {
    if (pumping) return;
    pumping = true;
    try {
      while (queue.length > 0) {
        if (inFlight >= window) {
          // A settled request or a larger window wakes the loop.
          await idle();
          continue;
        }
        const resumeWait = resumeAt - policy.now();
        if (resumeWait > 0) {
          await idle(resumeWait);
          continue;
        }
        // The first waiter, in order, that no quota holds back: a request of
        // a kind with no quota does not wait behind one that is paced.
        let at = -1;
        let tokenWait = Infinity;
        for (let i = 0; i < queue.length; i++) {
          const bucket = bucketFor(queue[i]!.kind);
          if (!bucket || bucket.tokens >= 1) {
            at = i;
            break;
          }
          tokenWait = Math.min(
            tokenWait,
            ((1 - bucket.tokens) * bucket.quota.windowMs) / bucket.quota.limit,
          );
        }
        if (at < 0) {
          // Whole milliseconds, so a fractional wait cannot leave the loop
          // asleep for less than it needs and spinning.
          await idle(tokenWait);
          continue;
        }
        const [next] = queue.splice(at, 1) as [Waiter];
        const bucket = bucketFor(next.kind);
        if (bucket) bucket.tokens -= 1;
        inFlight += 1;
        requests += 1;
        next.leave?.();
        next.resolve(ticketFor(next.kind));
      }
    } finally {
      pumping = false;
    }
  }

  function hold(ms: number, serverAsked: boolean): void {
    // Never trust a wait without a bound: it is a number from the wire.
    const bounded = Number.isFinite(ms)
      ? Math.min(Math.max(0, ms), policy.maxHoldMs)
      : 0;
    const until = policy.now() + bounded;
    if (until > resumeAt) {
      if (serverAsked) {
        retryAfterWaitMs += until - Math.max(resumeAt, policy.now());
      }
      resumeAt = until;
      wakeLoop();
    }
  }

  function halve(): void {
    epoch += 1;
    streak = 0;
    window = Math.max(1, Math.floor(window / 2));
    ssthresh = window;
  }

  function ticketFor(kind: RequestKind): GateTicket {
    const ticketEpoch = epoch;
    let settled = false;
    const settle = (): boolean => {
      if (settled) return false;
      settled = true;
      inFlight -= 1;
      return true;
    };
    return {
      success() {
        if (!settle()) return;
        // Only a request sent in the current epoch counts toward growth.
        if (ticketEpoch === epoch && ++streak >= window) {
          streak = 0;
          window =
            window < ssthresh
              ? Math.min(policy.maxWindow, ssthresh, window * 2)
              : Math.min(policy.maxWindow, window + 1);
        }
        wakeLoop();
      },
      quotaExceeded(retryAfterMs) {
        if (!settle()) return;
        throttles += 1;
        // The service's rate is reached: the ramp ends where it is. The window
        // does not shrink.
        ssthresh = Math.min(ssthresh, window);
        // The tokens spent are not given back, and none is free until the
        // wait is over.
        const bucket = bucketFor(kind);
        if (bucket) bucket.tokens = 0;
        if (retryAfterMs !== undefined) hold(retryAfterMs, true);
        wakeLoop();
      },
      congested(retryAfterMs) {
        if (!settle()) return;
        throttles += 1;
        // The answers to requests sent before the first halving do not compound it.
        if (ticketEpoch === epoch) halve();
        if (retryAfterMs !== undefined) hold(retryAfterMs, true);
        wakeLoop();
      },
      abandon() {
        if (!settle()) return;
        wakeLoop();
      },
    };
  }

  // Requests per second of each kind a quota paces.
  const quotaRates = (): Pick<SendGateStats, "quotaPerSec"> => {
    const rates: Partial<Record<RequestKind, number>> = {};
    for (const kind of REQUEST_KINDS) {
      const found = quotas && quotaFor(quotas, kind);
      if (found)
        rates[kind] = (found.quota.limit * 1000) / found.quota.windowMs;
    }
    return Object.keys(rates).length > 0 ? { quotaPerSec: rates } : {};
  };

  return {
    admit: (kind, signal) => {
      if (signal?.aborted) return Promise.reject(signal.reason);
      return new Promise((resolve, reject) => {
        const waiter: Waiter = { kind, resolve, reject };
        if (signal) {
          const onAbort = () => {
            const at = queue.indexOf(waiter);
            if (at < 0) return;
            queue.splice(at, 1);
            reject(signal.reason);
            // The loop may be asleep on this waiter's wait: let it look again.
            wakeLoop();
          };
          signal.addEventListener("abort", onAbort, { once: true });
          waiter.leave = () => signal.removeEventListener("abort", onAbort);
        }
        queue.push(waiter);
        // A loop asleep on another kind's token must look at this waiter too.
        wakeLoop();
        void pump();
      });
    },
    setQuota(next) {
      // Tokens earned at the old rate are kept; a kind the new quotas do not
      // pace loses its bucket, and one they pace for the first time gets a
      // new bucket with its one token free.
      for (const [name, bucket] of buckets) {
        refill(bucket);
        const quota = REQUEST_KINDS.map(
          (kind) => next && quotaFor(next, kind),
        ).find((found) => found?.bucket === name)?.quota;
        if (quota) bucket.quota = quota;
        else buckets.delete(name);
      }
      quotas = next;
      wakeLoop();
    },
    holdFor: (ms) => hold(ms, false),
    stats: () => ({
      window,
      requests,
      throttles,
      retryAfterWaitMs,
      ...quotaRates(),
    }),
  };
}

export interface ByteBudget {
  /**
   * Resolves with a release function once `bytes` fit under the budget. A
   * request larger than the whole budget waits until nothing else is held,
   * then runs alone: it never waits for ever. Waiters are served in order.
   * The release is safe to call twice.
   */
  reserve(bytes: number): Promise<() => void>;
  readonly inUse: () => number;
}

export function createByteBudget(
  limitBytes: number,
  onChange?: (inUse: number) => void,
): ByteBudget {
  if (!Number.isFinite(limitBytes) || limitBytes < 1) {
    throw new RangeError("send gate: the byte budget must be above 0");
  }
  let inUse = 0;
  const waiting: { bytes: number; grant: () => void }[] = [];
  const fits = (bytes: number) => inUse === 0 || inUse + bytes <= limitBytes;
  const drain = () => {
    while (waiting.length > 0 && fits(waiting[0]!.bytes)) {
      const next = waiting.shift()!;
      inUse += next.bytes;
      onChange?.(inUse);
      next.grant();
    }
  };
  return {
    inUse: () => inUse,
    reserve(bytes) {
      const size = Math.max(0, bytes);
      const hold = () => {
        let released = false;
        return () => {
          if (released) return;
          released = true;
          inUse -= size;
          drain();
        };
      };
      if (waiting.length === 0 && fits(size)) {
        inUse += size;
        onChange?.(inUse);
        return Promise.resolve(hold());
      }
      return new Promise((resolve) => {
        waiting.push({ bytes: size, grant: () => resolve(hold()) });
      });
    },
  };
}
