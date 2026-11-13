import { afterEach, describe, expect, it, vi } from "vitest";
import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import {
  createRateLimitPolicyFeed,
  type QuotaListener,
} from "../storage/adapters/rate-limit-policy.js";
import { createStorageStreamSyncBlobs } from "./blobs.js";
import { fakeClock, type FakeClock } from "./fake-clock.test-helper.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  StorageDeferredError,
  StorageObjectTooLargeError,
  backoffDelayMs,
  createStorageAccess,
  isTransientStorageError,
  parseRetryAfterBody,
  parseRetryAfterHeader,
  throttleOf,
  type StorageAccessPolicy,
} from "./storage-retry.js";

const NO_REQUEST = { kind: "put" } as const;
const failed = (status: number) =>
  new Error(`vana-storage download failed: ${status} Whatever`);
const ONE_MINUTE = 60_000;
const throttled = (retryAfterMs?: number) =>
  Object.assign(new Error("storage request failed (429)"), {
    status: 429,
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  });

/** A policy on the test's clock, with the jitter pinned just under its bound. */
const policyOn = (
  clock: FakeClock,
  over: Partial<StorageAccessPolicy> = {},
): StorageAccessPolicy => ({
  ...DEFAULT_STORAGE_ACCESS_POLICY,
  now: clock.now,
  after: clock.after,
  random: () => 0.999,
  ...over,
});

/** What a promise ended with, so it never goes unobserved while time is stepped. */
function outcome<T>(work: Promise<T>) {
  const seen: { ok?: T; error?: unknown; done: boolean } = { done: false };
  void work.then(
    (ok) => Object.assign(seen, { ok, done: true }),
    (error: unknown) => Object.assign(seen, { error, done: true }),
  );
  return seen;
}

/** An operation that ends only when its signal aborts, as a cooperating transfer does. */
const untilSignal = (seen?: { aborted: boolean }) => (signal: AbortSignal) =>
  new Promise<never>((_, reject) => {
    signal.addEventListener("abort", () => {
      if (seen) seen.aborted = true;
      reject(signal.reason);
    });
  });

/** An operation that never ends, as a transfer that ignores its signal. */
const hangs = () => new Promise<never>(() => {});

describe("isTransientStorageError", () => {
  it.each([429, 500, 502, 503, 504])("retries HTTP %i", (status) => {
    expect(isTransientStorageError(failed(status))).toBe(true);
  });

  it.each([400, 401, 403, 404, 408, 409, 410, 422])(
    "does not retry HTTP %i",
    (status) => {
      expect(isTransientStorageError(failed(status))).toBe(false);
    },
  );

  it("reads a numeric status before the message", () => {
    expect(
      isTransientStorageError(
        Object.assign(new Error("download failed: 404"), { status: 503 }),
      ),
    ).toBe(true);
    expect(
      isTransientStorageError(
        Object.assign(new Error("download failed: 503"), { statusCode: 403 }),
      ),
    ).toBe(false);
  });

  it("reads the status of the audience adapter's messages", () => {
    expect(isTransientStorageError(new Error("Storage GET failed (503)"))).toBe(
      true,
    );
    expect(isTransientStorageError(new Error("Storage GET failed (403)"))).toBe(
      false,
    );
    expect(
      isTransientStorageError(new Error("Blob download failed (500)")),
    ).toBe(true);
  });

  it("retries network failures, also behind a cause", () => {
    expect(
      isTransientStorageError(
        new Error("vana-storage public download network error"),
      ),
    ).toBe(true);
    expect(
      isTransientStorageError(
        new TypeError("fetch failed", {
          cause: Object.assign(new Error("read"), { code: "ECONNRESET" }),
        }),
      ),
    ).toBe(true);
    expect(
      isTransientStorageError(
        Object.assign(new Error("stalled"), { name: "TimeoutError" }),
      ),
    ).toBe(true);
  });

  it("never retries a cancelled call or an error it cannot classify", () => {
    expect(
      isTransientStorageError(
        Object.assign(new Error("aborted"), { name: "AbortError" }),
      ),
    ).toBe(false);
    expect(isTransientStorageError(new Error("head hash mismatch"))).toBe(
      false,
    );
    expect(isTransientStorageError("500")).toBe(false);
    expect(isTransientStorageError(undefined)).toBe(false);
  });
});

describe("backoffDelayMs", () => {
  const base = { baseDelayMs: 100, maxDelayMs: 1_000 };

  it("doubles the bound each attempt and caps it", () => {
    const top = { ...base, random: () => 0.999999 };
    expect([1, 2, 3, 4, 5, 9].map((n) => backoffDelayMs(n, top))).toEqual([
      99, 199, 399, 799, 999, 999,
    ]);
  });

  it("draws the wait uniformly below the bound (full jitter)", () => {
    expect(backoffDelayMs(3, { ...base, random: () => 0 })).toBe(0);
    expect(backoffDelayMs(3, { ...base, random: () => 0.5 })).toBe(200);
  });
});

describe("Retry-After parsing", () => {
  it("reads seconds, fractional seconds and an HTTP date", () => {
    expect(parseRetryAfterHeader("60", 0)).toBe(60_000);
    expect(parseRetryAfterHeader("1.5", 0)).toBe(1_500);
    expect(parseRetryAfterHeader("Thu, 01 Jan 1970 00:01:00 GMT", 10_000)).toBe(
      50_000,
    );
    expect(parseRetryAfterHeader("Thu, 01 Jan 1970 00:00:01 GMT", 10_000)).toBe(
      0,
    );
  });

  it("gives nothing for an absent or unreadable header", () => {
    expect(parseRetryAfterHeader(null, 0)).toBeUndefined();
    expect(parseRetryAfterHeader("soon", 0)).toBeUndefined();
  });

  it("reads the JSON body's retryAfter when the header cannot be read", () => {
    expect(
      parseRetryAfterBody('{"error":"RATE_LIMITED","retryAfter":60}'),
    ).toBe(60_000);
    expect(parseRetryAfterBody("not json")).toBeUndefined();
  });

  it("takes no wait that is not a finite number", () => {
    const huge = "9".repeat(400);
    expect(parseRetryAfterHeader(huge, 0)).toBeUndefined();
    expect(parseRetryAfterBody(`{"retryAfter":${huge}}`)).toBeUndefined();
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -5]) {
      expect(
        throttleOf(
          Object.assign(new Error("failed: 429"), { retryAfterMs: bad }),
        ),
      ).toEqual({ status: 429 });
    }
  });

  it("finds a throttle and its wait through the error chain", () => {
    const sdk = new Error(
      'vana-storage upload failed: 429 Too Many Requests - {"retryAfter":60}',
    );
    expect(throttleOf(sdk)).toEqual({ status: 429, retryAfterMs: 60_000 });
    const wrapped = new Error("vana-storage upload network error", {
      cause: Object.assign(new Error("storage request failed (503)"), {
        status: 503,
        retryAfterMs: 1_000,
      }),
    });
    expect(throttleOf(wrapped)).toEqual({ status: 503, retryAfterMs: 1_000 });
    expect(throttleOf(failed(500))).toBeUndefined();
    expect(throttleOf(failed(503))).toEqual({ status: 503 });
  });
});

describe("createStorageAccess", () => {
  it("repeats a transient failure with a growing wait, then returns", async () => {
    const clock = fakeClock();
    const access = createStorageAccess(
      policyOn(clock, { baseDelayMs: 100, maxDelayMs: 1_000 }),
    );
    const sentAt: number[] = [];
    const operation = vi.fn(async () => {
      sentAt.push(clock.now());
      if (sentAt.length < 3) throw failed(500);
      return "ok";
    });
    await expect(clock.drive(access.run(NO_REQUEST, operation))).resolves.toBe(
      "ok",
    );
    expect(sentAt).toEqual([0, 99, 298]);
  });

  it.each([400, 401, 403, 404, 409])(
    "does not retry HTTP %i",
    async (status) => {
      const access = createStorageAccess(policyOn(fakeClock()));
      const operation = vi.fn().mockRejectedValue(failed(status));
      await expect(access.run(NO_REQUEST, operation)).rejects.toThrow(
        String(status),
      );
      expect(operation).toHaveBeenCalledTimes(1);
    },
  );

  it("holds back a later caller while another backs off", async () => {
    const clock = fakeClock();
    const access = createStorageAccess(
      policyOn(clock, {
        baseDelayMs: 1_000,
        maxDelayMs: 1_000,
        random: () => 0.5,
      }),
    );
    const first = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue("first");
    const later = vi.fn(async () => "later");

    const firstResult = access.run(NO_REQUEST, first);
    await clock.advance(0);
    // The first call failed and the shared wait is 500 ms.
    expect(first).toHaveBeenCalledTimes(1);
    const laterResult = access.run(NO_REQUEST, later);
    await clock.advance(499);
    // The later call has not failed, yet it does not send into the overload.
    expect(later).not.toHaveBeenCalled();
    expect(first).toHaveBeenCalledTimes(1);

    await clock.advance(10);
    await expect(Promise.all([firstResult, laterResult])).resolves.toEqual([
      "first",
      "later",
    ]);
    expect(first).toHaveBeenCalledTimes(2);
    expect(later).toHaveBeenCalledTimes(1);
  });

  describe("Retry-After", () => {
    it("makes every caller wait for a 60 s Retry-After, then succeeds", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(policyOn(clock));
      const sent: string[] = [];
      let aCalls = 0;
      const resultA = access.run(NO_REQUEST, async () => {
        sent.push("a");
        if (aCalls++ === 0) throw throttled(ONE_MINUTE);
        return "a";
      });
      await clock.advance(0);
      expect(sent).toEqual(["a"]);
      // B and C have not failed; they still wait out the minute.
      const resultB = access.run(NO_REQUEST, async () => (sent.push("b"), "b"));
      const resultC = access.run(NO_REQUEST, async () => (sent.push("c"), "c"));
      await clock.advance(ONE_MINUTE - 1);
      expect(sent).toEqual(["a"]);
      await clock.advance(5_000);
      await expect(Promise.all([resultA, resultB, resultC])).resolves.toEqual([
        "a",
        "b",
        "c",
      ]);
      expect(sent.sort()).toEqual(["a", "a", "b", "c"]);
    });

    it("honours a Retry-After that came from the JSON body", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(policyOn(clock));
      const sentAt: number[] = [];
      await clock.drive(
        access.run(NO_REQUEST, async () => {
          sentAt.push(clock.now());
          if (sentAt.length === 1) {
            throw new Error(
              'vana-storage upload failed: 429 Too Many Requests - {"error":"RATE_LIMITED","retryAfter":60}',
            );
          }
        }),
      );
      expect(sentAt[1]! - sentAt[0]!).toBe(ONE_MINUTE);
    });

    it("keeps trying through four throttled minutes: the budget is a time, not a count", async () => {
      const clock = fakeClock();
      const operation = vi
        .fn<() => Promise<string>>()
        .mockRejectedValueOnce(throttled(ONE_MINUTE))
        .mockRejectedValueOnce(throttled(ONE_MINUTE))
        .mockRejectedValueOnce(throttled(ONE_MINUTE))
        .mockRejectedValueOnce(throttled(ONE_MINUTE))
        .mockResolvedValue("ok");
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: 4 * ONE_MINUTE + 10_000 }),
      );
      await expect(
        clock.drive(access.run(NO_REQUEST, operation)),
      ).resolves.toBe("ok");
      expect(operation).toHaveBeenCalledTimes(5);
    });

    it("reports the wait and the throttles of a publish window", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(policyOn(clock));
      const window = access.window();
      await clock.drive(
        access.run(
          NO_REQUEST,
          vi
            .fn<() => Promise<string>>()
            .mockRejectedValueOnce(throttled(ONE_MINUTE))
            .mockResolvedValue("ok"),
        ),
      );
      const stats = window.end();
      expect(stats.throttles).toBe(1);
      expect(stats.retryAfterWaitMs).toBe(ONE_MINUTE);
      expect(stats.requests).toBe(2);
      // A 429 is quota, not congestion: the window did not shrink, and the
      // success after the wait grew it.
      expect(stats.window).toBe(2);
    });

    it("defers at once when the wait it asks for passes the deadline, and holds the others no longer than the deadline", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: ONE_MINUTE }),
      );
      const operation = vi.fn().mockRejectedValue(throttled(60 * ONE_MINUTE));
      const first = outcome(access.run(NO_REQUEST, operation));
      await clock.advance(0);
      expect(first.error).toBeInstanceOf(StorageDeferredError);
      expect(operation).toHaveBeenCalledTimes(1);
      expect(clock.now()).toBe(0);
      expect(clock.pending()).toBe(0);
      // A caller that arrives next is held for the budget at most, not for the hour.
      const next = vi.fn(async () => "ok");
      const second = outcome(access.run(NO_REQUEST, next));
      await clock.advance(ONE_MINUTE - 1);
      expect(next).not.toHaveBeenCalled();
      await clock.advance(1);
      // It left the gate at the budget's end; its own deadline is the same moment.
      expect(second.done).toBe(true);
    });
  });

  describe("the deadline", () => {
    it("fails within the retry budget, with a clear error", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: 30_000 }),
      );
      const operation = vi.fn().mockRejectedValue(failed(503));
      const error = await clock
        .drive(access.run(NO_REQUEST, operation))
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(StorageDeferredError);
      expect((error as Error).message).toMatch(
        /storage unavailable: still failing after 30 s.*503/,
      );
      expect(operation.mock.calls.length).toBeGreaterThan(3);
      expect(clock.pending()).toBe(0);
    });

    it("aborts a transfer that hangs, and frees its slot", async () => {
      const clock = fakeClock();
      // The window starts at 1: the hung transfer holds the only slot.
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: 10_000 }),
      );
      const seen = { aborted: false };
      const hung = outcome(access.run(NO_REQUEST, untilSignal(seen)));
      await clock.advance(9_999);
      expect(hung.done).toBe(false);
      await clock.advance(1);
      expect(seen.aborted).toBe(true);
      expect(hung.error).toBeInstanceOf(StorageDeferredError);
      // The slot is free: the next request goes out at once.
      const next = outcome(access.run(NO_REQUEST, async () => "next"));
      await clock.advance(0);
      expect(next.ok).toBe("next");
      expect(clock.pending()).toBe(0);
    });

    it("frees the slot of a transfer that ignores its signal", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: 10_000 }),
      );
      const hung = outcome(access.run(NO_REQUEST, hangs));
      await clock.advance(10_000);
      expect(hung.error).toBeInstanceOf(StorageDeferredError);
      const next = outcome(access.run(NO_REQUEST, async () => "next"));
      await clock.advance(0);
      expect(next.ok).toBe("next");
    });

    it("counts the wait at the gate: a queued request leaves at the deadline and never sends", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(
        policyOn(clock, { retryBudgetMs: 10_000 }),
      );
      const holder = outcome(access.run(NO_REQUEST, hangs));
      const sent = vi.fn(async () => "never");
      const queued = outcome(access.run(NO_REQUEST, sent));
      await clock.advance(9_999);
      expect(queued.done).toBe(false);
      await clock.advance(1);
      expect(queued.error).toBeInstanceOf(StorageDeferredError);
      expect(holder.error).toBeInstanceOf(StorageDeferredError);
      expect(sent).not.toHaveBeenCalled();
      expect(clock.pending()).toBe(0);
    });

    it("lets a paced run finish inside its budget and defers the rest at the deadline", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(
        policyOn(clock, {
          retryBudgetMs: 2_500,
          quota: { limit: 1, windowMs: 1_000 },
        }),
      );
      const results = Array.from({ length: 6 }, (_, i) =>
        outcome(access.run(NO_REQUEST, async () => i)),
      );
      await clock.advance(3_000);
      // Sent at 0, 1 s and 2 s; the rest were still queued at 2.5 s.
      expect(results.filter((r) => r.ok !== undefined)).toHaveLength(3);
      for (const late of results.slice(3)) {
        expect(late.error).toBeInstanceOf(StorageDeferredError);
      }
    });

    it("checks the deadline before every attempt, even when its timer is late", async () => {
      const clock = fakeClock();
      const budget = 600;
      const access = createStorageAccess(
        policyOn(clock, {
          retryBudgetMs: budget,
          baseDelayMs: 1,
          maxDelayMs: 1,
          random: () => 0,
          quota: { limit: 1, windowMs: 1_000 },
          // The expiry timer never fires, as when the event loop is starved;
          // the gate's own waits still do.
          after: (ms, fn) => (ms === budget ? () => {} : clock.after(ms, fn)),
        }),
      );
      const operation = vi.fn().mockRejectedValue(failed(500));
      const done = outcome(access.run(NO_REQUEST, operation));
      // The retry waits for the next token, a second away, past the deadline.
      await clock.advance(2_000);
      expect(done.error).toBeInstanceOf(StorageDeferredError);
      expect(operation).toHaveBeenCalledTimes(1);
    });

    it("leaves no timer behind after a success or a failure", async () => {
      const clock = fakeClock();
      const access = createStorageAccess(policyOn(clock));
      await access.run(NO_REQUEST, async () => "ok");
      expect(clock.pending()).toBe(0);
      await expect(
        access.run(NO_REQUEST, () => Promise.reject(failed(404))),
      ).rejects.toThrow("404");
      expect(clock.pending()).toBe(0);
    });
  });

  it("sends a retry through the gate, like any other request", async () => {
    const clock = fakeClock();
    const access = createStorageAccess(
      policyOn(clock, {
        baseDelayMs: 1,
        maxDelayMs: 1,
        random: () => 0,
        quota: { limit: 2, windowMs: 1_000 },
      }),
    );
    const sentAt: number[] = [];
    let calls = 0;
    const done = access.run(NO_REQUEST, async () => {
      sentAt.push(clock.now());
      if (calls++ < 3) throw failed(500);
    });
    await clock.advance(5_000);
    await done;
    // The backoff is 0, so only the gate spaces the retries: 2 a second.
    expect(sentAt).toEqual([0, 500, 1_000, 1_500]);
  });

  describe("the memory budget", () => {
    const budgeted = (over: Partial<StorageAccessPolicy> = {}) =>
      createStorageAccess(
        policyOn(fakeClock(), {
          maxBytesInFlight: 100,
          maxObjectBytes: 1_000,
          ...over,
        }),
      );

    it("refuses an object over the store's own limit, even when the memory would fit", async () => {
      const access = budgeted({ maxBytesInFlight: 10_000 });
      await expect(access.reserve(10, 1_001)).rejects.toBeInstanceOf(
        StorageObjectTooLargeError,
      );
      await expect(access.reserve(2_000, 900)).resolves.toBeTypeOf("function");
    });

    it("lets an object above the budget through alone, and holds the rest until it is done", async () => {
      const access = budgeted();
      const big = await access.reserve(500, 500); // 5 times the budget, nothing held: it runs
      let small = false;
      const waiting = access.reserve(10).then((release) => {
        small = true;
        return release;
      });
      await Promise.resolve();
      expect(small).toBe(false);
      big();
      (await waiting)();
      expect(small).toBe(true);
    });
  });
});

function adapter(over: Partial<StorageAdapter> = {}): StorageAdapter {
  return {
    upload: vi.fn(async (key: string) => key),
    urlForKey: (key: string) => `https://storage.test/${key}`,
    download: vi.fn(async () => new Uint8Array([1])),
    delete: vi.fn(async () => true),
    exists: vi.fn(async () => true),
    ...over,
  } as StorageAdapter;
}

describe("createStorageStreamSyncBlobs", () => {
  it("retries a read that failed with a 500 and returns the bytes", async () => {
    const clock = fakeClock();
    const download = vi
      .fn()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue(new Uint8Array([7]));
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download }),
      policyOn(clock),
    );
    await expect(clock.drive(blobs.get("scope/blob"))).resolves.toEqual(
      new Uint8Array([7]),
    );
    expect(download).toHaveBeenCalledTimes(2);
  });

  it("reads a missing blob as null, once", async () => {
    const download = vi.fn().mockRejectedValue(failed(404));
    const exists = vi.fn();
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policyOn(fakeClock()),
    );
    await expect(blobs.get("scope/blob")).resolves.toBeNull();
    expect(download).toHaveBeenCalledTimes(1);
    expect(exists).not.toHaveBeenCalled();
  });

  it("never reads a persistent 5xx as a missing blob", async () => {
    const clock = fakeClock();
    const download = vi.fn().mockRejectedValue(failed(500));
    const exists = vi.fn().mockResolvedValue(false);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policyOn(clock, { retryBudgetMs: 10_000 }),
    );
    await expect(clock.drive(blobs.get("scope/blob"))).rejects.toThrow(/500/);
    expect(download.mock.calls.length).toBeGreaterThan(1);
    expect(exists).not.toHaveBeenCalled();
  });

  it("does not retry a refused read", async () => {
    const download = vi.fn().mockRejectedValue(failed(403));
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists: vi.fn().mockResolvedValue(true) }),
      policyOn(fakeClock()),
    );
    await expect(blobs.get("scope/blob")).rejects.toThrow("403");
    expect(download).toHaveBeenCalledTimes(1);
  });

  describe("a read that fails in a way the probe settles", () => {
    it("asks its probe only after its own request has left the gate, so one slot is enough", async () => {
      const clock = fakeClock();
      // The window is 1: a probe that waited for a slot while the read held
      // the only one could never leave.
      const download = vi.fn().mockRejectedValue(failed(403));
      const exists = vi.fn().mockResolvedValue(true);
      const blobs = createStorageStreamSyncBlobs(
        adapter({ download, exists }),
        policyOn(clock),
      );
      const result = outcome(blobs.get("scope/blob"));
      await clock.advance(1_000);
      expect(result.done).toBe(true);
      expect(String(result.error)).toContain("403");
      expect(exists).toHaveBeenCalledTimes(1);
    });

    it("reads the blob as missing when the probe says so", async () => {
      const clock = fakeClock();
      const blobs = createStorageStreamSyncBlobs(
        adapter({
          download: vi.fn().mockRejectedValue(failed(403)),
          exists: vi.fn().mockResolvedValue(false),
        }),
        policyOn(clock),
      );
      const result = outcome(blobs.get("scope/blob"));
      await clock.advance(1_000);
      expect(result).toMatchObject({ done: true, ok: null });
    });
  });

  it("passes the deadline's signal to every transfer and stops a hung one at the deadline", async () => {
    const clock = fakeClock();
    const signals: AbortSignal[] = [];
    const take = (signal?: AbortSignal) => {
      signals.push(signal!);
      return new Promise<never>(() => {});
    };
    const blobs = createStorageStreamSyncBlobs(
      adapter({
        upload: vi.fn((_k: string, _b: Uint8Array, signal?: AbortSignal) =>
          take(signal),
        ),
        download: vi.fn((_u: string, signal?: AbortSignal) => take(signal)),
        exists: vi.fn((_u: string, signal?: AbortSignal) => take(signal)),
      }),
      policyOn(clock, {
        retryBudgetMs: 5_000,
        maxBytesInFlight: 16 * 4 * 1024 * 1024,
      }),
    );
    // Let the window open so all three go out together.
    const all = [
      outcome(blobs.put("s/a", new Uint8Array([1]))),
      outcome(blobs.get("s/b")),
      outcome(blobs.exists("s/c")),
    ];
    await clock.advance(0);
    expect(signals.length).toBe(1); // window 1: one at a time
    await clock.advance(5_000);
    expect(signals[0]!.aborted).toBe(true);
    for (const result of all) {
      expect(result.error).toBeInstanceOf(StorageDeferredError);
    }
  });

  describe("two wrappers on one adapter", () => {
    it("share one gate: the second waits for the first's slot", async () => {
      const clock = fakeClock();
      let release!: () => void;
      const upload = vi
        .fn()
        .mockImplementationOnce(
          () =>
            new Promise<string>((resolve) => (release = () => resolve("u"))),
        )
        .mockResolvedValue("u");
      const shared = adapter({ upload });
      const one = createStorageStreamSyncBlobs(shared, policyOn(clock));
      const two = createStorageStreamSyncBlobs(shared, policyOn(clock));
      const first = outcome(one.put("s/a", new Uint8Array([1])));
      const second = outcome(two.put("s/b", new Uint8Array([2])));
      await clock.advance(1_000);
      expect(upload).toHaveBeenCalledTimes(1);
      release();
      await clock.advance(0);
      expect(upload).toHaveBeenCalledTimes(2);
      expect(first.done && second.done).toBe(true);
      expect(one.governor).toBe(two.governor);
    });

    it("do not share a gate across two adapters", async () => {
      const clock = fakeClock();
      const one = createStorageStreamSyncBlobs(adapter(), policyOn(clock));
      const two = createStorageStreamSyncBlobs(adapter(), policyOn(clock));
      expect(one.governor).not.toBe(two.governor);
    });
  });

  describe("an upload that is no longer wanted", () => {
    /** The caller's guard: throws once the caller has gone stale. */
    const staleness = () => {
      const state = { stale: false };
      return {
        state,
        guard: () => {
          if (state.stale) throw new Error("connection purged");
        },
      };
    };

    it("does not start an upload that waited at the gate while the caller went stale", async () => {
      // The gate lets one request out a second; B waits there, the caller goes
      // stale during the wait, and B's request must not start.
      const clock = fakeClock();
      const upload = vi.fn(async (key: string) => key);
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policyOn(clock, { quota: { limit: 1, windowMs: 1_000 } }),
      );
      const { state, guard } = staleness();
      await clock.drive(blobs.put("scope/a", new Uint8Array([1]), guard));
      const putB = outcome(blobs.put("scope/b", new Uint8Array([2]), guard));
      await clock.advance(500);
      state.stale = true;
      await clock.advance(1_000);
      expect(String(putB.error)).toContain("connection purged");
      expect(upload.mock.calls.map(([key]) => key)).toEqual(["scope/a"]);
    });

    it("makes no second attempt when the caller went stale during the retry delay", async () => {
      const clock = fakeClock();
      const upload = vi.fn().mockRejectedValueOnce(failed(500));
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policyOn(clock, { baseDelayMs: 100 }),
      );
      const { state, guard } = staleness();
      const put = outcome(blobs.put("scope/a", new Uint8Array([1]), guard));
      await clock.advance(10);
      expect(upload).toHaveBeenCalledTimes(1);
      state.stale = true;
      await clock.advance(1_000);
      expect(String(put.error)).toContain("connection purged");
      expect(upload).toHaveBeenCalledTimes(1);
    });

    it("still retries when the caller is current after the retry delay", async () => {
      const clock = fakeClock();
      const upload = vi.fn().mockRejectedValueOnce(failed(500));
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policyOn(clock, { baseDelayMs: 100 }),
      );
      await clock.drive(
        blobs.put("scope/a", new Uint8Array([1]), staleness().guard),
      );
      expect(upload).toHaveBeenCalledTimes(2);
    });
  });

  it("retries a failed upload and still ignores a conflict", async () => {
    const clock = fakeClock();
    const upload = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("vana-storage upload failed: 503 Unavailable"),
      )
      .mockResolvedValue("url");
    const blobs = createStorageStreamSyncBlobs(
      adapter({ upload }),
      policyOn(clock),
    );
    await clock.drive(blobs.put("scope/blob", new Uint8Array([1])));
    expect(upload).toHaveBeenCalledTimes(2);

    const conflict = vi
      .fn()
      .mockRejectedValue(new StoredBlobConflictError("k"));
    await createStorageStreamSyncBlobs(
      adapter({ upload: conflict }),
      policyOn(clock),
    ).put("scope/blob", new Uint8Array([2]));
    expect(conflict).toHaveBeenCalledTimes(1);
  });

  it("sends uploads, reads and probes through one gate", async () => {
    const clock = fakeClock();
    const sentAt: number[] = [];
    const stamp = () => sentAt.push(clock.now());
    const blobs = createStorageStreamSyncBlobs(
      adapter({
        upload: vi.fn(async () => (stamp(), "url")),
        download: vi.fn(async () => (stamp(), new Uint8Array([1]))),
        exists: vi.fn(async () => (stamp(), true)),
      }),
      policyOn(clock, { quota: { limit: 2, windowMs: 1_000 } }),
    );
    const all = Promise.all([
      blobs.put("s/a", new Uint8Array([1])),
      blobs.get("s/b"),
      blobs.exists("s/c"),
    ]);
    await clock.advance(2_000);
    await all;
    expect(sentAt).toEqual([0, 500, 1_000]);
  });
});

describe("createStorageStreamSyncBlobs and a published quota", () => {
  it("paces its requests to the quota the adapter reports, and to nothing before", async () => {
    const clock = fakeClock();
    const sentAt: number[] = [];
    let report: QuotaListener | undefined;
    const blobs = createStorageStreamSyncBlobs(
      adapter({
        upload: vi.fn(async () => (sentAt.push(clock.now()), "url")),
        onRateLimitPolicy: (listener) => {
          report = listener;
          return () => {};
        },
      }),
      policyOn(clock),
    );
    // No quota yet: nothing to pace to, the window alone decides.
    await blobs.put("s/a", new Uint8Array([1]));
    expect(sentAt).toEqual([0]);
    report!({ named: {}, unnamed: { limit: 1, windowMs: 2_000 } });
    const rest = Promise.all([
      blobs.put("s/b", new Uint8Array([1])),
      blobs.put("s/c", new Uint8Array([1])),
      blobs.put("s/d", new Uint8Array([1])),
    ]);
    await clock.advance(10_000);
    await rest;
    expect(sentAt).toEqual([0, 0, 2_000, 4_000]);
  });
});

describe("createStorageStreamSyncBlobs and the header storage sends", () => {
  /** A blob store whose adapter learns its quotas from a real response header. */
  async function storeAnnouncing(header: string) {
    const clock = fakeClock();
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("", { headers: { "ratelimit-policy": header } }),
      ),
    );
    const feed = createRateLimitPolicyFeed();
    await feed.fetch("https://storage.test/");
    const sent: { kind: string; at: number }[] = [];
    const blobs = createStorageStreamSyncBlobs(
      adapter({
        upload: vi.fn(
          async () => (sent.push({ kind: "put", at: clock.now() }), "url"),
        ),
        download: vi.fn(
          async () => (
            sent.push({ kind: "get", at: clock.now() }),
            new Uint8Array([1])
          ),
        ),
        exists: vi.fn(
          async () => (sent.push({ kind: "head", at: clock.now() }), true),
        ),
        onRateLimitPolicy: feed.subscribe,
      }),
      policyOn(clock),
    );
    const times = (kind: string) =>
      sent.filter((s) => s.kind === kind).map((s) => s.at);
    return { clock, blobs, times };
  }

  afterEach(() => vi.unstubAllGlobals());

  it("sends a first import's 105 parts at the put policy, not the delete policy, with reads unpaced", async () => {
    const { clock, blobs, times } = await storeAnnouncing(
      '"put";q=240;w=60, "delete";q=30;w=60',
    );
    const parts = Array.from({ length: 105 }, (_, i) =>
      blobs.put(`s/p${i}`, new Uint8Array([1])),
    );
    const reads = [blobs.get("s/a"), blobs.exists("s/b")];
    await clock.advance(300_000);
    await Promise.all([...parts, ...reads]);
    // One PUT every 250 ms: the last of 105 leaves at 26 s. The delete
    // policy would put it at 208 s.
    expect(times("put")).toHaveLength(105);
    expect(Math.max(...times("put"))).toBe(26_000);
    // Storage limits neither: they leave at once, ahead of the queued PUTs.
    expect(times("get")).toEqual([0]);
    expect(times("head")).toEqual([0]);
  });

  it("follows the 600 a minute put policy", async () => {
    const { clock, blobs, times } = await storeAnnouncing('"put";q=600;w=60');
    const parts = Array.from({ length: 105 }, (_, i) =>
      blobs.put(`s/p${i}`, new Uint8Array([1])),
    );
    await clock.advance(300_000);
    await Promise.all(parts);
    expect(Math.max(...times("put"))).toBe(10_400);
  });
});

describe("createStorageStreamSyncBlobs.exists", () => {
  it("answers from the storage probe and never reads the body", async () => {
    const download = vi.fn(async () => new Uint8Array([1, 2, 3]));
    const exists = vi.fn(async () => true);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policyOn(fakeClock()),
    );
    await expect(blobs.exists("scope/blob")).resolves.toBe(true);
    expect(exists).toHaveBeenCalledTimes(1);
    expect(download).not.toHaveBeenCalled();
  });

  it("reads a probe answering not found as missing", async () => {
    const exists = vi.fn(async () => false);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ exists }),
      policyOn(fakeClock()),
    );
    await expect(blobs.exists("scope/blob")).resolves.toBe(false);
  });

  it("retries a probe that failed with a 500, then answers", async () => {
    const clock = fakeClock();
    const exists = vi
      .fn()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue(true);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ exists }),
      policyOn(clock),
    );
    await expect(clock.drive(blobs.exists("scope/blob"))).resolves.toBe(true);
    expect(exists).toHaveBeenCalledTimes(2);
  });

  it.each([401, 403])(
    "fails at once on a probe refused with %i, never as missing",
    async (status) => {
      const exists = vi.fn().mockRejectedValue(failed(status));
      const blobs = createStorageStreamSyncBlobs(
        adapter({ exists }),
        policyOn(fakeClock()),
      );
      await expect(blobs.exists("scope/blob")).rejects.toThrow(String(status));
      expect(exists).toHaveBeenCalledTimes(1);
    },
  );

  it("throws a persistent 5xx probe after its retry budget, never as missing", async () => {
    const clock = fakeClock();
    const exists = vi.fn().mockRejectedValue(failed(500));
    const blobs = createStorageStreamSyncBlobs(
      adapter({ exists }),
      policyOn(clock, { retryBudgetMs: 10_000 }),
    );
    await expect(clock.drive(blobs.exists("scope/blob"))).rejects.toThrow(
      /500/,
    );
    expect(exists.mock.calls.length).toBeGreaterThan(1);
  });
});
