import { describe, expect, it, vi } from "vitest";
import {
  StoredBlobConflictError,
  type StorageAdapter,
} from "../storage/adapters/interface.js";
import { createStorageStreamSyncBlobs } from "./blobs.js";
import {
  DEFAULT_STORAGE_ACCESS_POLICY,
  backoffDelayMs,
  createConcurrencyLimit,
  createStorageAccess,
  isTransientStorageError,
  type StorageAccessPolicy,
} from "./storage-retry.js";

const failed = (status: number) =>
  new Error(`vana-storage download failed: ${status} Whatever`);
const policy = (
  over: Partial<StorageAccessPolicy> = {},
): StorageAccessPolicy => ({
  ...DEFAULT_STORAGE_ACCESS_POLICY,
  sleep: async () => {},
  random: () => 0.999,
  ...over,
});

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

/** A virtual clock: sleeping advances time and never waits. */
function virtualClock() {
  const clock = { time: 0, waits: [] as number[] };
  return {
    clock,
    now: () => clock.time,
    sleep: async (ms: number) => {
      clock.waits.push(ms);
      clock.time += ms;
    },
  };
}

describe("createStorageAccess", () => {
  it("repeats a transient failure with a growing wait, then returns", async () => {
    const t = virtualClock();
    const run = createStorageAccess(
      policy({
        baseDelayMs: 100,
        maxDelayMs: 1_000,
        now: t.now,
        sleep: t.sleep,
      }),
    );
    const operation = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(failed(500))
      .mockRejectedValueOnce(failed(429))
      .mockResolvedValue("ok");
    await expect(run(operation)).resolves.toBe("ok");
    expect(operation).toHaveBeenCalledTimes(3);
    expect(t.clock.waits).toEqual([99, 199]);
  });

  it("stops after maxAttempts and throws the last error", async () => {
    const run = createStorageAccess(policy({ maxAttempts: 4 }));
    const operation = vi.fn().mockRejectedValue(failed(503));
    await expect(run(operation)).rejects.toThrow("503");
    expect(operation).toHaveBeenCalledTimes(4);
  });

  it.each([400, 401, 403, 404, 409])(
    "does not retry HTTP %i",
    async (status) => {
      const run = createStorageAccess(policy());
      const operation = vi.fn().mockRejectedValue(failed(status));
      await expect(run(operation)).rejects.toThrow(String(status));
      expect(operation).toHaveBeenCalledTimes(1);
    },
  );

  it("holds back a later caller while another backs off", async () => {
    let time = 0;
    const sleeping: { ms: number; wake: () => void }[] = [];
    const run = createStorageAccess(
      policy({
        maxConcurrent: 2,
        baseDelayMs: 1_000,
        maxDelayMs: 1_000,
        random: () => 0.5,
        now: () => time,
        sleep: (ms) => new Promise<void>((wake) => sleeping.push({ ms, wake })),
      }),
    );
    const flush = async () => {
      for (let i = 0; i < 10; i++) await Promise.resolve();
    };
    const first = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue("first");
    const later = vi.fn(async () => "later");

    const firstResult = run(first);
    await flush();
    // The first call failed and waits 500 ms before its second try.
    expect(first).toHaveBeenCalledTimes(1);
    const laterResult = run(later);
    await flush();
    // The later call has not failed, yet it does not send into the overload.
    expect(later).not.toHaveBeenCalled();
    expect(sleeping.map((s) => s.ms)).toEqual([500, 500]);

    time = 500;
    sleeping.forEach((s) => s.wake());
    await expect(Promise.all([firstResult, laterResult])).resolves.toEqual([
      "first",
      "later",
    ]);
    expect(first).toHaveBeenCalledTimes(2);
    expect(later).toHaveBeenCalledTimes(1);
  });
});

describe("createConcurrencyLimit", () => {
  it("runs at most the limit at once and finishes every operation", async () => {
    const limit = createConcurrencyLimit(4);
    let active = 0;
    let peak = 0;
    const results = await Promise.all(
      Array.from({ length: 30 }, (_, i) =>
        limit(async () => {
          active++;
          peak = Math.max(peak, active);
          await new Promise((resolve) => setTimeout(resolve, 1));
          active--;
          return i;
        }),
      ),
    );
    expect(peak).toBe(4);
    expect(results).toEqual(Array.from({ length: 30 }, (_, i) => i));
  });

  it("frees the slot when an operation throws", async () => {
    const limit = createConcurrencyLimit(1);
    await expect(
      limit(async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    await expect(limit(async () => "next")).resolves.toBe("next");
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
    const download = vi
      .fn()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue(new Uint8Array([7]));
    const blobs = createStorageStreamSyncBlobs(adapter({ download }), policy());
    await expect(blobs.get("scope/blob")).resolves.toEqual(new Uint8Array([7]));
    expect(download).toHaveBeenCalledTimes(2);
  });

  it("reads a missing blob as null, once", async () => {
    const download = vi.fn().mockRejectedValue(failed(404));
    const exists = vi.fn();
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policy(),
    );
    await expect(blobs.get("scope/blob")).resolves.toBeNull();
    expect(download).toHaveBeenCalledTimes(1);
    expect(exists).not.toHaveBeenCalled();
  });

  it("never reads a persistent 5xx as a missing blob", async () => {
    const download = vi.fn().mockRejectedValue(failed(500));
    const exists = vi.fn().mockResolvedValue(false);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policy({ maxAttempts: 3 }),
    );
    await expect(blobs.get("scope/blob")).rejects.toThrow("500");
    expect(download).toHaveBeenCalledTimes(3);
    expect(exists).not.toHaveBeenCalled();
  });

  it("does not retry a refused read", async () => {
    const download = vi.fn().mockRejectedValue(failed(403));
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists: vi.fn().mockResolvedValue(true) }),
      policy(),
    );
    await expect(blobs.get("scope/blob")).rejects.toThrow("403");
    expect(download).toHaveBeenCalledTimes(1);
  });

  it("serves a burst of reads that storage refuses above 4 in flight", async () => {
    let inFlight = 0;
    let refused = 0;
    const download = vi.fn(async () => {
      inFlight++;
      try {
        await new Promise((resolve) => setTimeout(resolve, 2));
        if (inFlight > 4) {
          refused++;
          throw failed(500);
        }
        return new Uint8Array([1]);
      } finally {
        inFlight--;
      }
    });
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download }),
      policy({ maxConcurrent: 4 }),
    );
    const results = await Promise.all(
      Array.from({ length: 40 }, (_, i) => blobs.get(`scope/part-${i}`)),
    );
    expect(results.every((r) => r !== null)).toBe(true);
    expect(refused).toBe(0);
  });

  describe("limits that are not a positive whole number", () => {
    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, undefined])(
      "refuses %s for maxConcurrentPuts and maxConcurrent",
      (bad) => {
        expect(() =>
          createStorageStreamSyncBlobs(
            adapter(),
            policy({ maxConcurrentPuts: bad as number }),
          ),
        ).toThrow(/maxConcurrentPuts must be a positive whole number/);
        expect(() =>
          createStorageStreamSyncBlobs(
            adapter(),
            policy({ maxConcurrent: bad as number }),
          ),
        ).toThrow(/maxConcurrent must be a positive whole number/);
        expect(() =>
          createStorageAccess(policy({ maxConcurrent: bad as number })),
        ).toThrow(/maxConcurrent must be a positive whole number/);
      },
    );

    it("refuses an explicit undefined that the policy spread would let through", () => {
      expect(() =>
        createStorageStreamSyncBlobs(adapter(), {
          maxConcurrentPuts: undefined,
        }),
      ).toThrow(/maxConcurrentPuts/);
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
    const deferred = () => {
      let release!: () => void;
      const promise = new Promise<void>((r) => (release = r));
      return { promise, release };
    };
    /** Records how `promise` settled, so a test can wait on it with `vi.waitFor`. */
    const outcomeOf = (promise: Promise<unknown>) => {
      const outcome: { done: boolean; error?: unknown } = { done: false };
      promise.then(
        () => (outcome.done = true),
        (error: unknown) => {
          outcome.error = error;
          outcome.done = true;
        },
      );
      return outcome;
    };

    it("does not start an upload that queued for the single PUT slot while the caller was current", async () => {
      // A holds the one slot; B queues for it; C (the purge) makes the caller
      // stale; A finishes. B's request must not start.
      const a = deferred();
      const upload = vi.fn(async (key: string) => {
        if (key === "scope/a") await a.promise;
        return key;
      });
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ maxConcurrentPuts: 1 }),
      );
      const { state, guard } = staleness();
      const putA = blobs.put("scope/a", new Uint8Array([1]), guard);
      await vi.waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
      const putB = blobs.put("scope/b", new Uint8Array([2]), guard);
      const rejection = expect(putB).rejects.toThrow("connection purged");
      state.stale = true;
      a.release();
      await putA;
      await rejection;
      expect(upload.mock.calls.map(([key]) => key)).toEqual(["scope/a"]);
    });

    it("does not start an upload that waits for the shared storage limit", async () => {
      // Same, through `maxConcurrent`: the upload waits there, not at the PUT limit.
      const a = deferred();
      const upload = vi.fn(async (key: string) => {
        if (key === "scope/a") await a.promise;
        return key;
      });
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ maxConcurrentPuts: 2, maxConcurrent: 1 }),
      );
      const { state, guard } = staleness();
      const putA = blobs.put("scope/a", new Uint8Array([1]), guard);
      await vi.waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
      const putB = blobs.put("scope/b", new Uint8Array([2]), guard);
      const rejection = expect(putB).rejects.toThrow("connection purged");
      state.stale = true;
      a.release();
      await putA;
      await rejection;
      expect(upload.mock.calls.map(([key]) => key)).toEqual(["scope/a"]);
    });

    it("frees the single PUT slot when a queued upload's guard throws", async () => {
      // A holds the one PUT slot; B queues for it and its guard throws when
      // the slot reaches it. The slot must come back: a fresh upload C runs.
      const a = deferred();
      const upload = vi.fn(async (key: string) => {
        if (key === "scope/a") await a.promise;
        return key;
      });
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ maxConcurrentPuts: 1 }),
      );
      const { state, guard } = staleness();
      const putA = blobs.put("scope/a", new Uint8Array([1]), guard);
      await vi.waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
      const putB = outcomeOf(blobs.put("scope/b", new Uint8Array([2]), guard));
      state.stale = true;
      a.release();
      await putA;
      // Bounded: if B never settles, this wait fails the test instead of hanging it.
      await vi.waitFor(() => expect(putB.done).toBe(true));
      expect(putB.error).toEqual(new Error("connection purged"));
      expect(upload.mock.calls.map(([key]) => key)).toEqual(["scope/a"]);
      // Bounded: a slot left taken fails this wait instead of hanging the test.
      const putC = blobs.put("scope/c", new Uint8Array([3]), staleness().guard);
      await vi.waitFor(() =>
        expect(upload.mock.calls.map(([key]) => key)).toContain("scope/c"),
      );
      await expect(putC).resolves.toBeUndefined();
      expect(upload.mock.calls.map(([key]) => key)).toEqual([
        "scope/a",
        "scope/c",
      ]);
    });

    it("frees the shared storage limit when a queued upload's guard throws", async () => {
      // Same, through `maxConcurrent`: B takes the shared slot, its guard
      // throws, and the slot must come back for a fresh upload C.
      const a = deferred();
      const upload = vi.fn(async (key: string) => {
        if (key === "scope/a") await a.promise;
        return key;
      });
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ maxConcurrentPuts: 2, maxConcurrent: 1 }),
      );
      const { state, guard } = staleness();
      const putA = blobs.put("scope/a", new Uint8Array([1]), guard);
      await vi.waitFor(() => expect(upload).toHaveBeenCalledTimes(1));
      const putB = outcomeOf(blobs.put("scope/b", new Uint8Array([2]), guard));
      state.stale = true;
      a.release();
      await putA;
      // Bounded: if B never settles, this wait fails the test instead of hanging it.
      await vi.waitFor(() => expect(putB.done).toBe(true));
      expect(putB.error).toEqual(new Error("connection purged"));
      expect(upload.mock.calls.map(([key]) => key)).toEqual(["scope/a"]);
      // Bounded: a slot left taken fails this wait instead of hanging the test.
      const putC = blobs.put("scope/c", new Uint8Array([3]), staleness().guard);
      await vi.waitFor(() =>
        expect(upload.mock.calls.map(([key]) => key)).toContain("scope/c"),
      );
      await expect(putC).resolves.toBeUndefined();
      expect(upload.mock.calls.map(([key]) => key)).toEqual([
        "scope/a",
        "scope/c",
      ]);
    });

    it("makes no second attempt when the caller went stale during the retry delay", async () => {
      const sleeping = deferred();
      const slept = vi.fn(() => sleeping.promise);
      const upload = vi.fn().mockRejectedValueOnce(failed(500));
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ sleep: slept, now: () => 0, baseDelayMs: 100 }),
      );
      const { state, guard } = staleness();
      const put = blobs.put("scope/a", new Uint8Array([1]), guard);
      const rejection = expect(put).rejects.toThrow("connection purged");
      await vi.waitFor(() => expect(slept).toHaveBeenCalledTimes(1));
      state.stale = true;
      sleeping.release();
      await rejection;
      expect(upload).toHaveBeenCalledTimes(1);
    });

    it("still retries when the caller is current after the retry delay", async () => {
      const upload = vi.fn().mockRejectedValueOnce(failed(500));
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ now: () => 0, baseDelayMs: 100 }),
      );
      await blobs.put("scope/a", new Uint8Array([1]), staleness().guard);
      expect(upload).toHaveBeenCalledTimes(2);
    });
  });

  describe("uploads in flight", () => {
    /** Storage that counts uploads in flight, and reads, while each takes a moment. */
    const counting = () => {
      const seen = { puts: 0, putPeak: 0, reads: 0, readPeak: 0 };
      return {
        seen,
        storage: adapter({
          upload: vi.fn(async () => {
            seen.puts++;
            seen.putPeak = Math.max(seen.putPeak, seen.puts);
            await new Promise((resolve) => setTimeout(resolve, 3));
            seen.puts--;
            return "url";
          }),
          download: vi.fn(async () => {
            seen.reads++;
            seen.readPeak = Math.max(seen.readPeak, seen.reads);
            await new Promise((resolve) => setTimeout(resolve, 3));
            seen.reads--;
            return new Uint8Array([1]);
          }),
        }),
      };
    };
    const putAll = (blobs: ReturnType<typeof createStorageStreamSyncBlobs>) =>
      Promise.all(
        Array.from({ length: 12 }, (_, i) =>
          blobs.put(`scope/part-${i}`, new Uint8Array([i])),
        ),
      );

    it("keeps one upload in flight by default, however many callers", () => {
      expect(DEFAULT_STORAGE_ACCESS_POLICY.maxConcurrentPuts).toBe(1);
      const { seen, storage } = counting();
      return putAll(
        createStorageStreamSyncBlobs(storage, policy({ maxConcurrent: 4 })),
      ).then(() => expect(seen.putPeak).toBe(1));
    });

    it("lets maxConcurrentPuts raise it, never above maxConcurrent", async () => {
      const wide = counting();
      await putAll(
        createStorageStreamSyncBlobs(
          wide.storage,
          policy({ maxConcurrent: 4, maxConcurrentPuts: 3 }),
        ),
      );
      expect(wide.seen.putPeak).toBe(3);
      const narrow = counting();
      await putAll(
        createStorageStreamSyncBlobs(
          narrow.storage,
          policy({ maxConcurrent: 2, maxConcurrentPuts: 5 }),
        ),
      );
      expect(narrow.seen.putPeak).toBe(2);
    });

    it("does not queue reads behind uploads that wait for their turn", async () => {
      const { seen, storage } = counting();
      const blobs = createStorageStreamSyncBlobs(
        storage,
        policy({ maxConcurrent: 2, maxConcurrentPuts: 1 }),
      );
      let putsDone = 0;
      const puts = putAll(blobs).then(() => (putsDone = 12));
      const settledPuts = () => seen.puts === 0 && putsDone === 12;
      await Promise.all(
        Array.from({ length: 4 }, (_, i) => blobs.get(`scope/read-${i}`)),
      );
      // Eleven uploads still wait for their turn; they hold no slot of the
      // shared limit, so the reads finish while uploads remain.
      expect(settledPuts()).toBe(false);
      await puts;
      expect(seen.putPeak).toBe(1);
    });

    it("keeps an upload's retries inside its turn", async () => {
      let puts = 0;
      let peak = 0;
      let calls = 0;
      const upload = vi.fn(async () => {
        calls++;
        puts++;
        peak = Math.max(peak, puts);
        await new Promise((resolve) => setTimeout(resolve, 2));
        puts--;
        if (calls % 2 === 1)
          throw new Error("vana-storage upload failed: 500 Fast");
        return "url";
      });
      const blobs = createStorageStreamSyncBlobs(
        adapter({ upload }),
        policy({ maxConcurrent: 4 }),
      );
      await Promise.all(
        Array.from({ length: 6 }, (_, i) =>
          blobs.put(`scope/part-${i}`, new Uint8Array([i])),
        ),
      );
      expect(peak).toBe(1);
    });
  });

  it("retries a failed upload and still ignores a conflict", async () => {
    const upload = vi
      .fn()
      .mockRejectedValueOnce(
        new Error("vana-storage upload failed: 503 Unavailable"),
      )
      .mockResolvedValue("url");
    const blobs = createStorageStreamSyncBlobs(adapter({ upload }), policy());
    await blobs.put("scope/blob", new Uint8Array([1]));
    expect(upload).toHaveBeenCalledTimes(2);

    const conflict = vi
      .fn()
      .mockRejectedValue(new StoredBlobConflictError("k"));
    await createStorageStreamSyncBlobs(
      adapter({ upload: conflict }),
      policy(),
    ).put("scope/blob", new Uint8Array([2]));
    expect(conflict).toHaveBeenCalledTimes(1);
  });
});

describe("createStorageStreamSyncBlobs.exists", () => {
  it("answers from the storage probe and never reads the body", async () => {
    const download = vi.fn(async () => new Uint8Array([1, 2, 3]));
    const exists = vi.fn(async () => true);
    const blobs = createStorageStreamSyncBlobs(
      adapter({ download, exists }),
      policy(),
    );
    await expect(blobs.exists("scope/blob")).resolves.toBe(true);
    expect(exists).toHaveBeenCalledTimes(1);
    expect(download).not.toHaveBeenCalled();
  });

  it("reads a probe answering not found as missing", async () => {
    const exists = vi.fn(async () => false);
    const blobs = createStorageStreamSyncBlobs(adapter({ exists }), policy());
    await expect(blobs.exists("scope/blob")).resolves.toBe(false);
  });

  it("retries a probe that failed with a 500, then answers", async () => {
    const exists = vi
      .fn()
      .mockRejectedValueOnce(failed(500))
      .mockResolvedValue(true);
    const blobs = createStorageStreamSyncBlobs(adapter({ exists }), policy());
    await expect(blobs.exists("scope/blob")).resolves.toBe(true);
    expect(exists).toHaveBeenCalledTimes(2);
  });

  it.each([401, 403])(
    "fails at once on a probe refused with %i, never as missing",
    async (status) => {
      const exists = vi.fn().mockRejectedValue(failed(status));
      const blobs = createStorageStreamSyncBlobs(adapter({ exists }), policy());
      await expect(blobs.exists("scope/blob")).rejects.toThrow(String(status));
      expect(exists).toHaveBeenCalledTimes(1);
    },
  );

  it("throws a persistent 5xx probe after its attempts, never as missing", async () => {
    const exists = vi.fn().mockRejectedValue(failed(500));
    const blobs = createStorageStreamSyncBlobs(
      adapter({ exists }),
      policy({ maxAttempts: 3 }),
    );
    await expect(blobs.exists("scope/blob")).rejects.toThrow("500");
    expect(exists).toHaveBeenCalledTimes(3);
  });
});
