import { describe, expect, it } from "vitest";

import {
  createDownloadRetryMemory,
  downloadRetryKey,
  DEFAULT_MAX_TRANSIENT_ATTEMPTS,
} from "./retry-memory.js";

const KEY = "0xrecord@1";

describe("download retry memory", () => {
  it("allows the first attempt for an unknown key", () => {
    const memory = createDownloadRetryMemory({ now: () => 0 });
    expect(memory.decide(KEY)).toBe("attempt");
  });

  it("never allows another attempt after a non-retryable failure", () => {
    let nowMs = 0;
    const memory = createDownloadRetryMemory({ now: () => nowMs });

    memory.recordFailure(KEY, false);

    expect(memory.decide(KEY)).toBe("give-up");
    // Not even after arbitrary time passes — a 404 cannot heal by waiting.
    nowMs = 24 * 60 * 60 * 1000;
    expect(memory.decide(KEY)).toBe("give-up");
  });

  it("backs off retryable failures exponentially", () => {
    let nowMs = 0;
    const memory = createDownloadRetryMemory({
      now: () => nowMs,
      backoffBaseMs: 1000,
    });

    memory.recordFailure(KEY, true); // attempt 1 → wait 1000ms
    expect(memory.decide(KEY)).toBe("backoff");
    nowMs = 999;
    expect(memory.decide(KEY)).toBe("backoff");
    nowMs = 1000;
    expect(memory.decide(KEY)).toBe("attempt");

    memory.recordFailure(KEY, true); // attempt 2 → wait 2000ms
    nowMs = 2999;
    expect(memory.decide(KEY)).toBe("backoff");
    nowMs = 3000;
    expect(memory.decide(KEY)).toBe("attempt");

    memory.recordFailure(KEY, true); // attempt 3 → wait 4000ms
    nowMs = 6999;
    expect(memory.decide(KEY)).toBe("backoff");
    nowMs = 7000;
    expect(memory.decide(KEY)).toBe("attempt");
  });

  it("gives up on retryable failures after the attempt cap", () => {
    let nowMs = 0;
    const memory = createDownloadRetryMemory({
      now: () => nowMs,
      backoffBaseMs: 0,
      maxTransientAttempts: 3,
    });

    memory.recordFailure(KEY, true);
    expect(memory.decide(KEY)).toBe("attempt");
    memory.recordFailure(KEY, true);
    expect(memory.decide(KEY)).toBe("attempt");
    memory.recordFailure(KEY, true);
    expect(memory.decide(KEY)).toBe("give-up");
    nowMs = 60_000;
    expect(memory.decide(KEY)).toBe("give-up");
  });

  it("clears failure history on success", () => {
    const nowMs = 0;
    const memory = createDownloadRetryMemory({
      now: () => nowMs,
      backoffBaseMs: 0,
      maxTransientAttempts: 2,
    });

    memory.recordFailure(KEY, true);
    memory.recordFailure(KEY, true);
    expect(memory.decide(KEY)).toBe("give-up");

    memory.recordSuccess(KEY);
    expect(memory.decide(KEY)).toBe("attempt");
  });

  it("tracks keys independently", () => {
    const memory = createDownloadRetryMemory({ now: () => 0 });
    memory.recordFailure(KEY, false);
    expect(memory.decide(KEY)).toBe("give-up");
    expect(memory.decide("0xother@1")).toBe("attempt");
  });

  it("exposes a sane default attempt cap", () => {
    // Bounded retries: 3-5 attempts, not one per sync cycle forever.
    expect(DEFAULT_MAX_TRANSIENT_ATTEMPTS).toBeGreaterThanOrEqual(3);
    expect(DEFAULT_MAX_TRANSIENT_ATTEMPTS).toBeLessThanOrEqual(5);
  });

  it("keys on the record id AND version so a new version retries fresh", () => {
    expect(downloadRetryKey({ id: "0xabc", expectedVersion: "3" })).not.toBe(
      downloadRetryKey({ id: "0xabc", expectedVersion: "4" }),
    );
  });
});
