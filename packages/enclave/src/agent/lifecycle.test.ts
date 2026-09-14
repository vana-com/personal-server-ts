import { describe, expect, it, vi } from "vitest";
import { drainWithTimeout } from "./lifecycle.js";

describe("agent lifecycle", () => {
  it("bounds SIGTERM draining and reports a timeout", async () => {
    vi.useFakeTimers();
    const logger = { warn: vi.fn() };
    const drain = vi.fn(() => new Promise<void>(() => {}));

    const result = drainWithTimeout(drain, 110_000, logger);
    await vi.advanceTimersByTimeAsync(110_000);

    await expect(result).resolves.toBe(false);
    expect(logger.warn).toHaveBeenCalledWith(
      { timeoutMs: 110_000 },
      "Timed out while draining agent jobs",
    );
    vi.useRealTimers();
  });

  it("reports a completed drain before the bound", async () => {
    const logger = { warn: vi.fn() };

    await expect(
      drainWithTimeout(async () => {}, 110_000, logger),
    ).resolves.toBe(true);
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
