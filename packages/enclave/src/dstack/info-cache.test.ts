import { describe, expect, it, vi } from "vitest";
import type { DstackInfo } from "./client.js";
import { createFakeDstackClient } from "./fake.js";
import {
  cachedDstackInfo,
  DSTACK_INFO_BUDGET_MS,
  dstackInfo,
  DstackInfoUnavailable,
  warmDstackInfo,
} from "./info-cache.js";

const FAKE_APP_ID = "0000000000000000000000000000000000000005";

/**
 * A client standing in for the 2026-09-11 prod5 guest agent: Info hangs until
 * the test hands out an answer, and every call is counted.
 */
function countedClient(): {
  client: ReturnType<typeof createFakeDstackClient>;
  release: () => void;
  calls: () => number;
} {
  const fake = createFakeDstackClient({ appId: FAKE_APP_ID });
  const read = fake.info.bind(fake);
  const waiting: (() => void)[] = [];
  let calls = 0;

  fake.info = () => {
    calls += 1;

    return new Promise<DstackInfo>((resolve) => {
      waiting.push(() => {
        resolve(read());
      });
    });
  };

  return {
    client: fake,
    release: () => waiting.shift()?.(),
    calls: () => calls,
  };
}

describe("dstack info cache", () => {
  it("serves every later caller from the boot read", async () => {
    const { client, release, calls } = countedClient();
    const warming = warmDstackInfo(client);
    release();
    const booted = await warming;

    await expect(dstackInfo(client)).resolves.toEqual(booted);
    await expect(cachedDstackInfo(client)).resolves.toEqual(booted);
    expect(booted.appId).toBe(FAKE_APP_ID);
    expect(calls()).toBe(1);
  });

  it("logs how long the boot read took", async () => {
    const { client, release } = countedClient();
    const logger = { info: vi.fn() };
    const warming = warmDstackInfo(client, logger);
    release();
    await warming;

    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({
        durationMs: expect.any(Number) as number,
        appId: FAKE_APP_ID,
      }),
      expect.any(String) as string,
    );
  });

  it("fails closed when nothing is cached and the agent is slow", async () => {
    vi.useFakeTimers();
    const { client } = countedClient();

    // Assert before the clock moves: the rejection lands inside the advance.
    const refused = expect(dstackInfo(client)).rejects.toBeInstanceOf(
      DstackInfoUnavailable,
    );
    await vi.advanceTimersByTimeAsync(DSTACK_INFO_BUDGET_MS);

    await refused;
    vi.useRealTimers();
  });
});
