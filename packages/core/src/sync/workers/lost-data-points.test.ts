import { describe, it, expect, vi } from "vitest";
import { requeueLostDataPoints } from "./lost-data-points.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { Logger } from "../../logger/index.js";

const logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

async function seed(
  scope: string,
  version: number,
  dataPointId: string | null,
) {
  const storage = createMemoryDataStorage();
  await storage.insertEntry({
    fileId: null,
    path: `${scope}/2026-10-13T20-29-35Z.json`,
    scope,
    collectedAt: "2026-10-13T20:29:35Z",
    sizeBytes: 10,
    version,
    dataPointId,
  });
  return storage;
}

function gatewayReturning(
  byId: Record<string, { expectedVersion: string } | null | Error>,
) {
  return {
    getDataPoint: vi.fn(async (id: string) => {
      const value = byId[id];
      if (value instanceof Error) throw value;
      return (value ?? null) as never;
    }),
  };
}

describe("requeueLostDataPoints", () => {
  it("re-queues a synced scope the gateway has no data point for", async () => {
    const storage = await seed("chatgpt.memories", 1, "0xlost");
    const gateway = gatewayReturning({ "0xlost": null });

    const requeued = await requeueLostDataPoints({ storage, gateway, logger });

    expect(requeued).toEqual(["chatgpt.memories"]);
    expect(
      storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId,
    ).toBeNull();
    expect(storage.findUnsynced().map((e) => e.scope)).toEqual([
      "chatgpt.memories",
    ]);
  });

  it("re-queues when the gateway head was rolled back below the local version", async () => {
    const storage = await seed("chatgpt.memories", 3, "0xdp");
    const gateway = gatewayReturning({ "0xdp": { expectedVersion: "2" } });

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual([
      "chatgpt.memories",
    ]);
  });

  it("leaves a scope alone when the gateway has this version or a newer one", async () => {
    for (const expectedVersion of ["1", "4"]) {
      const storage = await seed("chatgpt.memories", 1, "0xdp");
      const gateway = gatewayReturning({ "0xdp": { expectedVersion } });
      expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual(
        [],
      );
      expect(
        storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId,
      ).toBe("0xdp");
    }
  });

  it("never re-queues on a tombstone or a gateway error", async () => {
    const storage = await seed("chatgpt.memories", 1, "0xdp");
    const gateway = gatewayReturning({
      "0xdp": new Error("Data point 0xdp has been deleted"),
    });

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual(
      [],
    );
    expect(storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId).toBe(
      "0xdp",
    );
  });

  it("does not ask the gateway about entries that are not synced yet", async () => {
    const storage = await seed("chatgpt.memories", 1, null);
    const gateway = gatewayReturning({});

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual(
      [],
    );
    expect(gateway.getDataPoint).not.toHaveBeenCalled();
  });
});
