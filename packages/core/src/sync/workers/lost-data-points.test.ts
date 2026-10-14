import { describe, it, expect, vi } from "vitest";
import { DataPointDeletedError } from "@opendatalabs/vana-sdk/browser";
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

    const result = await requeueLostDataPoints({ storage, gateway, logger });

    expect(result).toEqual({ requeued: ["chatgpt.memories"], failed: [] });
    expect(
      storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId,
    ).toBeNull();
    expect(storage.findUnsynced().map((e) => e.scope)).toEqual([
      "chatgpt.memories",
    ]);
  });

  it("leaves a scope alone whenever the gateway has any version of it", async () => {
    // An older head (rolled back) is deliberately not re-queued: the download
    // worker would re-stamp the row from it before a failed re-upload retried.
    for (const expectedVersion of ["1", "2", "4"]) {
      const storage = await seed("chatgpt.memories", 3, "0xdp");
      const gateway = gatewayReturning({ "0xdp": { expectedVersion } });
      expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual(
        { requeued: [], failed: [] },
      );
      expect(
        storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId,
      ).toBe("0xdp");
    }
  });

  it("treats a tombstone as the owner's deletion: nothing re-queued or retried", async () => {
    const storage = await seed("chatgpt.memories", 1, "0xdp");
    const gateway = gatewayReturning({
      "0xdp": new DataPointDeletedError("Data point 0xdp has been deleted", {
        dataPointId: "0xdp",
      } as never),
    });

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual({
      requeued: [],
      failed: [],
    });
    expect(storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId).toBe(
      "0xdp",
    );
  });

  it("reports a scope whose lookup failed so the caller can retry it", async () => {
    const storage = await seed("chatgpt.memories", 1, "0xdp");
    const gateway = gatewayReturning({
      "0xdp": new Error("Gateway error: 503 Service Unavailable"),
    });

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual({
      requeued: [],
      failed: ["chatgpt.memories"],
    });
    expect(storage.findEntry({ scope: "chatgpt.memories" })?.dataPointId).toBe(
      "0xdp",
    );
  });

  it("does not ask the gateway about entries that are not synced yet", async () => {
    const storage = await seed("chatgpt.memories", 1, null);
    const gateway = gatewayReturning({});

    expect(await requeueLostDataPoints({ storage, gateway, logger })).toEqual({
      requeued: [],
      failed: [],
    });
    expect(gateway.getDataPoint).not.toHaveBeenCalled();
  });

  it("re-checks only the given scopes on a retry", async () => {
    const storage = await seed("chatgpt.memories", 1, "0xlost");
    await storage.insertEntry({
      fileId: null,
      path: "github.repositories/2026-10-13T20-29-35Z.json",
      scope: "github.repositories",
      collectedAt: "2026-10-13T20:29:35Z",
      sizeBytes: 10,
      version: 1,
      dataPointId: "0xother",
    });
    const gateway = gatewayReturning({ "0xlost": null, "0xother": null });

    expect(
      await requeueLostDataPoints({ storage, gateway, logger }, [
        "chatgpt.memories",
      ]),
    ).toEqual({ requeued: ["chatgpt.memories"], failed: [] });
    expect(gateway.getDataPoint).toHaveBeenCalledTimes(1);
  });
});
