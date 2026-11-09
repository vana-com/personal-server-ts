import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  syncStop: vi.fn(),
  deactivate: vi.fn(),
  activate: vi.fn(),
  relayStart: vi.fn(),
}));

vi.mock("./browser-runtime.js", () => ({
  createIndexedDbPsLiteRuntime: vi.fn(async () => ({
    runtime: {
      activate: mocks.activate,
      deactivate: mocks.deactivate,
      fetch: vi.fn(),
    },
    syncManager: { stop: mocks.syncStop },
  })),
}));

vi.mock("./relay.js", async () => ({
  ...(await vi.importActual<Record<string, unknown>>("./relay.js")),
  startPsLiteRelayClient: mocks.relayStart,
}));

import { startPersonalServer } from "./client.js";

const startFailure = new Error("relay start failed");

function options() {
  return {
    ownerSignature: "0x1234" as const,
    relay: { sessionId: "session-1", publicSuffix: "relay.example" },
    dbName: "start-throw-test",
  } as unknown as Parameters<typeof startPersonalServer>[0];
}

describe("startPersonalServer when the start throws after the runtime exists", () => {
  beforeEach(() => {
    mocks.syncStop.mockReset().mockResolvedValue(undefined);
    mocks.deactivate.mockReset();
    mocks.activate.mockReset();
    mocks.relayStart.mockReset().mockImplementation(() => {
      throw startFailure;
    });
  });

  it("relay_start_throw_leaves_sync_running: stops the sync manager and deactivates", async () => {
    await expect(startPersonalServer(options())).rejects.toBe(startFailure);

    expect(mocks.syncStop).toHaveBeenCalledOnce();
    expect(mocks.deactivate).toHaveBeenCalledOnce();
  });

  it("rethrows the start error even when stopping the sync manager also fails", async () => {
    mocks.syncStop.mockRejectedValue(new Error("stop failed"));

    await expect(startPersonalServer(options())).rejects.toBe(startFailure);
  });
});
