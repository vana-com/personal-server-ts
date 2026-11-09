import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  syncStop: vi.fn(),
  syncStart: vi.fn(),
  relayClose: vi.fn(),
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
    syncManager: { stop: mocks.syncStop, start: mocks.syncStart },
  })),
}));

vi.mock("./relay.js", async () => ({
  ...(await vi.importActual<Record<string, unknown>>("./relay.js")),
  startPsLiteRelayClient: mocks.relayStart,
}));

import {
  START_CLEANUP_STOP_TIMEOUT_MS,
  startPersonalServer,
  unstoppedRuntimeOf,
} from "./client.js";

let startFailure = new Error("relay start failed");

function options() {
  return {
    ownerSignature: "0x1234" as const,
    relay: { sessionId: "session-1", publicSuffix: "relay.example" },
    dbName: "start-throw-test",
  } as unknown as Parameters<typeof startPersonalServer>[0];
}

describe("startPersonalServer when the start throws after the runtime exists", () => {
  beforeEach(() => {
    startFailure = new Error("relay start failed");
    mocks.syncStop.mockReset().mockResolvedValue(undefined);
    mocks.syncStart.mockReset();
    mocks.relayClose.mockReset();
    mocks.deactivate.mockReset();
    mocks.activate.mockReset();
    mocks.relayStart.mockReset().mockImplementation(() => {
      throw startFailure;
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("relay_start_throw_leaves_sync_running: stops the sync manager and deactivates", async () => {
    await expect(startPersonalServer(options())).rejects.toBe(startFailure);

    expect(mocks.syncStop).toHaveBeenCalledOnce();
    expect(mocks.deactivate).toHaveBeenCalledOnce();
    expect(mocks.syncStart).not.toHaveBeenCalled();
  });

  it("starts the sync manager only after the relay has started", async () => {
    mocks.relayStart.mockReset().mockImplementation(() => {
      expect(mocks.syncStart).not.toHaveBeenCalled();
      return { close: mocks.relayClose, sessionId: "session-1", url: "" };
    });

    await startPersonalServer(options());

    expect(mocks.syncStart).toHaveBeenCalledOnce();
  });

  it("closes a live relay client when the sync start throws", async () => {
    mocks.relayStart.mockReset().mockReturnValue({
      close: mocks.relayClose,
      sessionId: "session-1",
      url: "",
    });
    mocks.syncStart.mockImplementation(() => {
      throw startFailure;
    });

    await expect(startPersonalServer(options())).rejects.toBe(startFailure);

    expect(mocks.relayClose).toHaveBeenCalledOnce();
    expect(mocks.syncStop).toHaveBeenCalledOnce();
  });

  it("abandon_stop_failure_swallowed: carries the unstopped runtime on the start error", async () => {
    mocks.syncStop.mockRejectedValueOnce(new Error("stop failed"));

    const error = await startPersonalServer(options()).catch(
      (caught: unknown) => caught,
    );

    expect(error).toBe(startFailure);
    const unstopped = unstoppedRuntimeOf(error);
    expect(unstopped).toBeDefined();
    await unstopped!.stop();
    expect(mocks.syncStop).toHaveBeenCalledTimes(2);
  });

  it("carries no unstopped runtime when the cleanup stop succeeded", async () => {
    const error = await startPersonalServer(options()).catch(
      (caught: unknown) => caught,
    );

    expect(unstoppedRuntimeOf(error)).toBeUndefined();
  });

  it("abandon_stop_hang_unbounded: gives up a hung cleanup stop and still rejects with the handle", async () => {
    vi.useFakeTimers();
    mocks.syncStop.mockReturnValue(new Promise<void>(() => {}));
    let settled: unknown = "pending";
    void startPersonalServer(options()).catch((caught: unknown) => {
      settled = caught;
    });

    await vi.advanceTimersByTimeAsync(START_CLEANUP_STOP_TIMEOUT_MS - 1);
    expect(settled).toBe("pending");
    await vi.advanceTimersByTimeAsync(1);

    expect(settled).toBe(startFailure);
    expect(unstoppedRuntimeOf(settled)).toBeDefined();
  });
});
