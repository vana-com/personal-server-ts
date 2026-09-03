import { vi } from "vitest";
import type { SandboxRegistry } from "../sandbox/registry.js";
import { startClaimLoop, type JobLogger } from "./claim-loop.js";
import type { GatewayClient } from "./gateway-client.js";
import type { ClaimResponse } from "./types.js";

const CLAIM = {
  job: { jobId: "job-1" },
  identity: { userPsId: "0x01" },
} as unknown as ClaimResponse;

function deferred<T>() {
  let resolvePromise: (value: T) => void = () => {};
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });

  return { promise, resolve: resolvePromise };
}

function gatewayFake(): GatewayClient {
  return {
    claim: vi.fn(),
    heartbeat: vi.fn(),
    complete: vi.fn(),
    fail: vi.fn(),
    nodeHeartbeat: vi.fn(),
  };
}

function registryFake(): SandboxRegistry {
  return {
    acquire: vi.fn(),
    release: vi.fn(),
    drain: vi.fn().mockResolvedValue(undefined),
    activeCount: vi.fn().mockReturnValue(0),
  };
}

function loggerFake(): JobLogger {
  return { info: vi.fn(), warn: vi.fn() };
}

describe("claim loop", () => {
  it("continues claiming after a job run rejects", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const logger = loggerFake();
    const lastClaim = deferred<ClaimResponse | null>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM)
      .mockImplementationOnce(() => lastClaim.promise);
    const run = vi
      .fn()
      .mockRejectedValueOnce(new Error("run failed"))
      .mockResolvedValueOnce(undefined);
    const loop = startClaimLoop({
      gateway,
      run,
      registry,
      leaseSeconds: 30,
      wait: 25,
      capacity: 20,
      logger,
    });

    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(gateway.claim).toHaveBeenCalledTimes(3));
    expect(loop.running()).toBe(0);
    expect(logger.warn).toHaveBeenCalledWith(
      { jobId: "job-1", error: "Error: run failed" },
      "Claimed job run failed",
    );

    const draining = loop.drain();
    lastClaim.resolve(null);
    await draining;
  });

  it("runs claims sequentially and drain waits for in-flight work", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const firstRun = deferred<void>();
    const secondRun = deferred<void>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM);
    const run = vi
      .fn()
      .mockImplementationOnce(() => firstRun.promise)
      .mockImplementationOnce(() => secondRun.promise);
    const loop = startClaimLoop({
      gateway,
      run,
      registry,
      leaseSeconds: 30,
      wait: 25,
      capacity: 20,
      logger: loggerFake(),
    });
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(1));

    expect(gateway.claim).toHaveBeenCalledTimes(1);
    firstRun.resolve();
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(2));

    let drained = false;
    const draining = loop.drain().then(() => {
      drained = true;
    });
    await Promise.resolve();
    expect(drained).toBe(false);
    expect(loop.running()).toBe(1);

    secondRun.resolve();
    await draining;
    expect(loop.running()).toBe(0);
    expect(registry.drain).toHaveBeenCalledOnce();
  });

  it("backs off and logs only failure and recovery transitions", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const logger = loggerFake();
    const lastClaim = deferred<ClaimResponse | null>();
    vi.mocked(gateway.claim)
      .mockRejectedValueOnce(new Error("offline"))
      .mockRejectedValueOnce(new Error("still offline"))
      .mockImplementationOnce(() => lastClaim.promise);
    const sleep = vi.fn().mockResolvedValue(undefined);
    const loop = startClaimLoop({
      gateway,
      run: vi.fn(),
      registry,
      leaseSeconds: 30,
      wait: 25,
      capacity: 20,
      logger,
      sleep,
    });
    await vi.waitFor(() => expect(gateway.claim).toHaveBeenCalledTimes(3));

    expect(sleep).toHaveBeenCalledTimes(2);
    expect(logger.warn).toHaveBeenCalledOnce();
    const draining = loop.drain();
    lastClaim.resolve(null);
    await draining;

    expect(logger.info).toHaveBeenCalledOnce();
  });
});
