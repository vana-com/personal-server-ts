import { vi } from "vitest";
import { CLAIM_POLL_FLOOR_MS } from "@opendatalabs/vana-sdk/protocol/jobs";
import type { SandboxRegistry } from "../sandbox/registry.js";
import { startClaimLoop, type JobLogger } from "./claim-loop.js";
import type { GatewayClient } from "./gateway-client.js";
import type { ClaimResponse } from "./types.js";

const CLAIM = {
  job: { jobId: "job-1" },
  identity: { userPsId: "0x01" },
} as unknown as ClaimResponse;
const MAX_CLAIMS_PER_FLOOR = 2;

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
  it("waits for the poll floor after an immediate empty claim", async () => {
    vi.useFakeTimers();
    const gateway = gatewayFake();
    const lastClaim = deferred<ClaimResponse | null>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(null)
      .mockImplementationOnce(() => lastClaim.promise);
    const sleep = vi.fn(
      (milliseconds: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, milliseconds)),
    );
    const loop = startClaimLoop({
      gateway,
      run: vi.fn(),
      registry: registryFake(),
      leaseSeconds: 30,
      wait: 25,
      capacity: 20,
      logger: loggerFake(),
      sleep,
    });

    try {
      await vi.advanceTimersByTimeAsync(0);
      expect(sleep).toHaveBeenCalledOnce();
      const delay = sleep.mock.calls[0]?.[0] ?? 0;
      expect(delay).toBeGreaterThan(0);
      expect(delay).toBeLessThanOrEqual(CLAIM_POLL_FLOOR_MS);

      await vi.advanceTimersByTimeAsync(CLAIM_POLL_FLOOR_MS);
      expect(gateway.claim.mock.calls.length).toBeLessThanOrEqual(
        MAX_CLAIMS_PER_FLOOR,
      );

      const draining = loop.drain();
      lastClaim.resolve(null);
      await draining;
    } finally {
      vi.useRealTimers();
    }
  });

  it("continues claiming after a job run rejects", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const logger = loggerFake();
    const lastClaim = deferred<ClaimResponse | null>();
    const secondRun = deferred<void>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM)
      .mockImplementationOnce(() => lastClaim.promise);
    const run = vi
      .fn()
      .mockRejectedValueOnce(new Error("run failed"))
      .mockImplementationOnce(() => secondRun.promise);
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
    expect(loop.running()).toBe(1);
    expect(logger.warn).toHaveBeenCalledWith(
      { jobId: "job-1", error: "Error: run failed" },
      "Claimed job run failed",
    );

    const draining = loop.drain();
    lastClaim.resolve(null);
    secondRun.resolve();
    await draining;
    expect(loop.running()).toBe(0);
  });

  it("runs claims concurrently and drain waits for all in-flight work", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const firstRun = deferred<void>();
    const secondRun = deferred<void>();
    const lastClaim = deferred<ClaimResponse | null>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM)
      .mockImplementationOnce(() => lastClaim.promise);
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
      capacity: 2,
      logger: loggerFake(),
    });
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(2));

    expect(loop.running()).toBe(2);
    expect(gateway.claim).toHaveBeenNthCalledWith(1, 25, {
      leaseSeconds: 30,
      capacity: 2,
    });
    expect(gateway.claim).toHaveBeenNthCalledWith(2, 25, {
      leaseSeconds: 30,
      capacity: 1,
    });

    secondRun.resolve();
    await vi.waitFor(() => expect(gateway.claim).toHaveBeenCalledTimes(3));
    expect(gateway.claim).toHaveBeenNthCalledWith(3, 25, {
      leaseSeconds: 30,
      capacity: 1,
    });

    let drained = false;
    const draining = loop.drain().then(() => {
      drained = true;
    });
    lastClaim.resolve(null);
    await Promise.resolve();
    expect(drained).toBe(false);
    expect(loop.running()).toBe(1);

    firstRun.resolve();
    await draining;
    expect(loop.running()).toBe(0);
    expect(registry.drain).toHaveBeenCalledOnce();
  });

  it("never starts more runs than the advertised capacity", async () => {
    const gateway = gatewayFake();
    const registry = registryFake();
    const firstRun = deferred<void>();
    const secondRun = deferred<void>();
    const thirdRun = deferred<void>();
    vi.mocked(gateway.claim)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM)
      .mockResolvedValueOnce(CLAIM);
    const run = vi
      .fn()
      .mockImplementationOnce(() => firstRun.promise)
      .mockImplementationOnce(() => secondRun.promise)
      .mockImplementationOnce(() => thirdRun.promise);
    const loop = startClaimLoop({
      gateway,
      run,
      registry,
      leaseSeconds: 30,
      wait: 25,
      capacity: 2,
      logger: loggerFake(),
    });
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(2));

    expect(loop.running()).toBe(2);
    expect(gateway.claim).toHaveBeenCalledTimes(2);

    firstRun.resolve();
    await vi.waitFor(() => expect(run).toHaveBeenCalledTimes(3));
    expect(loop.running()).toBe(2);

    let drained = false;
    const draining = loop.drain().then(() => {
      drained = true;
    });
    secondRun.resolve();
    await Promise.resolve();
    expect(drained).toBe(false);

    thirdRun.resolve();
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
