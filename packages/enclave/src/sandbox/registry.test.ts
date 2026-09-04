import { describe, expect, it, vi } from "vitest";
import type { Hex } from "viem";
import {
  createSandboxRegistry,
  SandboxCapacityError,
  type RegistryTimer,
  type SetTimer,
} from "./registry.js";
import type { SandboxHandle, SandboxRuntime, SandboxSpec } from "./runtime.js";

const USER_PS_ID = `0x${"12".repeat(32)}` as Hex;

function deferred<T>() {
  let resolvePromise: (value: T) => void = () => {};
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });

  return { promise, resolve: resolvePromise };
}

class FakeClock {
  nowMs = 0;
  timers: Array<{
    at: number;
    callback: () => void;
    timer: RegistryTimer & { unref: ReturnType<typeof vi.fn> };
  }> = [];

  now = (): number => this.nowMs;

  setTimer: SetTimer = (callback, milliseconds) => {
    const timer = { unref: vi.fn() };
    this.timers.push({ at: this.nowMs + milliseconds, callback, timer });

    return timer;
  };

  advance(milliseconds: number): void {
    this.nowMs += milliseconds;
    const due = this.timers.filter((item) => item.at <= this.nowMs);
    this.timers = this.timers.filter((item) => item.at > this.nowMs);
    for (const item of due) item.callback();
  }
}

function memoryRuntime(): SandboxRuntime & {
  starts: SandboxSpec[];
  stops: string[];
} {
  const starts: SandboxSpec[] = [];
  const stops: string[] = [];

  return {
    starts,
    stops,
    async reconcile() {},
    async start(spec) {
      starts.push(spec);

      return {
        id: `sandbox-${starts.length}`,
        origin: `http://sandbox-${starts.length}`,
      };
    },
    async stop(id) {
      stops.push(id);
    },
    async inspect() {
      return { running: true };
    },
  };
}

function buildSpec(accessToken: string): SandboxSpec {
  return {
    userPsId: USER_PS_ID,
    epoch: 1,
    image: "image",
    env: { PS_ACCESS_TOKEN: accessToken },
  };
}

async function flush(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}

describe("sandbox registry", () => {
  it("reuses ready sandboxes and preserves their access token", async () => {
    const runtime = memoryRuntime();
    const registry = createSandboxRegistry({ runtime, max: 2, idleTtlMs: 100 });

    const first = await registry.acquire("owner:1", buildSpec);
    registry.release("owner:1");
    const second = await registry.acquire("owner:1", buildSpec);

    expect(second).toEqual(first);
    expect(first.accessToken).toMatch(/^[0-9a-f]{64}$/);
    expect(runtime.starts).toHaveLength(1);
  });

  it("tears an idle sandbox down after its TTL", async () => {
    const runtime = memoryRuntime();
    const clock = new FakeClock();
    const registry = createSandboxRegistry({
      runtime,
      max: 2,
      idleTtlMs: 100,
      now: clock.now,
      setTimer: clock.setTimer,
    });
    const { handle } = await registry.acquire("owner:1", buildSpec);

    registry.release("owner:1");
    expect(clock.timers[0]?.timer.unref).toHaveBeenCalledOnce();
    clock.advance(100);
    clock.advance(0);
    await flush();

    expect(runtime.stops).toEqual([handle.id]);
    expect(registry.activeCount()).toBe(0);
  });

  it("logs an idle sandbox force-removal failure", async () => {
    const runtime = memoryRuntime();
    runtime.stop = vi.fn().mockRejectedValue(new Error("docker unavailable"));
    const logger = { warn: vi.fn() };
    const clock = new FakeClock();
    const registry = createSandboxRegistry({
      runtime,
      logger,
      idleTtlMs: 100,
      now: clock.now,
      setTimer: clock.setTimer,
    });
    const { handle } = await registry.acquire("owner:1", buildSpec);

    registry.release("owner:1");
    clock.advance(100);
    clock.advance(0);
    await flush();

    expect(logger.warn).toHaveBeenCalledWith(
      { sandboxId: handle.id, error: "Error: docker unavailable" },
      "Failed to force-remove sandbox",
    );
  });

  it("cancels teardown when an expiring sandbox is claimed", async () => {
    const runtime = memoryRuntime();
    const clock = new FakeClock();
    const registry = createSandboxRegistry({
      runtime,
      max: 1,
      idleTtlMs: 100,
      now: clock.now,
      setTimer: clock.setTimer,
    });
    const first = await registry.acquire("owner:1", buildSpec);
    registry.release("owner:1");

    clock.advance(100);
    const second = await registry.acquire("owner:1", buildSpec);
    clock.advance(0);
    await flush();

    expect(second).toEqual(first);
    expect(runtime.stops).toEqual([]);
  });

  it("starts a fresh sandbox while an expired sandbox is stopping", async () => {
    const stopping = deferred<void>();
    const runtime = memoryRuntime();
    runtime.stop = vi.fn(() => stopping.promise);
    const clock = new FakeClock();
    const registry = createSandboxRegistry({
      runtime,
      max: 1,
      idleTtlMs: 100,
      now: clock.now,
      setTimer: clock.setTimer,
    });
    const first = await registry.acquire("owner:1", buildSpec);
    registry.release("owner:1");

    clock.advance(100);
    clock.advance(0);
    await flush();
    const second = await registry.acquire("owner:1", buildSpec);

    expect(second.handle.id).not.toBe(first.handle.id);
    expect(runtime.starts).toHaveLength(2);

    stopping.resolve();
    await flush();
    expect(registry.activeCount()).toBe(1);
  });

  it("evicts the least recently used idle sandbox", async () => {
    const runtime = memoryRuntime();
    const clock = new FakeClock();
    const registry = createSandboxRegistry({
      runtime,
      max: 2,
      idleTtlMs: 1_000,
      now: clock.now,
      setTimer: clock.setTimer,
    });
    const first = await registry.acquire("owner:1", buildSpec);
    registry.release("owner:1");
    clock.advance(10);
    await registry.acquire("owner:2", buildSpec);
    registry.release("owner:2");

    await registry.acquire("owner:3", buildSpec);

    expect(runtime.stops).toContain(first.handle.id);
    expect(registry.activeCount()).toBe(2);
  });

  it("throws at capacity when no sandbox is idle", async () => {
    const registry = createSandboxRegistry({
      runtime: memoryRuntime(),
      max: 1,
      idleTtlMs: 100,
    });
    await registry.acquire("owner:1", buildSpec);

    await expect(registry.acquire("owner:2", buildSpec)).rejects.toBeInstanceOf(
      SandboxCapacityError,
    );
  });

  it("drains every sandbox and rejects new acquires", async () => {
    const runtime = memoryRuntime();
    const registry = createSandboxRegistry({ runtime, max: 2, idleTtlMs: 100 });
    await registry.acquire("owner:1", buildSpec);
    await registry.acquire("owner:2", buildSpec);

    await registry.drain();

    expect(runtime.stops).toHaveLength(2);
    expect(registry.activeCount()).toBe(0);
    await expect(registry.acquire("owner:3", buildSpec)).rejects.toThrow(
      "registry is draining",
    );
  });

  it("deduplicates concurrent acquires while start is in flight", async () => {
    let resolveStart: ((handle: SandboxHandle) => void) | undefined;
    const runtime = memoryRuntime();
    runtime.start = vi.fn(
      () =>
        new Promise<SandboxHandle>((resolve) => {
          resolveStart = resolve;
        }),
    );
    const registry = createSandboxRegistry({ runtime, max: 2, idleTtlMs: 100 });

    const first = registry.acquire("owner:1", buildSpec);
    const second = registry.acquire("owner:1", buildSpec);
    resolveStart?.({ id: "shared", origin: "http://shared" });

    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.objectContaining({
        handle: { id: "shared", origin: "http://shared" },
      }),
      expect.objectContaining({
        handle: { id: "shared", origin: "http://shared" },
      }),
    ]);
    expect(runtime.start).toHaveBeenCalledOnce();
  });
});
