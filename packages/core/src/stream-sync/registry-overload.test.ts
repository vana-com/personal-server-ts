import { afterEach, expect, it, vi } from "vitest";
import { createRegistryChangePush } from "../sync/engine/change-push.js";
import { createGatewayStreamSyncRegistry } from "./registry.js";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it("waits for Retry-After before retrying an overloaded change feed", async () => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0);
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(null, { status: 429, headers: { "Retry-After": "5" } }),
    )
    .mockResolvedValueOnce(Response.json({ seq: "1", changed: false }))
    .mockImplementation(() => new Promise(() => {}));
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    fetch,
  });
  const onChange = vi.fn();
  const stop = createRegistryChangePush(registry)!.subscribe({
    onChange,
    onHealth: vi.fn(),
    onPosition: vi.fn(),
    since: () => undefined,
  });
  await vi.advanceTimersByTimeAsync(4999);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(onChange).not.toHaveBeenCalled();
  await vi.advanceTimersByTimeAsync(1);
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(onChange).not.toHaveBeenCalled();
  stop();
});

it("shares a 503 deadline with reads and aborts a waiting caller", async () => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0.5);
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(
      new Response(null, { status: 503, headers: { "Retry-After": "4" } }),
    )
    .mockResolvedValue(new Response(null, { status: 404 }));
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    fetch,
  });
  await expect(registry.read("first")).rejects.toThrow();
  const controller = new AbortController();
  const cancelled = registry.read("cancelled", controller.signal);
  const rejected = expect(cancelled).rejects.toThrow();
  const read = registry.read("next");
  controller.abort(new Error("stopped"));
  await rejected;
  await vi.advanceTimersByTimeAsync(4999);
  expect(fetch).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  await expect(read).resolves.toEqual({ found: false });
  expect(fetch).toHaveBeenCalledTimes(2);
});

it("keeps the existing backoff for an overload without Retry-After", async () => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0.5);
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(new Response(null, { status: 429 }))
    .mockImplementation(() => new Promise(() => {}));
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    fetch,
  });
  const stop = createRegistryChangePush(registry)!.subscribe({
    onChange: vi.fn(),
    onHealth: vi.fn(),
    onPosition: vi.fn(),
    since: () => undefined,
  });
  await vi.advanceTimersByTimeAsync(999);
  expect(fetch).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(fetch).toHaveBeenCalledTimes(2);
  stop();
});

it("stops promptly during an overload wait", async () => {
  vi.useFakeTimers();
  const fetch = vi
    .fn()
    .mockResolvedValue(
      new Response(null, { status: 429, headers: { "Retry-After": "30" } }),
    );
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: "0x" + "11".repeat(20),
    fetch,
  });
  const stop = createRegistryChangePush(registry)!.subscribe({
    onChange: vi.fn(),
    onHealth: vi.fn(),
    onPosition: vi.fn(),
    since: () => undefined,
  });
  await vi.advanceTimersByTimeAsync(0);
  stop();
  await vi.advanceTimersByTimeAsync(60_000);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
});
