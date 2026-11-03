import { afterEach, expect, it, vi } from "vitest";
import { createLegacyScopeRevalidator } from "./legacy-scope-revalidator.js";
afterEach(() => vi.useRealTimers());
it("folds N commits during an evaluation into exactly one follow-up", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const evaluate = vi
    .fn()
    .mockImplementationOnce(() => gate)
    .mockResolvedValue(undefined);
  const worker = createLegacyScopeRevalidator({
    evaluate,
    candidates: () => [],
    fingerprint: () => "",
    intervalMs: 1000,
    logger: { warn: vi.fn() },
  });
  worker.enqueue("i", ["chatgpt.conversations"]);
  await Promise.resolve();
  expect(evaluate).toHaveBeenCalledTimes(1);
  for (let i = 0; i < 20; i++) worker.enqueue("i", ["chatgpt.conversations"]);
  release();
  await worker.idle();
  expect(evaluate).toHaveBeenCalledTimes(2);
  await worker.stop();
});
it("recovers a dropped enqueue within one sweep interval and on restart", async () => {
  vi.useFakeTimers();
  let stale = true;
  let covered = true;
  const evaluate = vi.fn(async () => {
    covered = false;
    stale = false;
  });
  const options = {
    evaluate,
    candidates: () => [
      { instance: "i", scopes: ["chatgpt.conversations"], stale },
    ],
    fingerprint: () => "",
    intervalMs: 1000,
    logger: { warn: vi.fn() },
  };
  const first = createLegacyScopeRevalidator(options);
  first.start();
  await first.idle();
  expect(covered).toBe(false);
  covered = true;
  stale = true; // Deliberately lose the mutation notification.
  await vi.advanceTimersByTimeAsync(1000);
  await first.idle();
  expect(covered).toBe(false);
  await first.stop();
  stale = true;
  covered = true;
  const restarted = createLegacyScopeRevalidator(options);
  restarted.start();
  await restarted.idle();
  expect(covered).toBe(false);
  await restarted.stop();
});
it("coarsely schedules every referring instance for non-stream and policy changes", async () => {
  vi.useFakeTimers();
  let revision = 0;
  const evaluate = vi.fn(async () => {});
  const worker = createLegacyScopeRevalidator({
    evaluate,
    candidates: () => [
      { instance: "a", scopes: ["one.scope"], stale: false },
      { instance: "b", scopes: ["two.scope"], stale: false },
    ],
    fingerprint: () => String(revision),
    intervalMs: 5000,
    logger: { warn: vi.fn() },
  });
  worker.start();
  await worker.idle();
  evaluate.mockClear();
  revision++;
  await vi.advanceTimersByTimeAsync(1000);
  await worker.idle();
  expect(evaluate.mock.calls.map((args) => args[0])).toEqual(["a", "b"]);
  await worker.stop();
});
it("logs failures and retries stale evidence on the next sweep", async () => {
  vi.useFakeTimers();
  const warn = vi.fn();
  const evaluate = vi
    .fn()
    .mockRejectedValueOnce(Error("failure"))
    .mockResolvedValue(undefined);
  const worker = createLegacyScopeRevalidator({
    evaluate,
    candidates: () => [{ instance: "i", scopes: ["one.scope"], stale: true }],
    fingerprint: () => "",
    intervalMs: 1000,
    logger: { warn },
  });
  worker.start();
  await worker.idle();
  expect(warn).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1000);
  await worker.idle();
  expect(evaluate).toHaveBeenCalledTimes(2);
  await worker.stop();
});

it("startup recovers an evaluation interrupted by restart", async () => {
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let stale = true;
  let covered = true;
  const first = createLegacyScopeRevalidator({
    evaluate: () => gate,
    candidates: () => [{ instance: "i", scopes: ["one.scope"], stale }],
    fingerprint: () => "",
    logger: { warn: vi.fn() },
  });
  first.start();
  await Promise.resolve();
  const stopping = first.stop();
  const next = createLegacyScopeRevalidator({
    evaluate: async () => {
      covered = false;
      stale = false;
    },
    candidates: () => [{ instance: "i", scopes: ["one.scope"], stale }],
    fingerprint: () => "",
    logger: { warn: vi.fn() },
  });
  next.start();
  await next.idle();
  expect(covered).toBe(false);
  release();
  await stopping;
  await next.stop();
});
