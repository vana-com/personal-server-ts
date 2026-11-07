import { describe, expect, it } from "vitest";
import {
  StreamSyncHomeClosedError,
  createStreamSyncIoBarrier,
} from "./io-barrier.js";
import { createMemoryStreamSyncFiles } from "./memory-files.js";

const settles = async (promise: Promise<unknown>) => {
  let done = false;
  void promise.then(() => (done = true));
  await new Promise((r) => setTimeout(r, 20));
  return done;
};

describe("stream-sync I/O barrier", () => {
  it("resolves shut() at once when nothing is in flight", async () => {
    const barrier = createStreamSyncIoBarrier();
    await barrier.shut();
    await barrier.shut();
  });

  it("does not count an iterator that was never started", async () => {
    const barrier = createStreamSyncIoBarrier();
    const files = barrier.guard(createMemoryStreamSyncFiles());
    files.readChunks("x")[Symbol.asyncIterator]();
    await barrier.shut();
  });

  it("refuses to start an iterator after shut(), but lets a started one finish", async () => {
    const barrier = createStreamSyncIoBarrier();
    const files = barrier.guard(createMemoryStreamSyncFiles());
    await files.write("log", new Uint8Array([1]));
    const started = files.readChunks("log")[Symbol.asyncIterator]();
    await started.next();
    const closing = barrier.shut();
    expect(await settles(closing)).toBe(false);
    await expect(
      files.readChunks("log")[Symbol.asyncIterator]().next(),
    ).rejects.toBeInstanceOf(StreamSyncHomeClosedError);
    expect((await started.next()).done).toBe(true);
    await closing;
  });

  it("an operation that fails still leaves the count", async () => {
    const barrier = createStreamSyncIoBarrier();
    const memory = createMemoryStreamSyncFiles();
    const files = barrier.guard({
      ...memory,
      read: async () => {
        throw new Error("disk");
      },
    });
    await expect(files.read("x")).rejects.toThrow("disk");
    await barrier.shut();
  });

  it("return() before the first next() is harmless", async () => {
    const barrier = createStreamSyncIoBarrier();
    const files = barrier.guard(createMemoryStreamSyncFiles());
    const it = files.readChunks("x")[Symbol.asyncIterator]();
    await it.return!();
    await barrier.shut();
  });
});
