import { describe, expect, it } from "vitest";
import { readAhead } from "./read-ahead.js";

const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** A source that logs when each item's read starts and ends. */
function source(items: number[], log: string[], failAt?: number) {
  return (async function* () {
    try {
      for (const item of items) {
        log.push(`start ${item}`);
        await tick();
        if (item === failAt) throw new Error(`read ${item} failed`);
        log.push(`end ${item}`);
        yield item;
      }
    } finally {
      log.push("closed");
    }
  })();
}

describe("readAhead", () => {
  it("yields the source's items in order", async () => {
    const log: string[] = [];
    const seen: number[] = [];
    for await (const item of readAhead(source([1, 2, 3, 4], log)))
      seen.push(item);
    expect(seen).toEqual([1, 2, 3, 4]);
  });

  it("starts the next read before the consumer is done with the current item", async () => {
    const log: string[] = [];
    const iterator = readAhead(source([1, 2, 3], log));
    expect((await iterator.next()).value).toBe(1);
    await tick();
    await tick();
    // The consumer has not asked again, and item 2 has been read already.
    expect(log).toContain("end 2");
    // But no further: one item of lookahead, never two.
    expect(log).not.toContain("start 3");
    await iterator.return(undefined);
  });

  it("never has two reads in flight", async () => {
    let inFlight = 0;
    let peak = 0;
    const gen = (async function* () {
      for (let i = 0; i < 6; i++) {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await tick();
        inFlight -= 1;
        yield i;
      }
    })();
    for await (const _ of readAhead(gen)) await tick();
    expect(peak).toBe(1);
  });

  it("closes the source when the consumer stops, after the read in flight ends", async () => {
    const log: string[] = [];
    for await (const item of readAhead(source([1, 2, 3], log))) {
      if (item === 1) break;
    }
    expect(log.at(-1)).toBe("closed");
    expect(log.indexOf("end 2")).toBeLessThan(log.indexOf("closed"));
    expect(log).not.toContain("start 3");
  });

  it("reports a failed read to the consumer at the item it belongs to, not before", async () => {
    const log: string[] = [];
    const seen: number[] = [];
    await expect(
      (async () => {
        for await (const item of readAhead(source([1, 2, 3], log, 2)))
          seen.push(item);
      })(),
    ).rejects.toThrow("read 2 failed");
    expect(seen).toEqual([1]);
  });

  it("does not leave an unhandled rejection when the consumer stops before a failing read is used", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const log: string[] = [];
      for await (const item of readAhead(source([1, 2], log, 2))) {
        if (item === 1) break;
      }
      await tick();
      await tick();
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("ends cleanly on an empty source", async () => {
    const log: string[] = [];
    const seen: number[] = [];
    for await (const item of readAhead(source([], log))) seen.push(item);
    expect(seen).toEqual([]);
    expect(log).toEqual(["closed"]);
  });
});
