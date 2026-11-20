// The writer of one change-feed connection. A write the test holds open is a
// reader that stopped reading; no timers and no sleeps.
import { describe, expect, it } from "vitest";
import { createFeedWriter } from "./sync-event-writer.js";

/** A write whose completion the test controls. */
function heldWrites() {
  const sent: Array<{ event: string; data: unknown }> = [];
  const waiting: Array<() => void> = [];
  return {
    sent,
    write: (event: string, data: unknown) => {
      sent.push({ event, data });
      return new Promise<void>((resolve) => waiting.push(resolve));
    },
    /** The stream takes the frame it is holding. */
    accept: async () => {
      waiting.shift()?.();
      await Promise.resolve();
      await Promise.resolve();
    },
  };
}

describe("createFeedWriter", () => {
  it("writes frames owed together in a fixed order: status, then views", async () => {
    const held = heldWrites();
    const feed = createFeedWriter(held.write);
    feed.ready(); // in flight, held
    // Owed together while it is held, in the opposite order.
    feed.views(["a"]);
    feed.status({ syncing: false });
    await held.accept();
    await held.accept();
    await held.accept();
    expect(held.sent.map((f) => f.event)).toEqual(["ready", "status", "view"]);
  });

  it("holds bounded work while one write never completes, however many changes arrive", async () => {
    const held = heldWrites();
    const feed = createFeedWriter(held.write);
    feed.ready();
    // The first frame is in flight and never accepted.
    const changes = 10_000;
    for (let n = 0; n < changes; n++) {
      feed.views([`c${n % 3}`]);
      feed.status({ n });
    }
    // Nothing more was written: the loop is waiting on the first frame.
    expect(held.sent).toEqual([{ event: "ready", data: {} }]);
    // The reader catches up: what is owed is one status and one view frame.
    await held.accept();
    await held.accept();
    await held.accept();
    expect(held.sent).toEqual([
      { event: "ready", data: {} },
      { event: "status", data: { n: changes - 1 } },
      { event: "view", data: { connectionIds: ["c0", "c1", "c2"] } },
    ]);
  });

  it("delivers every change to a reader that keeps up", async () => {
    const sent: Array<{ event: string; data: unknown }> = [];
    const feed = createFeedWriter(async (event, data) => {
      sent.push({ event, data });
    });
    for (let n = 0; n < 5; n++) {
      feed.views([`c${n}`]);
      feed.status({ n });
      // The reader takes each frame before the next change arrives.
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
    }
    expect(sent.filter((f) => f.event === "view").map((f) => f.data)).toEqual([
      { connectionIds: ["c0"] },
      { connectionIds: ["c1"] },
      { connectionIds: ["c2"] },
      { connectionIds: ["c3"] },
      { connectionIds: ["c4"] },
    ]);
    expect(sent.filter((f) => f.event === "status").at(-1)?.data).toEqual({
      n: 4,
    });
  });

  it("writes nothing after close, and drops what was owed", async () => {
    const held = heldWrites();
    const feed = createFeedWriter(held.write);
    feed.ready();
    feed.views(["a"]);
    feed.close();
    await held.accept();
    feed.views(["b"]);
    feed.close();
    expect(held.sent).toEqual([{ event: "ready", data: {} }]);
  });

  it("stops after a write fails", async () => {
    const sent: string[] = [];
    const feed = createFeedWriter(async (event) => {
      sent.push(event);
      throw new Error("write failed");
    });
    feed.ready();
    feed.views(["a"]);
    await Promise.resolve();
    await Promise.resolve();
    feed.views(["b"]);
    await Promise.resolve();
    expect(sent).toEqual(["ready"]);
  });
});
