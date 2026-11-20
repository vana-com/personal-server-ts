// A first run that proves a large stream publishes it whole when it fits one
// segment (its completion and its changes in one segment). The publisher
// handled the stream's keys as call arguments (`push(...keys)`), so a stream
// of about 125k keys or more overflowed the call stack. The size is the point
// of this test: it is above what a spread can take, and still within one
// segment. A replacing stream larger than a segment goes in rounds
// (`log-replace-split.test.ts`).
import { afterEach, describe, expect, it } from "vitest";
import { closeWorldDrivers, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

// Above the ~125k a spread overflows at, and below what one 16 MiB segment holds.
const KEYS = 125_000;

describe("log publish of a very large stream", () => {
  it("publishes a stream with more keys than a call can take as arguments", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "r1",
      Array.from({ length: KEYS }, (_, i) => ({ stream: "s0", id: i })),
    );
    await a.cycle();
    expect(await a.position()).toBeGreaterThan(0);
  }, 180_000);
});
