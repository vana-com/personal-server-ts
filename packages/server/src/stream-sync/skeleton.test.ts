import { describe, expect, it } from "vitest";
import { formatHops, formatStubs, runSkeleton } from "./skeleton.test-utils.js";

describe("stream-sync walking skeleton", () => {
  it("one record flows full server -> full/phone/frame and PS-Lite -> full/frame", async () => {
    const hops = await runSkeleton();
    expect(hops.length).toBeGreaterThanOrEqual(8);
    process.stdout.write(`${formatHops(hops)}\n`);
    process.stdout.write(`${formatStubs()}\n`);
    const failed = hops.filter((h) => !h.pass);
    expect(failed, formatHops(hops)).toEqual([]);
  }, 120_000);
});
