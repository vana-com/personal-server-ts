/**
 * Guard against baseline slack hiding retention (see the helper's contract in
 * packages/core/src/test-support/memory-oracle.ts). The workload imports the
 * publish harness, so the empty baseline loads the same modules. At the budget
 * scale of the publish cases (96 MiB) a retain-all workload must still read as
 * about what it retained. If it does not, the delta cannot gate that case.
 */

import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";

const WORKLOAD = fileURLToPath(
  new URL("./memory-oracle.retain.workload.ts", import.meta.url),
);
const MiB = 1024 * 1024;

describe("memory-oracle under the publish harness baseline", () => {
  it("reads a 96 MiB retain-all at about its full size", async () => {
    const r = await run({
      module: WORKLOAD,
      exportName: "retainAll",
      args: { mib: 96 },
    });
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * 96 * MiB);
  }, 120_000);
});
