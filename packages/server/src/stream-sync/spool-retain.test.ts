/**
 * Red test for the spool read path. A reducer keeps a winner's line text for
 * the whole bucket, and those texts come from every chunk of the spool. If a
 * kept text is a view into the decoded chunk, it pins that chunk, so the peak
 * tracks the input size, not the number of kept lines. At 192 MiB (2x the
 * 96 MiB the sweep uses) the pinned build reads about the input, and the fixed
 * build reads its churn floor of about 55 MiB. The limit sits between them.
 */

import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";

const WORKLOAD = fileURLToPath(
  new URL("./spool-retain.workload.ts", import.meta.url),
);
const MiB = 1024 * 1024;
const DATA = process.env.STREAM_SYNC_P1_DATA_DIR ?? "/tmp";

describe("spool read path retains only the kept lines", () => {
  it("keeping every 100th line of 192 MiB does not pin the whole spool", async () => {
    await mkdir(DATA, { recursive: true });
    const r = await run(
      {
        module: WORKLOAD,
        exportName: "retainWinners",
        args: {
          path: `${DATA}/spool-retain-v2-192.spool`,
          mib: 192,
          keepEvery: 100,
        },
      },
      { gc: "timer25ms" },
    );
    const out = r.result as { lines: number; kept: number };
    expect(out.lines).toBe((192 * MiB) / (16 * 1024));
    expect(out.kept).toBe(Math.ceil(out.lines / 100));
    expect(r.peakBytes).toBeLessThan(0.5 * 192 * MiB);
  }, 120_000);
});
