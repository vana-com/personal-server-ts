import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it } from "vitest";
import { IMPORT_CHUNK_BYTES } from "../../../core/src/localdb/legacy-import.js";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import {
  createImportMemoryFixture,
  buildImportMemoryChild,
  MEMORY_ROWS,
  MEMORY_ROW_BYTES,
  type ImportMemoryFixture,
} from "./import-memory-fixture.test-utils.js";
import type { ImportMemoryResult } from "./import-memory.child.js";

let root: string;
let childModule: string;
let sample = 0;
beforeAll(() => {
  const temporary = join(homedir(), ".tmp");
  mkdirSync(temporary, { recursive: true });
  root = mkdtempSync(join(temporary, "ps3-import-memory-"));
  childModule = buildImportMemoryChild(root);
}, 600_000);
afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

/** What the child keeps reachable through the final HWM read. Default: nothing. */
interface Retention {
  /** Every source record. */
  loadWhole?: boolean;
  /** Every Nth source record (indexes 0, N, 2N, ...). */
  retainEvery?: number;
}
const retainedRowsFor = (fixture: ImportMemoryFixture, r: Retention) =>
  r.loadWhole
    ? fixture.rows
    : r.retainEvery
      ? Math.ceil(fixture.rows / r.retainEvery)
      : 0;

async function measure(
  fixture: ImportMemoryFixture,
  path: "node" | "upload",
  retention: Retention = {},
) {
  const loadWhole = retention.loadWhole ?? false;
  expect(fixture.bytes).toBe(fixture.rows * MEMORY_ROW_BYTES);
  // Share only immutable input; every fresh child gets a new database and
  // staging area, removed as soon as its peak has been reported.
  const workRoot = join(root, `measurement-${++sample}`);
  mkdirSync(workRoot);
  let measured;
  try {
    measured = await run<ImportMemoryResult>({
      module: childModule,
      exportName: "importMemoryWorkload",
      args: {
        fixture,
        path,
        loadWhole,
        retainEvery: retention.retainEvery,
        workRoot,
      },
      // glibc gives the SQLite worker thread its own malloc arena and keeps
      // memory it has freed there. That adds 15-20 MiB between 4x and 16x
      // (arena cap 1: 6 MiB; in-thread driver: 8 MiB) and reads as growth
      // with row count at the margin below. One arena measures the workload.
      env: { MALLOC_ARENA_MAX: "1" },
      // A fixed small nursery (4 MiB semi-space, 8 MiB reported capacity). With
      // V8's default nursery the upload path read 18-30 MB more peak RSS at 4x
      // than at 1x (node: -4 to 14 MB); with this setting 4x minus 1x is 2-4 MB
      // on upload and 5-6 MB on node. So this setting measurably removes the
      // size-dependent RSS difference. Diagnostic that points at capacity, not
      // live data: after a full GC the live old and large-object space was the
      // same at 1x and 4x in both the main and the SQLite worker isolate, and
      // RSS did not fall after the GC. It is not a full attribution: the first
      // RSS step happens while V8 still reports its initial 64 MB capacity, so
      // it is consistent with touching that capacity, not proof of it. It does
      // NOT measure default-runtime memory: a phone or server with V8's default
      // nursery holds more young-generation pages than this test charges. The
      // retention controls below must fail this same comparison.
      maxSemiSpaceMiB: 4,
    });
  } finally {
    rmSync(workRoot, { recursive: true, force: true });
  }
  process.stdout.write(
    "IMPORT_MEMORY " +
      JSON.stringify({
        path,
        loadWhole,
        retainEvery: retention.retainEvery,
        fixtureBytes: fixture.bytes,
        node: process.version,
        abi: process.versions.modules,
        ...measured,
      }) +
      "\n",
  );
  expect(measured.result.kind).toBe("imported");
  expect(measured.result.rows).toBe(fixture.rows);
  expect(measured.result.receiptRows).toBe(fixture.rows);
  expect(measured.result.payloadBytes).toBe(fixture.payloadBytes);
  const retainedRows = retainedRowsFor(fixture, retention);
  expect(measured.result.retainedRows).toBe(retainedRows);
  // Every fixture row carries the same payload size.
  expect(fixture.payloadBytes % fixture.rows).toBe(0);
  expect(measured.result.retainedPayloadBytes).toBe(
    retainedRows * (fixture.payloadBytes / fixture.rows),
  );
  return measured;
}

// What the test protects: the import holds a batch, not the input. Two
// readings test that claim with different allowances, not exact heap bounds.
//
// 1. Live bytes (main-isolate heap plus external after two full collections,
//    rows still reachable). This measures retention. Byte-identical readings
//    across repeated children were observed on the tested runtime, not
//    guaranteed by two collections or independent of timing. The clean import
//    held 0.1 MiB more at 4x than at 1x (upload) or 1.1 MiB less (node).
//    The allowance reuses the real import batch threshold, IMPORT_CHUNK_BYTES
//    (4 MiB). A batch's character budget is not an exact bound on retained
//    heap: objects and statements add overhead, and a row can cross the
//    threshold. Detection floor: retention growth of 4 MiB or less from 1x to
//    4x input passes by design. Retaining every 10th row adds 10 MiB between
//    1x and 4x, every 4th 26 MiB, the whole input 106 MiB.
// 2. Peak resident size, a high-water mark. It is a maximum over the run, so it
//    rises with run length and with when the 25 ms collector timer fires: the
//    clean upload peak rose 70, 78, 84, 90, 91 MiB at 1x, 4x, 16x, 32x, 64x
//    and stopped (a per-row leak would keep climbing), and CI saw 2 to 12 MiB of
//    4x-minus-1x on code that never touched the import. A margin tighter than
//    that noise cannot tell a clean import from one that keeps every 10th row.
//    The guard against materializing the input allows peak growth of half the
//    bytes the larger input adds. This is a calibrated tolerance backed by the
//    load-whole control below, not a consequence of batching.
const LIVE_MARGIN = IMPORT_CHUNK_BYTES;
interface Growth {
  addedBytes: number;
  peak: { small: number; large: number };
  live: { small: number; large: number };
}
function expectBoundedLive({ live }: Growth) {
  expect(live.large).toBeLessThanOrEqual(live.small + LIVE_MARGIN);
}
function expectBoundedPeak({ peak, addedBytes }: Growth) {
  expect(peak.large).toBeLessThanOrEqual(peak.small + addedBytes / 2);
}
async function compare(
  path: "node" | "upload",
  retention: Retention = {},
): Promise<Growth> {
  // Fixtures exist only for this comparison and are removed on success and on
  // failure; the 1x and 4x inputs together are about 0.6 GB.
  const directory = mkdtempSync(join(root, "fixtures-"));
  try {
    const fixtures = [1, 4].map((multiplier) => {
      const at = join(directory, String(multiplier));
      mkdirSync(at);
      return createImportMemoryFixture(at, MEMORY_ROWS * multiplier);
    });
    const peak = { small: [] as number[], large: [] as number[] };
    const live = { small: [] as number[], large: [] as number[] };
    // Compare the median of three independent children at each size; keep
    // every raw reading above. Every retention mutant uses the same sampling.
    for (let repetition = 0; repetition < 3; repetition++) {
      for (const [size, fixture] of [
        ["small", fixtures[0]!],
        ["large", fixtures[1]!],
      ] as const) {
        const measured = await measure(fixture, path, retention);
        peak[size].push(measured.peakBytes);
        live[size].push(measured.result.liveBytes);
      }
    }
    const median = (values: number[]) => [...values].sort((a, b) => a - b)[1]!;
    const growth: Growth = {
      addedBytes: fixtures[1]!.bytes - fixtures[0]!.bytes,
      peak: { small: median(peak.small), large: median(peak.large) },
      live: { small: median(live.small), large: median(live.large) },
    };
    process.stdout.write(
      "IMPORT_MEMORY_COMPARISON " +
        JSON.stringify({ path, ...retention, peak, live, median: growth }) +
        "\n",
    );
    return growth;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}
it.each(["node", "upload"] as const)(
  "import-memory-does-not-grow-%s",
  async (path) => {
    const growth = await compare(path);
    expectBoundedLive(growth);
    expectBoundedPeak(growth);
  },
  1_800_000,
);
it("import-load-whole-mutant-fails", async () => {
  const growth = await compare("upload", { loadWhole: true });
  expect(() => expectBoundedLive(growth)).toThrow();
  expect(() => expectBoundedPeak(growth)).toThrow();
}, 1_800_000);
// Partial retention. Keeping one row in N adds (9,000 - 2,250) / N rows of
// 16 KiB between 1x and 4x: 10.55 MiB for N = 10 and 26.37 MiB for N = 4, both
// above the one-batch live margin. The peak reading is not asserted here: the
// noise above is larger than the N = 10 signal.
it.each(
  (["node", "upload"] as const).flatMap((path) =>
    [10, 4].map((retainEvery) => [path, retainEvery] as const),
  ),
)(
  "import-%s-retaining-every-%ith-record-fails",
  async (path, retainEvery) => {
    const growth = await compare(path, { retainEvery });
    expect(() => expectBoundedLive(growth)).toThrow();
  },
  1_800_000,
);
