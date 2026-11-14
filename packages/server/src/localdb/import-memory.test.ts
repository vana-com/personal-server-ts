import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import {
  createImportMemoryFixture,
  buildImportMemoryChild,
  MEMORY_ROWS,
  MEMORY_ROW_BYTES,
  type ImportMemoryFixture,
} from "./import-memory-fixture.test-utils.js";
import type { ImportMemoryResult } from "./import-memory.child.js";

const fixtures: ImportMemoryFixture[] = [];
let root: string;
let childModule: string;
let sample = 0;
beforeAll(() => {
  const temporary = join(homedir(), ".tmp");
  mkdirSync(temporary, { recursive: true });
  root = mkdtempSync(join(temporary, "ps3-import-memory-"));
  childModule = buildImportMemoryChild(root);
  for (const multiplier of [1, 4]) {
    const directory = join(root, String(multiplier));
    mkdirSync(directory);
    fixtures.push(
      createImportMemoryFixture(directory, MEMORY_ROWS * multiplier),
    );
  }
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

// Allow two existing 4 MiB source-page workspaces for the decode/merge handoff
// and allocator/GC scatter. This constant does not scale with the input: 4x
// adds 105.5 MiB of rows, and LOAD_WHOLE must fail this exact comparison.
// The attribution probe separately reports actual page-cache and batch bytes.
const PAGE_MARGIN = 2 * 4 * 1024 * 1024;
function expectBoundedGrowth(small: number, large: number) {
  expect(large).toBeLessThanOrEqual(small + PAGE_MARGIN);
}
async function compare(path: "node" | "upload", retention: Retention = {}) {
  const small: number[] = [];
  const large: number[] = [];
  // RSS includes allocator/collector and startup scatter. Compare the median
  // of three independent children at each size; keep every raw peak above.
  // Every retention mutant uses the identical sampling and growth assertion.
  for (let repetition = 0; repetition < 3; repetition++) {
    small.push((await measure(fixtures[0]!, path, retention)).peakBytes);
    large.push((await measure(fixtures[1]!, path, retention)).peakBytes);
  }
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[1]!;
  const result = { small: median(small), large: median(large) };
  process.stdout.write(
    "IMPORT_MEMORY_COMPARISON " +
      JSON.stringify({
        path,
        ...retention,
        small,
        large,
        median: result,
      }) +
      "\n",
  );
  return result;
}
it.each(["node", "upload"] as const)(
  "import-memory-does-not-grow-%s",
  async (path) => {
    const { small, large } = await compare(path);
    expectBoundedGrowth(small, large);
  },
  1_800_000,
);
it("import-load-whole-mutant-fails", async () => {
  const { small, large } = await compare("upload", { loadWhole: true });
  expect(() => expectBoundedGrowth(small, large)).toThrow();
}, 1_800_000);
// Partial retention. At equal resident bytes per payload byte, keeping one row
// in N adds (9,000 - 2,250) / N rows of 16 KiB between 1x and 4x: 10.55 MiB for
// N = 10 (2.55 MiB above the 8 MiB margin) and 26.37 MiB for N = 4. RSS is not
// an exact byte counter, so the repetition count in the PR body, not this
// arithmetic, is the claim about how reliably each is caught.
it.each(
  (["node", "upload"] as const).flatMap((path) =>
    [10, 4].map((retainEvery) => [path, retainEvery] as const),
  ),
)(
  "import-%s-retaining-every-%ith-record-fails",
  async (path, retainEvery) => {
    const { small, large } = await compare(path, { retainEvery });
    expect(() => expectBoundedGrowth(small, large)).toThrow();
  },
  1_800_000,
);
