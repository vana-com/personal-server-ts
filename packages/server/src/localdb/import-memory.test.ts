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

async function measure(
  fixture: ImportMemoryFixture,
  path: "node" | "upload",
  loadWhole = false,
) {
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
      args: { fixture, path, loadWhole, workRoot },
      // glibc gives the SQLite worker thread its own malloc arena and keeps
      // memory it has freed there. That adds 15-20 MiB between 4x and 16x
      // (arena cap 1: 6 MiB; in-thread driver: 8 MiB) and reads as growth
      // with row count at the margin below. One arena measures the workload.
      env: { MALLOC_ARENA_MAX: "1" },
    });
  } finally {
    rmSync(workRoot, { recursive: true, force: true });
  }
  process.stdout.write(
    "IMPORT_MEMORY " +
      JSON.stringify({
        path,
        loadWhole,
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
  expect(measured.result.retainedRows).toBe(loadWhole ? fixture.rows : 0);
  expect(measured.result.retainedPayloadBytes).toBe(
    loadWhole ? fixture.payloadBytes : 0,
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
async function compare(path: "node" | "upload", loadWhole = false) {
  const small: number[] = [];
  const large: number[] = [];
  // RSS includes allocator/collector and startup scatter. Compare the median
  // of three independent children at each size; keep every raw peak above.
  // The whole-source mutant uses the identical sampling and growth assertion.
  for (let repetition = 0; repetition < 3; repetition++) {
    small.push((await measure(fixtures[0]!, path, loadWhole)).peakBytes);
    large.push((await measure(fixtures[1]!, path, loadWhole)).peakBytes);
  }
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[1]!;
  const result = { small: median(small), large: median(large) };
  process.stdout.write(
    "IMPORT_MEMORY_COMPARISON " +
      JSON.stringify({
        path,
        loadWhole,
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
  const { small, large } = await compare("upload", true);
  expect(() => expectBoundedGrowth(small, large)).toThrow();
}, 1_800_000);
