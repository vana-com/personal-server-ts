// Publish memory is bounded by the part size, not by the stream. A first
// publish of a stream four times larger must not grow the child's peak by the
// extra rows. The memory oracle measures a fresh child's kernel high-water
// mark, so a publisher that holds every row of the stream shows in full.
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import {
  buildPublishMemoryDb,
  type PublishMemoryResult,
} from "./publish-memory.workload.js";

const ROW_BYTES = 16_384;
const SMALL_ROWS = 1_500;
const LARGE_ROWS = 6_000;
let root: string;
let childModule: string;
const databases = new Map<number, string>();

beforeAll(async () => {
  const temporary = join(homedir(), ".tmp");
  mkdirSync(temporary, { recursive: true });
  root = mkdtempSync(join(temporary, "ps-publish-memory-"));
  childModule = join(root, "publish-memory.child.mjs");
  symlinkSync(
    fileURLToPath(new URL("../../../../node_modules", import.meta.url)),
    join(root, "node_modules"),
    "dir",
  );
  buildSync({
    entryPoints: [
      fileURLToPath(new URL("./publish-memory.workload.ts", import.meta.url)),
    ],
    outfile: childModule,
    bundle: true,
    platform: "node",
    format: "esm",
    packages: "external",
    target: "node22",
    logLevel: "silent",
  });
  for (const worker of ["better-sqlite3-worker.cjs", "statement-cache.cjs"])
    copyFileSync(
      fileURLToPath(new URL(`./${worker}`, import.meta.url)),
      join(root, worker),
    );
  for (const rows of [SMALL_ROWS, LARGE_ROWS]) {
    const path = join(root, `${rows}.sqlite`);
    await buildPublishMemoryDb(path, rows, ROW_BYTES);
    databases.set(rows, path);
  }
}, 600_000);
afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

async function peak(rows: number): Promise<number> {
  // Publish writes the database (watermark, head parts): give each child a copy.
  const path = join(
    root,
    `run-${rows}-${Math.random().toString(36).slice(2)}.sqlite`,
  );
  copyFileSync(databases.get(rows)!, path);
  try {
    const measured = await run<PublishMemoryResult>({
      module: childModule,
      exportName: "publishMemoryWorkload",
      args: { path },
    });
    process.stdout.write(
      "PUBLISH_MEMORY " + JSON.stringify({ rows, ...measured }) + "\n",
    );
    expect(measured.result.outcome).toBe("published");
    // One part per 16-bit prefix, and a few prefixes hold two rows.
    expect(measured.result.puts).toBeGreaterThanOrEqual(rows * 0.9);
    return measured.peakBytes;
  } finally {
    rmSync(path, { force: true });
  }
}

// Four times the rows adds 73.2 MiB of row bodies. What a publish keeps per
// part (the head's part list, the change list, the commit statements) is about
// 4 KiB per row here, where every row is its own part: +18 MiB measured. A
// publisher that held the stream's rows added 108 MiB before this test's fix.
// The margin sits between the two.
const MARGIN = 32 * 1024 * 1024;

it("publish-memory-does-not-grow-with-the-stream", async () => {
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[1]!;
  const small: number[] = [];
  const large: number[] = [];
  for (let repetition = 0; repetition < 3; repetition++) {
    small.push(await peak(SMALL_ROWS));
    large.push(await peak(LARGE_ROWS));
  }
  process.stdout.write(
    "PUBLISH_MEMORY_COMPARISON " +
      JSON.stringify({
        small,
        large,
        median: { small: median(small), large: median(large) },
      }) +
      "\n",
  );
  expect(median(large)).toBeLessThanOrEqual(median(small) + MARGIN);
}, 1_800_000);
