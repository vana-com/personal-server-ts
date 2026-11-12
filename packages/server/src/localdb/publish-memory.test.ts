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
  buildRowsDb,
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

/**
 * Peak of one child over a database built by `build`. Fresh copy per run: the
 * workloads write (the spool) and the next run must start from the same file.
 */
async function measure<T>(
  name: string,
  exportName: string,
  build: () => Promise<string>,
): Promise<{ peakBytes: number; result: T }> {
  const source = await build();
  const path = `${source}.run-${Math.random().toString(36).slice(2)}`;
  copyFileSync(source, path);
  try {
    const measured = await run<T>({
      module: childModule,
      exportName,
      args: { path },
    });
    process.stdout.write(
      `${name} ` +
        JSON.stringify({
          peakBytes: measured.peakBytes,
          result: measured.result,
        }) +
        "\n",
    );
    return measured;
  } finally {
    rmSync(path, { force: true });
  }
}

const extra = new Set<string>();
const median3 = (values: number[]) => [...values].sort((a, b) => a - b)[1]!;
const BLOB = "ab".repeat(32);

// One attachment named by every record of a stream. Finding it must not read
// every referring body at once: 6,000 rows of 16 KiB are 98 MiB. A lookup that
// pages the referrers and stops at the first that names the blob keeps a few
// rows, however many refer to it.
it("listing-a-shared-attachment-does-not-grow-with-its-referrers", async () => {
  const build = (rows: number) => async () => {
    const path = join(root, `fanout-${rows}.sqlite`);
    if (!extra.has(path)) {
      await buildRowsDb(path, rows, ROW_BYTES, BLOB);
      extra.add(path);
    }
    return path;
  };
  const small: number[] = [];
  const large: number[] = [];
  for (let repetition = 0; repetition < 3; repetition++) {
    for (const [rows, into] of [
      [SMALL_ROWS, small],
      [LARGE_ROWS, large],
    ] as const) {
      const { peakBytes, result } = await measure<{ blobs: number }>(
        `LIST_BLOBS_MEMORY rows=${rows}`,
        "listBlobsWorkload",
        build(rows),
      );
      expect(result.blobs).toBe(1);
      into.push(peakBytes);
    }
  }
  process.stdout.write(
    "LIST_BLOBS_MEMORY_COMPARISON " +
      JSON.stringify({
        small,
        large,
        median: { small: median3(small), large: median3(large) },
      }) +
      "\n",
  );
  // Four times the referrers add 73 MiB of bodies. A bounded lookup adds none.
  expect(median3(large)).toBeLessThanOrEqual(median3(small) + MARGIN);
}, 1_800_000);

// One prefix of very large bodies. A page is cut by bytes as well as rows, so
// a prefix five times larger must not grow the peak by the extra bodies. With
// a page of 64 rows, 40 bodies of 2 MiB were one 80 MiB page.
const HUGE_BODY = 2 * 1024 * 1024;
it("encoding-large-bodies-does-not-grow-with-the-prefix", async () => {
  const build = (rows: number) => async () => {
    const path = join(root, `huge-${rows}.sqlite`);
    if (!extra.has(path)) {
      await buildRowsDb(path, rows, HUGE_BODY);
      extra.add(path);
    }
    return path;
  };
  const small: number[] = [];
  const large: number[] = [];
  for (let repetition = 0; repetition < 3; repetition++) {
    for (const [rows, into] of [
      [8, small],
      [40, large],
    ] as const) {
      const { peakBytes, result } = await measure<{ puts: number }>(
        `HUGE_BODIES_MEMORY rows=${rows}`,
        "encodeOnePrefixWorkload",
        build(rows),
      );
      expect(result.puts).toBeGreaterThan(0);
      into.push(peakBytes);
    }
  }
  process.stdout.write(
    "HUGE_BODIES_MEMORY_COMPARISON " +
      JSON.stringify({
        small,
        large,
        median: { small: median3(small), large: median3(large) },
      }) +
      "\n",
  );
  // 32 more bodies are 64 MiB of text, and a copy of each as bytes.
  expect(median3(large)).toBeLessThanOrEqual(median3(small) + 24 * 1024 * 1024);
}, 1_800_000);
