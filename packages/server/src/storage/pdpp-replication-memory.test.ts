import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { expect, it } from "vitest";
const memoryRoot = process.env.TMPDIR ?? join(homedir(), ".tmp");
mkdirSync(memoryRoot, { recursive: true });

it("bounds real transport-worker memory across 32, 64 and 128 MiB blobs", () => {
  const results: { size: number; published: number; peakRssKiB: number }[] = [];
  for (const sizeMiB of [32, 64, 128]) {
    const directory = mkdtempSync(join(memoryRoot, "replica-memory-"));
    try {
      for (const mode of ["seed", "measure"]) {
        const child = spawnSync(
          process.execPath,
          [
            "--max-old-space-size=1536",
            "--import",
            "tsx",
            new URL("./pdpp-replication-memory.fixture.ts", import.meta.url)
              .pathname,
            mode,
            directory,
            String(sizeMiB * 1024 * 1024),
          ],
          { encoding: "utf8", timeout: 300000, maxBuffer: 16384 },
        );
        expect(child.status, child.stderr.slice(-4000)).toBe(0);
        if (mode === "measure") {
          results.push(JSON.parse(child.stdout));
          console.log("worker memory sample", results.at(-1));
        }
      }
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
  console.log("real worker memory", results);
  for (const result of results) {
    expect(result.published).toBeGreaterThan(0);
    expect(result.peakRssKiB).toBeLessThan(384 * 1024);
  }
  expect(
    Math.max(...results.map((r) => r.peakRssKiB)) -
      Math.min(...results.map((r) => r.peakRssKiB)),
  ).toBeLessThan(96 * 1024);
}, 900000);
