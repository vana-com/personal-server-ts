/**
 * Selection cost over a 100,000-row backlog. Slow, so it only runs on request:
 *
 *   UPLOAD_SCALE=1 npx vitest run --maxWorkers=1 packages/core/src/sync/workers/upload.scale.test.ts
 *
 * Host-index numbers (lite, server SQLite) come from
 * `scripts/measure-upload-selection.mjs`, which needs a build.
 */
import { describe, expect, it, vi } from "vitest";
import type { IndexEntry } from "../../storage/index/types.js";
import type { UploadWorkerDeps } from "./upload.js";
import { uploadAll } from "./upload.js";

const ROWS = 100_000;
const T0 = Date.parse("2026-11-07T12:00:00Z");

function backlog(scopeOf: (i: number) => string): IndexEntry[] {
  return Array.from({ length: ROWS }, (_, i) => ({
    id: i + 1,
    fileId: null,
    schemaId: null,
    path: `${scopeOf(i)}/${i}.json`,
    scope: scopeOf(i),
    collectedAt: new Date(T0 + i).toISOString(),
    createdAt: new Date(T0 + i).toISOString(),
    sizeBytes: 1024,
    version: i + 1,
    dataPointId: null,
  }));
}

function depsFor(rows: IndexEntry[]): UploadWorkerDeps {
  return {
    storage: { findUnsynced: vi.fn(() => rows) },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  } as unknown as UploadWorkerDeps;
}

describe.skipIf(!process.env.UPLOAD_SCALE)(
  "uploadAll selection at 100,000 unsynced rows",
  () => {
    it.each([
      ["one coalesced scope", () => "memory.bench"],
      ["1,000 coalesced scopes", (i: number) => `memory.bench${i % 1000}`],
      ["1,000 ordinary scopes", (i: number) => `bench.scope${i % 1000}`],
    ])("plans %s in well under a second", async (_name, scopeOf) => {
      const rows = backlog(scopeOf);
      const startedAt = performance.now();
      const results = await uploadAll(depsFor(rows), {
        now: () => new Date(T0 + ROWS + 1000),
      });
      const elapsedMs = performance.now() - startedAt;
      expect(results).toEqual([]);
      expect(elapsedMs).toBeLessThan(1000);
    });
  },
);
