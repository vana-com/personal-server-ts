#!/usr/bin/env node
/**
 * Cost of one upload selection pass (findUnsynced + planning, metadata only)
 * over a large unsynced backlog, on a real host index.
 *
 *   node --expose-gc scripts/measure-upload-selection.mjs <lite|server|core> <single|many> [rows=100000]
 *
 * Needs `npm run build` first (imports package dist). Run each scenario in
 * its own process: peak RSS is a process-wide high-water mark.
 * `single`: all rows in one coalesced (memory) scope. `many`: 1,000 ordinary scopes. `manymem`: 1,000 coalesced scopes.
 * Every row is inside the coalescing quiet window, so nothing uploads and the
 * pass is selection and planning only. Prints one JSON line.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PerformanceObserver, performance } from "node:perf_hooks";

const [host, layout, rowsArg] = process.argv.slice(2);
const N = Number(rowsArg ?? 100_000);
if (
  !["lite", "server", "core"].includes(host) ||
  !["single", "many", "manymem"].includes(layout)
) {
  console.error(
    "usage: measure-upload-selection.mjs <lite|server|core> <single|many|manymem> [rows]",
  );
  process.exit(2);
}
const T0 = Date.parse("2026-11-07T12:00:00Z");
const scopeOf = (i) =>
  layout === "single"
    ? "memory.bench"
    : layout === "manymem"
      ? `memory.bench${i % 1000}`
      : `bench.scope${i % 1000}`;
const rowAt = (i) => ({
  id: i + 1,
  fileId: null,
  schemaId: null,
  path: `${scopeOf(i)}/${new Date(T0 + i).toISOString()}.json`,
  scope: scopeOf(i),
  collectedAt: new Date(T0 + i).toISOString(),
  createdAt: new Date(T0 + i).toISOString(),
  sizeBytes: 1024,
  version: i + 1,
  dataPointId: null,
});

let storage;
if (host === "lite") {
  const { createPersistentPsLiteStorage } =
    await import("../packages/lite/dist/storage.js");
  const state = {
    version: 1,
    nextId: N + 1,
    entries: Array.from({ length: N }, (_, i) => rowAt(i)),
    envelopes: [],
  };
  const persistence = {
    read: async () => state,
    write: async () => {},
  };
  const files = {
    kind: "custom",
    readEnvelope: async () => null,
    writeEnvelope: async () => 0,
    deleteEnvelope: async () => {},
  };
  storage = await createPersistentPsLiteStorage(
    { kind: "custom" },
    persistence,
    files,
  );
} else if (host === "server") {
  const { initializeDatabase } =
    await import("../packages/server/dist/storage/index-schema.js");
  const { createIndexManager } =
    await import("../packages/server/dist/storage/index-manager.js");
  const dir = mkdtempSync(join(process.env.HOME, ".tmp", "upload-measure-"));
  const db = initializeDatabase(join(dir, "index.db"));
  const insert = db.prepare(
    `INSERT INTO data_files (file_id, schema_id, path, scope, collected_at, created_at, size_bytes, version, cas_revision, data_point_id)
     VALUES (NULL, NULL, @path, @scope, @collectedAt, @createdAt, @sizeBytes, @version, @version, NULL)`,
  );
  db.transaction(() => {
    for (let i = 0; i < N; i++) insert.run(rowAt(i));
  })();
  storage = createIndexManager(db);
  console.error(`index db: ${dir}`);
} else {
  const rows = Array.from({ length: N }, (_, i) => rowAt(i));
  storage = {
    findUnsynced: () =>
      rows
        .filter((r) => r.dataPointId === null)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt)),
  };
}

const { uploadAll } =
  await import("../packages/core/dist/sync/workers/upload.js");
const deps = {
  storage,
  storageAdapter: {},
  gateway: {},
  signer: {},
  masterKey: new Uint8Array(65),
  serverOwner: "0x0",
  logger: { info() {}, warn() {}, error() {}, debug() {} },
};
const now = new Date(T0 + N + 1000);

globalThis.gc?.();
const heap0 = process.memoryUsage().heapUsed;
// GC events during the pass: with none, heap only grew, so heapAfter is the
// peak; with some, heapAfter is a lower bound of the peak.
let gcDuringPass = 0;
const gcWatcher = new PerformanceObserver((list) => {
  for (const e of list.getEntries())
    if (e.startTime >= t0 && e.startTime <= tEnd) gcDuringPass++;
});
gcWatcher.observe({ entryTypes: ["gc"] });
const t0 = performance.now();
const results = await uploadAll(deps, { now: () => now });
const tEnd = performance.now();
const ms = tEnd - t0;
const heap1 = process.memoryUsage().heapUsed;
await new Promise((r) => setTimeout(r, 50)); // let GC entries arrive
gcWatcher.disconnect();
const MiB = 1024 * 1024;
console.log(
  JSON.stringify({
    host,
    layout,
    rows: N,
    uploaded: results.length,
    wallMs: Math.round(ms),
    heapBeforeMiB: +(heap0 / MiB).toFixed(1),
    heapAfterMiB: +(heap1 / MiB).toFixed(1),
    heapGrowthMiB: +((heap1 - heap0) / MiB).toFixed(1),
    gcDuringPass,
  }),
);
