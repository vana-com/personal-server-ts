import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import { createMemoryStreamSyncBlobs } from "../../packages/core/src/stream-sync/index.js";
globalThis.memoryDatabasePath = (id) =>
  join(process.env.MEMORY_DIR, id + ".db");
const blobDir = join(process.env.MEMORY_DIR, "blobs");
mkdirSync(blobDir, { recursive: true });
const blobPath = (key) => join(blobDir, Buffer.from(key).toString("hex"));
globalThis.memoryBlobs = {
  governor: createMemoryStreamSyncBlobs().governor,
  put: async (key, bytes) => writeFileSync(blobPath(key), bytes),
  get: async (key) =>
    existsSync(blobPath(key))
      ? new Uint8Array(readFileSync(blobPath(key)))
      : null,
  exists: async (key) => existsSync(blobPath(key)),
  keys: () =>
    readdirSync(blobDir).map((name) => Buffer.from(name, "hex").toString()),
  delete: (key) => {
    if (existsSync(blobPath(key))) unlinkSync(blobPath(key));
  },
};
// The same decoded-unit WeakRef boundary as the general memory harness, with
// synthetic verified history so source size and history can vary independently.
import { progressiveScenario } from "../../packages/server/src/localdb/progressive-workspace.test-utils.js";
import {
  closeWorldDrivers,
  CONNECTION_ID,
} from "../../packages/server/src/localdb/log-world.test-utils.js";
import { applyLog } from "../../packages/core/src/localdb/log-apply.js";
globalThis.memoryOperations = () => {};
let decoded = [],
  peakUnits = 0,
  peakBytes = 0,
  active = false;
const seen = new WeakSet();
globalThis.memoryDecoded = (value) => {
  if (!active || seen.has(value)) return;
  seen.add(value);
  decoded.push({
    ref: new WeakRef(value),
    bytes: Buffer.byteLength(JSON.stringify(value)),
  });
};
const n = Number(process.env.MEMORY_N ?? 8);
try {
  const distinct = process.env.MEMORY_DISTINCT === "1";
  const { b, context } = await progressiveScenario(n, distinct);
  const batch = b.db.batch.bind(b.db);
  b.db.batch = async (statements) => {
    const result = await batch(statements);
    if (
      statements.some((s) =>
        s.sql.includes("INSERT OR REPLACE INTO stream_partial"),
      ) &&
      statements.some(
        (s) =>
          s.sql.includes("INSERT INTO workspace_receipts") ||
          (s.sql.includes("temp.incoming") && s.sql.startsWith("INSERT")),
      )
    ) {
      await new Promise((r) => setImmediate(r));
      global.gc();
      await new Promise((r) => setImmediate(r));
      global.gc();
      let units = 0,
        bytes = 0;
      for (const unit of decoded)
        if (unit.ref.deref()) {
          units++;
          bytes += unit.bytes;
        }
      peakUnits = Math.max(peakUnits, units);
      peakBytes = Math.max(peakBytes, bytes);
    }
    return result;
  };
  active = true;
  await applyLog(b.deps, CONNECTION_ID, context);
  active = false;
  const rows = await b.db.query("SELECT count(*) n FROM records");
  const expected = distinct ? n - 2 : 1;
  if (rows[0].n !== expected) throw new Error("incorrect canonical row count");
  console.log(
    JSON.stringify({
      n,
      distinct,
      rows: rows[0].n,
      peakUnits,
      peakBytes,
      position: await b.position(),
    }),
  );
} finally {
  await closeWorldDrivers();
}
