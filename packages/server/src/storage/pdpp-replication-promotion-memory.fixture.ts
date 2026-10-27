/**
 * Isolated canonical-promotion probe for pdpp-replication-memory.test.ts.
 * Each mode runs in its own process, so its peak is attributable to one step.
 */
import Database from "better-sqlite3";
import { join } from "node:path";
import {
  BINARY_CHUNK_BYTES,
  binaryWriter,
  copyBinaryToCanonical,
} from "./pdpp-binary-chunks.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const [mode, directory, sizeArg] = process.argv.slice(2);
if (!directory) throw new Error("probe directory required");
const size = Number(sizeArg);
const maxRssKiB = () => process.resourceUsage().maxRSS;
const sourceId = "https://memory.invalid/declaration";
const report = (before: number, after: number) =>
  console.log(
    JSON.stringify({
      size,
      beforeKiB: before,
      afterKiB: after,
      deltaKiB: Math.max(0, after - before),
    }),
  );

if (mode === "promote") {
  // Replicated canonical promotion alone, from chunks already staged as
  // `received`. Staging streams 64 KiB pieces, so no whole blob exists before
  // the marker. Promotion makes the whole value that main's row format needs.
  const db = new Database(join(directory, "destination.sqlite"));
  const store = createReplicaRecordStore(db);
  const id = "promote-blob";
  // The receiver writes the blob's metadata row before promotion; the byte row references it.
  db.prepare("INSERT OR IGNORE INTO pdpp_blobs VALUES (?, ?, ?, ?)").run(
    id,
    "application/octet-stream",
    size,
    "0".repeat(64),
  );
  const writer = binaryWriter(db, "received", id);
  const piece = Buffer.alloc(BINARY_CHUNK_BYTES, 31);
  for (let written = 0; written < size; written += piece.length)
    writer.write(piece.subarray(0, Math.min(piece.length, size - written)));
  writer.finish();
  const before = maxRssKiB();
  copyBinaryToCanonical(db, "received", id);
  report(before, maxRssKiB());
  store.close();
} else if (mode === "plain") {
  // Main's ordinary blob write: the caller materializes the whole blob, then
  // storeBlobBytesForInstance writes it as one pdpp_blob_bytes row.
  const db = new Database(join(directory, "plain.sqlite"));
  const store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "memory",
  });
  const before = maxRssKiB();
  store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: Buffer.alloc(size, 31),
    mimeType: "application/octet-stream",
  });
  report(before, maxRssKiB());
  store.close();
} else throw new Error("unknown promotion probe mode");
