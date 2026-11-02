import Database from "better-sqlite3";
import { expect, it } from "vitest";
import {
  BINARY_CHUNK_BYTES,
  BINARY_CHUNKS_MIGRATION,
  readBinaryChunks,
  readBinaryWindow,
  type BinaryCursor,
} from "./pdpp-binary-chunks.js";

const MiB = 1024 * 1024;
/**
 * Every legacy windowed read asks SQLite for max(8 MiB, size / 16), rounded up
 * to whole 64 KiB chunks. Both 32 MiB and 128 MiB blobs therefore read 8 MiB
 * windows. This is the one allocation that scales with the blob, so it is the
 * property under test. Changing the window policy means changing this value.
 */
const EXPECTED_WINDOW_BYTES = 8 * MiB;

/** A whole-value row in main's `pdpp_blob_bytes` format, the legacy read path. */
function legacyDatabase(size: number) {
  const db = new Database(":memory:");
  db.exec(BINARY_CHUNKS_MIGRATION);
  db.exec(
    "CREATE TABLE pdpp_blob_bytes (blob_id TEXT PRIMARY KEY, bytes BLOB NOT NULL)",
  );
  db.prepare("INSERT INTO pdpp_blob_bytes (blob_id, bytes) VALUES (?, ?)").run(
    "blob",
    Buffer.alloc(size, 7),
  );
  return db;
}

/**
 * Records every windowed `substr` read the reader issues: the length it asked
 * SQLite for and the bytes SQLite handed back. Only the `get` call is wrapped,
 * because that is the only call the windowed path makes.
 */
function meterWindowReads(db: Database.Database) {
  const windows: { requested: number; returned: number }[] = [];
  const prepare = db.prepare.bind(db);
  db.prepare = ((sql: string) => {
    const statement = prepare(sql);
    if (!sql.includes("substr(bytes")) return statement;
    return {
      get: (...args: unknown[]) => {
        const row = statement.get(...args) as { bytes: Buffer } | undefined;
        windows.push({
          requested: args[1] as number,
          returned: row?.bytes.length ?? 0,
        });
        return row;
      },
    } as unknown as ReturnType<typeof prepare>;
  }) as typeof db.prepare;
  return windows;
}

/**
 * Deterministic: asserts the size of each allocation the reader makes, not
 * process RSS. A reader that reads the whole blob in one call fails here at
 * every size. Retention is not measured here. Whether earlier windows stay
 * reachable depends on the generator's single `part` binding, which this test
 * does not observe.
 */
it.each([32, 128])(
  "reads a %i MiB legacy blob in bounded windows and chunks",
  (sizeMiB) => {
    const size = sizeMiB * MiB;
    const db = legacyDatabase(size);
    const windows = meterWindowReads(db);
    let total = 0;
    let largestChunk = 0;
    for (const chunk of readBinaryChunks(db, "canonical", "blob")) {
      total += chunk.length;
      largestChunk = Math.max(largestChunk, chunk.length);
    }
    db.close();

    expect(total).toBe(size);
    expect(largestChunk).toBeLessThanOrEqual(BINARY_CHUNK_BYTES);
    expect(windows.length).toBe(size / EXPECTED_WINDOW_BYTES);
    expect(Math.max(...windows.map((w) => w.requested))).toBe(
      EXPECTED_WINDOW_BYTES,
    );
    expect(Math.max(...windows.map((w) => w.returned))).toBeLessThanOrEqual(
      EXPECTED_WINDOW_BYTES,
    );
  },
);

it("readBinaryWindow reads rows of any length in parts by cursor", () => {
  const db = new Database(":memory:");
  db.exec(BINARY_CHUNKS_MIGRATION);
  // Rows of any length up to a full chunk, as a copy of short writes leaves them.
  const rows = [5, 300, 3, 9];
  const all = Buffer.alloc(rows.reduce((a, b) => a + b, 0));
  for (let i = 0; i < all.length; i++) all[i] = (i * 13) & 255;
  let offset = 0;
  for (const [position, length] of rows.entries()) {
    db.prepare("INSERT INTO pdpp_binary_chunks VALUES (?,?,?,?)").run(
      "payload",
      "p",
      position,
      all.subarray(offset, offset + length),
    );
    offset += length;
  }
  db.prepare("INSERT INTO pdpp_binary_manifests VALUES (?,?,?)").run(
    "payload",
    "p",
    all.length,
  );
  for (const window of [1, 4, 7, 1000, all.length]) {
    const parts: Buffer[] = [];
    let cursor: BinaryCursor = { position: 0, offset: 0 };
    for (let read = 0; read < all.length;) {
      const length = Math.min(window, all.length - read);
      const { bytes, next } = readBinaryWindow(
        db,
        "payload",
        "p",
        cursor,
        length,
      );
      expect(bytes.length).toBe(length);
      parts.push(Buffer.from(bytes));
      cursor = next;
      read += length;
    }
    expect(Buffer.concat(parts).equals(all)).toBe(true);
    expect(cursor).toEqual({ position: rows.length, offset: 0 });
  }
  // Past the end, a missing value and a legacy namespace all throw.
  expect(() =>
    readBinaryWindow(db, "payload", "p", { position: 3, offset: 0 }, 10),
  ).toThrow("corrupt binary chunks");
  expect(() =>
    readBinaryWindow(db, "payload", "q", { position: 0, offset: 0 }, 1),
  ).toThrow("missing binary bytes");
  expect(() =>
    readBinaryWindow(db, "canonical", "p", { position: 0, offset: 0 }, 1),
  ).toThrow("legacy binary windows unsupported");
});
