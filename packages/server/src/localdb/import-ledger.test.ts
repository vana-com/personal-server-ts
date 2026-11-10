import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { SqlDriver, SqlValue } from "../../../core/src/localdb/driver.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import type { ImportReceipt } from "../../../core/src/localdb/legacy-import-types.js";
import {
  mergeIncoming,
  TEMP_TABLES,
  withOrigin,
} from "../../../core/src/localdb/merge.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const dirs: string[] = [];
const databases = new Set<SqlDriver>();
afterEach(async () => {
  try {
    for (const db of databases) await db.close();
  } finally {
    databases.clear();
    for (const dir of dirs.splice(0))
      rmSync(dir, { recursive: true, force: true });
  }
});

const receipt = (changes: Partial<ImportReceipt> = {}): ImportReceipt => ({
  source: "source:revision-1",
  revision: "revision-1",
  connectionId: "connection-1",
  stream: "stream-1",
  generation: 1,
  rows: 3,
  fingerprint: "a".repeat(64),
  highestSeq: 37,
  state: "imported",
  reason: "Copied without exclusions",
  at: 100,
  ...changes,
});

async function fresh(version = MIGRATIONS.length) {
  const dir = mkdtempSync(join(process.cwd(), ".import-ledger-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const db = openBetterSqlite3(path);
  databases.add(db);
  for (let index = 0; index < version; index++) {
    await db.batch([
      ...MIGRATIONS[index]!.map((sql) => ({ sql })),
      { sql: `PRAGMA user_version = ${index + 1}` },
    ]);
  }
  return { db, path };
}

const lookup = (db: SqlDriver, value = receipt()) =>
  createImportLedger(db).get(value.source, value.connectionId, value.stream);

describe("import ledger", () => {
  it("ledger-roundtrip", async () => {
    const { db, path } = await fresh();
    const ledger = createImportLedger(db);
    const original = receipt();
    const statements = ledger.statements(original);
    expect(await lookup(db)).toBeNull();
    await db.batch(statements);
    expect(await lookup(db)).toEqual(original);

    // Same key updates a single durable receipt; reason remains opaque text.
    const updated = receipt({
      state: "verified",
      reason: '{"detail":"free text, not metadata"}',
      at: 101,
      highestSeq: 49,
    });
    await db.batch(ledger.statements(updated));
    await db.batch(ledger.statements({ ...updated, highestSeq: 37 }));
    expect(await lookup(db)).toEqual(updated);
    expect(
      await db.query("SELECT COUNT(*) AS count FROM import_ledger"),
    ).toEqual([{ count: 1 }]);
    expect(
      await db.query(
        "SELECT revision, generation, highest_seq, reason FROM import_ledger",
      ),
    ).toEqual([
      {
        revision: updated.revision,
        generation: 1,
        highest_seq: 49,
        reason: updated.reason,
      },
    ]);

    // A replay must use its prior committed sequence, not its zero change count.
    expect(() => ledger.statements({ ...updated, highestSeq: 0 })).toThrow(
      "Invalid import receipt",
    );
    expect(await lookup(db)).toEqual(updated);

    for (const other of [
      receipt({ source: "other-source" }),
      receipt({ connectionId: "other-connection" }),
      receipt({ stream: "other-stream" }),
      receipt({ source: "empty-source", rows: 0, highestSeq: 0, reason: null }),
      receipt({ source: "excluded-source", state: "excluded" }),
      receipt({ source: "retired-source", state: "retired" }),
    ]) {
      await db.batch(ledger.statements(other));
      expect(await lookup(db, other)).toEqual(other);
    }
    await db.close();
    databases.delete(db);
    const reopened = openBetterSqlite3(path);
    databases.add(reopened);
    expect(await lookup(reopened)).toEqual(updated);
    expect(await lookup(reopened, receipt({ stream: "missing" }))).toBeNull();

    const nextRevision = receipt({ revision: "revision-2", highestSeq: 2 });
    await reopened.batch(createImportLedger(reopened).statements(nextRevision));
    expect(await lookup(reopened)).toEqual(nextRevision);
  });

  it("ledger-migration-2-from-1", async () => {
    const { db } = await fresh(1);
    const original = receipt();
    await db.batch([
      {
        sql: `INSERT INTO import_ledger
              (source, connection_id, stream, state, rows, fingerprint, reason, at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [
          original.source,
          original.connectionId,
          original.stream,
          original.state,
          original.rows,
          original.fingerprint,
          '{"v":1,"revision":"revision-1","generation":1,"highestSeq":37}',
          original.at,
        ],
      },
    ]);
    await db.batch([
      ...MIGRATIONS[1]!.map((sql) => ({ sql })),
      { sql: "PRAGMA user_version = 2" },
    ]);
    expect(await db.query("PRAGMA user_version")).toEqual([
      { user_version: 2 },
    ]);
    expect(
      await db.query(
        "SELECT source, connection_id, stream, state, rows, fingerprint, reason, at, revision, generation, highest_seq FROM import_ledger",
      ),
    ).toEqual([
      {
        source: original.source,
        connection_id: original.connectionId,
        stream: original.stream,
        state: original.state,
        rows: original.rows,
        fingerprint: original.fingerprint,
        reason:
          '{"v":1,"revision":"revision-1","generation":1,"highestSeq":37}',
        at: original.at,
        revision: null,
        generation: null,
        highest_seq: null,
      },
    ]);
    expect(await lookup(db)).toBeNull();
    const columns = await db.query("PRAGMA table_info(import_ledger)");
    for (const [name, type] of [
      ["revision", "TEXT"],
      ["generation", "INTEGER"],
      ["highest_seq", "INTEGER"],
    ]) {
      expect(columns.find((column) => column.name === name)).toMatchObject({
        type,
        notnull: 0,
        dflt_value: null,
      });
    }
  });

  it("ledger-null-or-malformed-holds", async () => {
    const { db } = await fresh();
    const ledger = createImportLedger(db);
    const invalid: readonly [string, SqlValue][] = [
      ["revision", null],
      ["revision", ""],
      ["revision", "  "],
      ["generation", null],
      ["generation", 0],
      ["generation", 2],
      ["generation", "unknown"],
      ["generation", 1.5],
      ["highest_seq", null],
      ["highest_seq", "unknown"],
      ["highest_seq", -1],
      ["highest_seq", 0],
      ["highest_seq", 1.5],
      ["highest_seq", Number.MAX_SAFE_INTEGER + 1],
      ["rows", -1],
      ["rows", 0.5],
      ["fingerprint", ""],
      ["at", -1],
      ["at", 0.5],
      ["reason", new Uint8Array([1])],
    ];
    for (const [column, value] of invalid) {
      await db.batch(ledger.statements(receipt()));
      await db.batch([
        {
          // Column identifiers come only from the fixed test cases above.
          sql: `UPDATE import_ledger SET ${column} = ?`,
          params: [value],
        },
      ]);
      expect(await lookup(db), column).toBeNull();
    }
  });

  it("ledger-batch-atomic", async () => {
    const { db } = await fresh();
    const ledger = createImportLedger(db);
    await db.batch([
      ...TEMP_TABLES.map((sql) => ({ sql })),
      {
        sql: `INSERT INTO incoming
                (op, stream, pk_hash, record_key, stamp_o, stamp_r,
                 body, body_sha256, first_o)
              VALUES (?, ?, ?, ?, 0, 'seed', ?, ?, NULL)`,
        params: [
          "import-1",
          "stream-1",
          "hash-1",
          "key-1",
          "{}",
          "b".repeat(64),
        ],
      },
    ]);
    const imported = receipt({ rows: 1, highestSeq: 1 });
    const merged = withOrigin("import", [
      ...mergeIncoming("import-1", imported.connectionId),
      ...ledger.statements(imported),
    ]);
    await expect(
      db.batch([
        ...merged,
        { sql: "INSERT INTO write_ctx (id, origin) VALUES (1, 'import')" },
      ]),
    ).rejects.toThrow();
    expect(await db.query("SELECT COUNT(*) AS count FROM records")).toEqual([
      { count: 0 },
    ]);
    expect(
      await db.query("SELECT COUNT(*) AS count FROM record_changes"),
    ).toEqual([{ count: 0 }]);
    expect(
      await db.query("SELECT COUNT(*) AS count FROM import_ledger"),
    ).toEqual([{ count: 0 }]);
    expect(await lookup(db)).toBeNull();
    expect(await db.query("SELECT COUNT(*) AS count FROM incoming")).toEqual([
      { count: 1 },
    ]);
    expect(await db.query("SELECT origin FROM write_ctx")).toEqual([
      { origin: "local" },
    ]);

    // The restored staging row can be retried, committing merge and receipt.
    await db.batch(merged);
    expect(await db.query("SELECT COUNT(*) AS count FROM records")).toEqual([
      { count: 1 },
    ]);
    expect(await db.query("SELECT seq, origin FROM record_changes")).toEqual([
      { seq: 1, origin: "import" },
    ]);
    expect(await lookup(db)).toEqual(imported);
  });
});
