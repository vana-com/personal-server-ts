import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import type { SqlValue } from "@opendatalabs/personal-server-ts-core/localdb";
import {
  TEMP_TABLES,
  mergeIncoming,
  withOrigin,
} from "../../../core/src/localdb/merge.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";

// The page writes of a first load, counted by SQLite: the shell's `.stats`
// reports them per statement, and better-sqlite3 has no such counter. This
// runs where the conformance suite's 3.22.0 shell is set (CI builds one).
const CLI = process.env.LOCALDB_SQLITE3_CLI;

// A browser's database: 64 KiB pages and a rollback journal. Its cache holds
// a small part of what a first load writes (16 MiB of about 550 MB for a
// 198,001-row source). At this size that share would be fewer pages than one
// insert touches (the last page of each b-tree it writes, and their parents),
// so the cache holds those and a few more.
const PAGE_SIZE = 65536;
const ROWS = 6000;
const CACHE_PAGES = 24;
// A key range applied in one transaction is larger than the cache, as there.
const BUCKETS = 13;

const ended = (sql: string) => `${sql.replace(/;?\s*$/, "")};`;
const literal = (v: SqlValue): string =>
  v === null
    ? "NULL"
    : typeof v === "string"
      ? `'${v.replaceAll("'", "''")}'`
      : String(v);
const inline = (sql: string, params: readonly SqlValue[]) => {
  let i = 0;
  return ended(sql.replaceAll("?", () => literal(params[i++] ?? null)));
};

/**
 * Statements that turn the migrated `records` into a WITHOUT ROWID table
 * keyed by its unique key, with the same indexes and triggers: what the test
 * measures against. None when it is one already.
 */
function withoutRowidRecords(): string[] {
  const db = new Database(":memory:");
  try {
    for (const sql of MIGRATIONS.flat()) db.exec(sql);
    const objects = db
      .prepare(
        "SELECT type, name, sql FROM sqlite_master WHERE tbl_name = 'records' AND sql IS NOT NULL ORDER BY type DESC, name",
      )
      .all() as { type: string; name: string; sql: string }[];
    const table = objects.find((o) => o.type === "table")!.sql;
    if (/WITHOUT ROWID\s*$/i.test(table)) return [];
    const [unique] = db
      .prepare(
        `SELECT name FROM pragma_index_list('records') WHERE "unique" = 1 AND origin = 'c'`,
      )
      .all() as { name: string }[];
    const key = (
      db
        .prepare(`SELECT name FROM pragma_index_info('${unique!.name}')`)
        .all() as { name: string }[]
    ).map((c) => c.name);
    return [
      "DROP TABLE records",
      table.replace(
        /\)\s*$/,
        `, PRIMARY KEY (${key.join(", ")})) WITHOUT ROWID`,
      ),
      ...objects
        .filter((o) => o.type !== "table" && o.name !== unique!.name)
        .map((o) => o.sql),
    ];
  } finally {
    db.close();
  }
}

/** Page writes of a key-ordered first load of ROWS rows. */
function loadWrites(schema: readonly string[]): number {
  const hash = (s: string) => createHash("sha256").update(s).digest("hex");
  const lines: string[] = [
    `PRAGMA page_size = ${PAGE_SIZE};`,
    "PRAGMA journal_mode = TRUNCATE;",
    "BEGIN;",
    ...schema.map(ended),
    "INSERT INTO connections(connection_id, connector, ns, control_state) VALUES ('c1','k','','active');",
    `INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental) VALUES ('c1','s','["id"]','mutable_state',0);`,
    "COMMIT;",
    ...TEMP_TABLES.map(ended),
  ];
  // Downloaded rows wait in a stage table per key range, in arrival order,
  // which is not key order: a key is a hash.
  const step = 16 ** 4 / BUCKETS;
  const bucketOf = (pkHash: string) =>
    Math.floor(Number.parseInt(pkHash.slice(0, 4), 16) / step);
  lines.push("BEGIN;");
  for (let b = 0; b < BUCKETS; b++)
    lines.push(
      `CREATE TABLE stage_${b} (pk_hash TEXT NOT NULL, record_key TEXT NOT NULL, body TEXT NOT NULL);`,
    );
  for (let i = 0; i < ROWS; i++) {
    const pkHash = hash(`key-${i}`);
    const body = JSON.stringify({ id: i, text: hash(`body-${i}`).repeat(36) });
    lines.push(
      inline(`INSERT INTO stage_${bucketOf(pkHash)} VALUES (?, ?, ?)`, [
        pkHash,
        JSON.stringify([i]),
        body,
      ]),
    );
  }
  lines.push("COMMIT;", `PRAGMA cache_size = ${CACHE_PAGES};`, ".stats on");
  // The keyed first load applies one key range at a time, in key order.
  for (let b = 0; b < BUCKETS; b++) {
    const statements = withOrigin("remote", [
      {
        sql: `INSERT INTO temp.incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256)
              SELECT 'load', 's', pk_hash, record_key, 0, 'seed', body, 'sha' FROM stage_${b}`,
      },
      ...mergeIncoming("load", "c1", {
        promoteSeen: true,
        firstSeenOfWinner: true,
      }),
    ]);
    lines.push(
      "BEGIN;",
      ...statements.map((s) => inline(s.sql, s.params ?? [])),
      "COMMIT;",
    );
  }
  lines.push(".stats off", "SELECT 'records:' || COUNT(*) FROM records;");

  const dir = mkdtempSync(join(process.cwd(), ".records-layout-"));
  try {
    const run = spawnSync(CLI!, [join(dir, "db.sqlite")], {
      input: lines.join("\n"),
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
    const out = run.stdout + run.stderr;
    expect(out).not.toMatch(/^(Error|Parse error|Runtime error)/m);
    expect(out).toMatch(new RegExp(`^records:${ROWS}$`, "m"));
    return [...out.matchAll(/^Page cache writes:\s+(\d+)/gm)].reduce(
      (sum, m) => sum + Number(m[1]),
      0,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe.skipIf(!CLI)("records layout", () => {
  it("writes a key-ordered first load in under half the pages a WITHOUT ROWID records table takes", () => {
    // A WITHOUT ROWID table keeps each row in its key's b-tree. An append
    // there rewrites the leaf's neighbours, which the small cache has
    // already written out; a rowid table appends a new page.
    const current = loadWrites(MIGRATIONS.flat());
    const withoutRowid = loadWrites([
      ...MIGRATIONS.flat(),
      ...withoutRowidRecords(),
    ]);
    expect(current).toBeLessThan(withoutRowid / 2);
  }, 120_000);
});
