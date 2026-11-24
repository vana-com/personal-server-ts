// The scratch of the operations that fold or build the log a whole at a time:
// the fold of a history too large to hold (`log-fold-workspace.ts`) and the
// sealed objects of a candidate waiting for upload (`log-spool.ts`). Both hold
// a connection's record bodies, delete keys or ciphertext in the local
// database. Nothing of them may outlive the operation that fills them.
//
// They are not part of the schema the file keeps. The tables are dropped and
// created again every time the file opens (`resetScratch`), so whatever a
// process left when it ended is gone before anything reads it, and their shape
// needs no migration. A purge of a connection also deletes its rows
// (`scratchDeletes`), because a purge can run while the file stays open. An
// operation empties its own rows when it ends.
//
// TEMP tables would be per-connection and need no reset, but SQLite keeps
// them in memory where `temp_store` says so (Web sets it), and the scratch
// exists to keep the log out of memory.

import type { SqlStatement } from "./driver.js";

export const FOLD_CELLS = "log_fold_cells";
export const SPOOL = "log_spool";

/** Every scratch table with its shape; each has `connection_id` as its first column. */
const SCRATCH: ReadonlyArray<{ table: string; create: string }> = [
  {
    table: FOLD_CELLS,
    // Names and run ids are BLOBs of their UTF-16BE code units: blobs compare
    // as `memcmp`, which for UTF-16BE is the order of code units that
    // JavaScript compares strings by. TEXT would compare by UTF-8 byte, which
    // differs for U+E000 against U+10000, and cannot hold a lone surrogate.
    // The sizes (`*_bytes`) come before the bodies, so a read of sizes alone
    // does not walk the pages a body overflows into.
    create: `CREATE TABLE ${FOLD_CELLS} (
  connection_id TEXT NOT NULL, workspace TEXT NOT NULL,
  stream BLOB NOT NULL, pk_hash TEXT NOT NULL,
  up_o INTEGER, up_r BLOB, up_ordinal INTEGER, up_hash TEXT,
  up_first_seen INTEGER, up_ref INTEGER, up_bytes INTEGER,
  del_o INTEGER, del_r BLOB, del_explicit INTEGER, del_bytes INTEGER,
  up_body TEXT, del_key TEXT,
  PRIMARY KEY (connection_id, workspace, stream, pk_hash)) WITHOUT ROWID`,
  },
  {
    table: SPOOL,
    // A sealed object is stored in rows of at most `SPOOL_CHUNK` bytes: one
    // row is one read, and a phone's SQL bridge refuses a frame over 4 MiB.
    create: `CREATE TABLE ${SPOOL} (
  connection_id TEXT NOT NULL, owner TEXT NOT NULL, name TEXT NOT NULL,
  chunk INTEGER NOT NULL, bytes INTEGER NOT NULL, cipher BLOB NOT NULL,
  PRIMARY KEY (connection_id, owner, name, chunk)) WITHOUT ROWID`,
  },
];

/** Drop and create the scratch tables: the statements `openLocalDb` runs. */
export function resetScratch(): SqlStatement[] {
  return SCRATCH.flatMap(({ table, create }) => [
    { sql: `DROP TABLE IF EXISTS ${table}` },
    { sql: create },
  ]);
}

/** Delete a connection's scratch rows: the statements a purge adds. */
export function scratchDeletes(connectionId: string): SqlStatement[] {
  return SCRATCH.map(({ table }) => ({
    sql: `DELETE FROM ${table} WHERE connection_id = ?`,
    params: [connectionId],
  }));
}
