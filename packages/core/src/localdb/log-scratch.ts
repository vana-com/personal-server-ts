// The scratch of the operations that fold or build the log a whole at a time:
// the fold of a history too large to hold (`log-fold-workspace.ts`) and the
// sealed objects of a candidate waiting for upload (`log-spool.ts`). Both hold
// a connection's record bodies, delete keys or ciphertext in the local
// database. Nothing of them may outlive the operation that fills them.
//
// Ownership. Every row names the process that wrote it (`process`) and the
// session that owns it (`session`: one fold, one candidate). The rule for
// removing a row:
//   - a session removes its own rows, when it ends (`close`, `discard`);
//   - opening the file removes the rows of any other process: the driver
//     contract is one process per database (`driver.ts`), so a row stamped by
//     a process other than this one belongs to one that ended, a crash or a
//     reload, and is abandoned. It runs after the owner and network are
//     checked, so a file that is refused is not touched;
//   - a purge of a connection removes the connection's rows, whoever owns them
//     (the connection they belong to is gone).
// A second handle on the same file in the same process is not another
// process: its open removes nothing, and its sessions are its own.
//
// TEMP tables would give each connection its own scratch with no ownership
// rule, but SQLite keeps TEMP tables in memory where its `temp_store` says so.
// Web sets it to MEMORY. A phone uses the system SQLite through sqflite; its
// compile-time default cannot be read through the bridge's pragma allow-list
// and a `PRAGMA temp_store = FILE` has no effect where it was compiled to
// memory. The scratch exists to keep the log out of memory, so it is in the
// file.
//
// The tables are not part of the schema the file keeps and need no migration:
// they hold nothing a later process reads.

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
    create: `CREATE TABLE IF NOT EXISTS ${FOLD_CELLS} (
  connection_id TEXT NOT NULL, session TEXT NOT NULL, process TEXT NOT NULL,
  stream BLOB NOT NULL, pk_hash TEXT NOT NULL,
  up_o INTEGER, up_r BLOB, up_ordinal INTEGER, up_hash TEXT,
  up_first_seen INTEGER, up_ref INTEGER, up_bytes INTEGER,
  del_o INTEGER, del_r BLOB, del_explicit INTEGER, del_bytes INTEGER,
  up_body TEXT, del_key TEXT,
  PRIMARY KEY (connection_id, session, stream, pk_hash)) WITHOUT ROWID`,
  },
  {
    table: SPOOL,
    // A sealed object is stored in rows of at most `SPOOL_CHUNK` bytes: one
    // row is one read, and a phone's SQL bridge refuses a frame over 4 MiB.
    create: `CREATE TABLE IF NOT EXISTS ${SPOOL} (
  connection_id TEXT NOT NULL, session TEXT NOT NULL, process TEXT NOT NULL,
  name TEXT NOT NULL,
  chunk INTEGER NOT NULL, bytes INTEGER NOT NULL, cipher BLOB NOT NULL,
  PRIMARY KEY (connection_id, session, name, chunk)) WITHOUT ROWID`,
  },
];

/** This process, for as long as this module is loaded: what a row's `process` says. */
export const PROCESS: string = `${Date.now().toString(36)}-${Math.random()
  .toString(36)
  .slice(2)}`;

let sessions = 0;
/** A session id no other session of this process has: one fold, one candidate. */
export const newSession = (): string => `s${++sessions}`;

/** Create the scratch tables when the file has none: the statements `openLocalDb` runs. */
export function ensureScratch(): SqlStatement[] {
  return SCRATCH.map(({ create }) => ({ sql: create }));
}

/** Delete the rows of every other process: what a crash or a reload left. Runs once the file's owner is checked. */
export function abandonedScratch(): SqlStatement[] {
  return SCRATCH.map(({ table }) => ({
    sql: `DELETE FROM ${table} WHERE process <> ?`,
    params: [PROCESS],
  }));
}

/** Delete one session's rows of `table`: what a fold or a candidate does when it ends. */
export function deleteSession(
  table: typeof FOLD_CELLS | typeof SPOOL,
  connectionId: string,
  session: string,
): SqlStatement {
  return {
    sql: `DELETE FROM ${table} WHERE connection_id = ? AND session = ? AND process = ?`,
    params: [connectionId, session, PROCESS],
  };
}

/** Delete a connection's scratch rows: the statements a purge adds. */
export function scratchDeletes(connectionId: string): SqlStatement[] {
  return SCRATCH.map(({ table }) => ({
    sql: `DELETE FROM ${table} WHERE connection_id = ?`,
    params: [connectionId],
  }));
}
