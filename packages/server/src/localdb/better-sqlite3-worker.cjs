"use strict";

/**
 * The owner of one local database connection. `better-sqlite3-driver.ts`
 * starts this file as a worker thread and sends every statement and batch
 * here, so a long merge never holds the main thread's event loop.
 *
 * Two roles, set by `workerData.role`:
 * - "writer": the one connection that writes. Statements and batches run in
 *   order on it, so writes stay serialized. For a file database it also takes
 *   the process lock (see `acquireProcessLock`).
 * - "reader": a read-only connection to the same WAL file, opened on its first
 *   message. It sees the last committed state and never waits for the
 *   writer's transaction. It refuses a file that was deleted or replaced
 *   after it opened (`sqlite_database_replaced`), rather than serving the
 *   old file.
 *
 * A statement is { sid?, sql?, params }. The first use of an id carries the
 * text; later uses carry only the id. Messages in:
 *               { id, op: "query", ...statement }
 *               { id, op: "batch", statements: [statement] }   (writer only)
 *               { id, op: "close" }
 * Messages out: { id, ok: true, result } or { id, ok: false, error }.
 * Plain CommonJS: the worker loads it directly, with no build step of its own.
 */
const { parentPort, workerData } = require("node:worker_threads");
const { statSync } = require("node:fs");
const Database = require("better-sqlite3");
const { createStatementCache } = require("./statement-cache.cjs");

// A view over the received bytes, not a copy: a worker that only runs SQL
// allocates little JavaScript, so V8 collects copied blob memory late.
const bind = (params = []) =>
  params.map((v) =>
    v instanceof Uint8Array
      ? Buffer.from(v.buffer, v.byteOffset, v.byteLength)
      : v,
  );

const { path, role, lockTimeoutMs } = workerData;
const isFile = path !== ":memory:";

/**
 * One process holds one database file. With separate read and write
 * connections the file itself cannot stay in `locking_mode=EXCLUSIVE` (that
 * mode refuses every other connection, this process's reader included), so a
 * lock file next to it carries the rule: an EXCLUSIVE SQLite lock taken by one
 * write and kept until `close`. The kernel drops it when the process dies. A
 * second process waits `lockTimeoutMs`, then gets SQLITE_BUSY, as it did when
 * the database file itself was exclusive.
 */
const acquireProcessLock = () => {
  const lock = new Database(`${path}.lock`, {
    ...(lockTimeoutMs === undefined ? {} : { timeout: lockTimeoutMs }),
  });
  try {
    lock.pragma("locking_mode = EXCLUSIVE");
    lock.pragma("user_version = 1");
  } catch (error) {
    lock.close();
    throw error;
  }
  return lock;
};

let db;
let cache;
let processLock;
let openError;
let identity;
const identityOf = () => {
  const { dev, ino } = statSync(path);
  return `${dev}:${ino}`;
};
if (role === "writer") {
  try {
    if (isFile) processLock = acquireProcessLock();
    db = new Database(path);
    cache = createStatementCache(db);
    if (!isFile) db.pragma("locking_mode = EXCLUSIVE");
  } catch (error) {
    openError = error;
  }
}

/** The reader opens on first use: the writer has made the file and set WAL by then. */
const openReader = () => {
  if (db) return;
  db = new Database(path, { readonly: true, fileMustExist: true });
  db.pragma("query_only = ON");
  cache = createStatementCache(db);
  identity = identityOf();
};
const checkReader = () => {
  openReader();
  let now;
  try {
    now = identityOf();
  } catch {
    now = undefined;
  }
  if (now !== identity) {
    throw Object.assign(new Error("sqlite_database_replaced"), {
      code: "SQLITE_DATABASE_REPLACED",
    });
  }
};

const texts = new Map();
const textOf = ({ sid, sql }) => {
  if (sql === undefined) return texts.get(sid);
  if (sid !== undefined) texts.set(sid, sql);
  return sql;
};

const run = {
  query(statement) {
    if (role === "reader") checkReader();
    const { params } = statement;
    const stmt = cache.prepare(textOf(statement));
    if (stmt.reader) return stmt.all(...bind(params));
    stmt.run(...bind(params));
    return [];
  },
  batch({ statements }) {
    if (role === "reader") throw new Error("sqlite_reader_cannot_write");
    // Register every text first: a failure part way must not leave a later
    // id unknown to the worker while the other side believes it is sent.
    const sqls = statements.map(textOf);
    db.exec("BEGIN IMMEDIATE");
    try {
      const changes = statements.map((s, i) => {
        const stmt = cache.prepare(sqls[i]);
        return stmt.reader
          ? (stmt.all(...bind(s.params)), 0)
          : stmt.run(...bind(s.params)).changes;
      });
      db.exec("COMMIT");
      return { changes };
    } catch (error) {
      if (db.inTransaction) db.exec("ROLLBACK");
      throw error;
    }
  },
  close() {
    try {
      cache?.clear();
      db?.close();
    } finally {
      processLock?.close();
    }
    return null;
  },
};

// The worker allocates almost no JavaScript, so V8 would collect the memory
// behind received messages (blobs, strings) late and RSS would grow with the
// volume of data written. Collect on a message count instead.
require("node:v8").setFlagsFromString("--expose-gc");
const gc = require("node:vm").runInNewContext("gc");
let handled = 0;
parentPort.on("message", (message) => {
  if (++handled % 25 === 0) gc();
  const { id, op } = message;
  try {
    if (openError) throw openError;
    parentPort.postMessage({ id, ok: true, result: run[op](message) });
  } catch (error) {
    parentPort.postMessage({
      id,
      ok: false,
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack,
        code: error.code,
      },
    });
  }
});
