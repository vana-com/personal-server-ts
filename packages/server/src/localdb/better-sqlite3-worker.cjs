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
 *               { id, op: "identity" }                         (writer: path, dev:ino)
 *               { id, op: "close" }
 * Messages out: { id, ok: true, result } or { id, ok: false, error }.
 * Plain CommonJS: the worker loads it directly, with no build step of its own.
 */
const { parentPort, workerData } = require("node:worker_threads");
const { realpathSync, statSync } = require("node:fs");
const { basename, dirname, join } = require("node:path");
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

const { role, lockTimeoutMs } = workerData;
const isFile = workerData.path !== ":memory:";

/**
 * The file's real path: symlinks resolved, so two names for one database give
 * one lock file and one set of -wal/-shm files. A file that does not exist yet
 * resolves through its directory.
 */
const canonicalPath = (given) => {
  try {
    return realpathSync(given);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return join(realpathSync(dirname(given)), basename(given));
  }
};
// The writer resolves the path; the reader is handed the writer's resolved
// path and the writer's file identity, and serves only that file.
const path =
  role === "writer" && isFile
    ? canonicalPath(workerData.path)
    : workerData.path;

/**
 * One process holds one database file. With separate read and write
 * connections the file itself cannot stay in `locking_mode=EXCLUSIVE` (that
 * mode refuses every other connection, this process's reader included), so a
 * lock file next to its real path (symlinks resolved; a hard-linked database
 * is refused) carries the rule: an EXCLUSIVE SQLite lock taken by one
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
// The writer's file as `dev:ino`. The reader gets it in `workerData`.
let identity = workerData.identity;
const identityOf = () => {
  try {
    const { dev, ino } = statSync(path);
    return `${dev}:${ino}`;
  } catch {
    return undefined;
  }
};
const replaced = () =>
  Object.assign(new Error("sqlite_database_replaced"), {
    code: "SQLITE_DATABASE_REPLACED",
  });
/**
 * The platform gives no way to ask an open SQLite handle which file it holds,
 * so identity is proved around the open: the path names the expected file
 * before the open and again after it. The opened file is whatever the path
 * named in between, so two equal answers around the open mean the handle
 * holds that file (the expected file stays open in the writer, so its inode
 * cannot be reused by another file). Any difference refuses.
 */
const openChecked = (open, expected) => {
  if (expected !== undefined && identityOf() !== expected) throw replaced();
  const opened = open();
  try {
    const after = identityOf();
    if (after === undefined || (expected !== undefined && after !== expected))
      throw replaced();
    return { opened, after };
  } catch (error) {
    opened.close();
    throw error;
  }
};
if (role === "writer") {
  try {
    if (isFile) {
      processLock = acquireProcessLock();
      // Two names for one inode would have two lock files: refuse them.
      if (identityOf() !== undefined && statSync(path).nlink > 1)
        throw Object.assign(new Error("sqlite_database_hard_linked"), {
          code: "SQLITE_DATABASE_HARD_LINKED",
        });
      const first = identityOf();
      const { opened, after } = openChecked(() => new Database(path), first);
      db = opened;
      identity = after;
      if (statSync(path).nlink > 1)
        throw Object.assign(new Error("sqlite_database_hard_linked"), {
          code: "SQLITE_DATABASE_HARD_LINKED",
        });
    } else {
      db = new Database(path);
    }
    cache = createStatementCache(db);
    if (!isFile) db.pragma("locking_mode = EXCLUSIVE");
  } catch (error) {
    openError = error;
    try {
      cache?.clear();
      db?.close();
      processLock?.close();
    } catch {}
    db = cache = processLock = undefined;
  }
}

/** The reader opens on first use: the writer has made the file and set WAL by then. */
const openReader = () => {
  if (db) return;
  const { opened } = openChecked(
    () => new Database(path, { readonly: true, fileMustExist: true }),
    identity,
  );
  opened.pragma("query_only = ON");
  db = opened;
  cache = createStatementCache(db);
};
const checkReader = () => {
  openReader();
  if (identityOf() !== identity) throw replaced();
};

const texts = new Map();
const textOf = ({ sid, sql }) => {
  if (sql === undefined) return texts.get(sid);
  if (sid !== undefined) texts.set(sid, sql);
  return sql;
};

const run = {
  /** The writer's resolved path and file identity, for the reader to serve. */
  identity() {
    return { path, identity };
  },
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
