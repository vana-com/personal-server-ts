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
const {
  closeSync,
  fstatSync,
  openSync,
  realpathSync,
  statSync,
} = require("node:fs");
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
 * A file that does not exist yet has no identity to expect, so the writer
 * creates it first, exclusively, and reads the identity from the descriptor
 * it created. SQLite then opens an empty file (a zero-length file is a valid
 * new database). Returns undefined if the file already exists.
 */
const createExclusively = () => {
  let fd;
  try {
    fd = openSync(path, "wx", 0o644);
  } catch (error) {
    if (error.code === "EEXIST") return undefined;
    throw error;
  }
  try {
    const { dev, ino } = fstatSync(fd);
    return `${dev}:${ino}`;
  } finally {
    closeSync(fd);
  }
};
/**
 * The platform gives no way to ask an open SQLite handle which file it holds,
 * so identity is checked around the open: the path must name the expected
 * file before the open and again after it. This narrows the race; it does not
 * prove the handle's identity. A swap that puts another file at the path for
 * the open and the original back before the second check (swap and swap
 * back) is not caught. Any other difference refuses.
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
function configureWorkspaceCache(connection) {
  const cacheKiB = workerData.workspaceCacheKiB ?? 2048;
  connection.pragma(`cache_size = -${cacheKiB}`);
  connection.pragma("mmap_size = 0");
  connection.pragma("temp_store = FILE");
  connection.pragma("cache_spill = ON");
}
if (role === "writer") {
  try {
    if (isFile) {
      processLock = acquireProcessLock();
      // Two names for one inode would have two lock files: refuse them.
      if (identityOf() !== undefined && statSync(path).nlink > 1)
        throw Object.assign(new Error("sqlite_database_hard_linked"), {
          code: "SQLITE_DATABASE_HARD_LINKED",
        });
      // A new file gets its expected identity from our own exclusive create.
      let first = createExclusively();
      if (first === undefined) {
        first = identityOf();
        if (first === undefined) throw replaced(); // removed since EEXIST
      }
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
    configureWorkspaceCache(db);
    cache = createStatementCache(db);
    if (!isFile) db.pragma("locking_mode = EXCLUSIVE");
    // A file database checkpoints its WAL after a write has replied (see
    // `checkpointAfterReply`), not inside the write's COMMIT.
    else db.pragma("wal_autocheckpoint = 0");
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
  configureWorkspaceCache(opened);
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
    const { params } = statement;
    if (role === "reader") checkReader();
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

/**
 * SQLite's own checkpoint mark: a WAL of this many frames is moved into the
 * database file. SQLite does it inside the COMMIT that crosses the mark, so the
 * commit's caller waits for the pages to be written and synced. A publish's
 * commit deletes its whole change log in one batch (about 12,400 pages for a
 * 198,001-row stream), and that COMMIT took 5 to 6 s, 23 ms without the
 * checkpoint. The writer replies first and then does the same PASSIVE
 * checkpoint at the same mark, so a write's caller no longer waits for it.
 * Calls to the writer run in order, so the next call waits for the checkpoint
 * instead: the work is the same and the log stays as short as before.
 *
 * Why not leave SQLite's checkpoint on and switch it off around the publish
 * commit: that needs the driver to tell the worker which commit is the slow
 * one, a new message in a contract every caller shares. Here the hook sits at
 * the one place every write completes, so a write path cannot miss it.
 *
 * Durability: `open.ts` sets `synchronous = NORMAL`, under which a WAL commit is
 * written but not synced; the sync happens at a checkpoint. At base the commit
 * that crossed the mark was synced before it was acknowledged, and every other
 * commit was not. Now that one is acknowledged first, like the rest. A process
 * crash loses nothing (the write is in the OS cache); a power loss in that
 * window can lose the last acknowledged transactions, whole, never half.
 * A PASSIVE checkpoint stops at frames a reader still needs, so the log is not
 * bounded while a run's read transaction is open; that was true before too.
 */
const CHECKPOINT_FRAMES = 1000;

function checkpointAfterReply() {
  try {
    // A transaction left open by `query("BEGIN")` commits in a later call, and
    // that call checkpoints.
    if (!db.open || db.inTransaction) return;
    // NOOP only reports: it writes nothing and takes no lock.
    const [{ log, checkpointed }] = db.pragma("wal_checkpoint(NOOP)");
    if (log - checkpointed >= CHECKPOINT_FRAMES)
      db.pragma("wal_checkpoint(PASSIVE)");
  } catch {
    // The next call or the close checkpoints it: a failure here changes no data.
  }
}

// The worker allocates almost no JavaScript, so V8 would collect the memory
// behind received messages (blobs, strings) late and RSS would grow with the
// volume of data written. Collect on a message count instead.
require("node:v8").setFlagsFromString("--expose-gc");
const gc = require("node:vm").runInNewContext("gc");
let handled = 0;
/**
 * Every call that can write on the writer's own connection checkpoints after
 * its reply, whichever reply it was: `batch`, and `query` (a statement, or a
 * write with RETURNING). A write that throws can still have committed rows
 * (`INSERT OR FAIL` keeps the rows before the failing one), so an error reply
 * is no reason to skip it. `close` and a handle that never opened have
 * nothing to checkpoint.
 */
const writesOwnConnection = ({ op }) =>
  role === "writer" &&
  isFile &&
  !openError &&
  (op === "batch" || op === "query");

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
  } finally {
    // The reply is already sent; this changes neither outcome.
    if (writesOwnConnection(message)) checkpointAfterReply();
  }
});
