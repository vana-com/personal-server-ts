"use strict";

/**
 * The one owner of a local database connection. `better-sqlite3-driver.ts`
 * starts this file as a worker thread and sends every statement and batch
 * here, so a long merge never holds the main thread's event loop and writes
 * stay serialized on one connection.
 *
 * A statement is { sid?, sql?, params }. The first use of an id carries the
 * text; later uses carry only the id. Messages in:
 *               { id, op: "query", ...statement }
 *               { id, op: "batch", statements: [statement] }
 *               { id, op: "close" }
 * Messages out: { id, ok: true, result } or { id, ok: false, error }.
 * Plain CommonJS: the worker loads it directly, with no build step of its own.
 */
const { parentPort, workerData } = require("node:worker_threads");
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

let db;
let cache;
let openError;
try {
  db = new Database(workerData.path);
  cache = createStatementCache(db);
  db.pragma("locking_mode = EXCLUSIVE");
} catch (error) {
  openError = error;
}

const texts = new Map();
const textOf = ({ sid, sql }) => {
  if (sql === undefined) return texts.get(sid);
  if (sid !== undefined) texts.set(sid, sql);
  return sql;
};

const run = {
  query(statement) {
    const { params } = statement;
    const stmt = cache.prepare(textOf(statement));
    if (stmt.reader) return stmt.all(...bind(params));
    stmt.run(...bind(params));
    return [];
  },
  batch({ statements }) {
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
    cache.clear();
    db.close();
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
