"use strict";

/**
 * Test-only entry for the SQLite worker thread. `worker-harness.test-utils.ts`
 * starts this file instead of `better-sqlite3-worker.cjs`; it wraps the two
 * things the worker calls (`node:fs` and the `better-sqlite3` constructor) so
 * a test can place an event at an exact step of the open sequence, then
 * loads the real worker. The worker itself holds no hook.
 *
 * `workerData.harness` is `{ worker, replaceAfterCreate?, park? }`:
 * - `worker`: absolute path of the real worker file.
 * - `replaceAfterCreate`: after the writer's exclusive create of the database
 *   file closes, another file is renamed over it.
 * - `park: { step, gate }`: the read connection stops at `step`
 *   ("open": before the read-only database opens; "run": with a read in
 *   flight) until the test releases `gate`: an Int32Array over a
 *   SharedArrayBuffer, `[0]` set when parked, `[1]` set to release.
 */
const { workerData } = require("node:worker_threads");
const fs = require("node:fs");

const { worker, replaceAfterCreate, park } = workerData.harness;
delete workerData.harness;

if (replaceAfterCreate) {
  const { openSync, closeSync, renameSync, writeFileSync } = fs;
  const created = new Map();
  fs.openSync = (path, flags, ...rest) => {
    const fd = openSync(path, flags, ...rest);
    if (flags === "wx") created.set(fd, path);
    return fd;
  };
  fs.closeSync = (fd) => {
    closeSync(fd);
    const path = created.get(fd);
    if (path === undefined) return;
    created.delete(fd);
    writeFileSync(`${path}.other`, "");
    renameSync(`${path}.other`, path);
  };
}

if (park) {
  const gate = new Int32Array(park.gate);
  const parkHere = () => {
    Atomics.store(gate, 0, 1);
    Atomics.notify(gate, 0);
    Atomics.wait(gate, 1, 0);
  };
  const Database = require("better-sqlite3");
  require.cache[require.resolve("better-sqlite3")].exports = new Proxy(
    Database,
    {
      construct(target, args) {
        const reading = args[1]?.readonly === true;
        if (reading && park.step === "open") parkHere();
        const db = Reflect.construct(target, args);
        if (reading && park.step === "run") {
          const prepare = db.prepare;
          db.prepare = function (sql) {
            const stmt = prepare.call(this, sql);
            const all = stmt.all;
            stmt.all = (...params) => {
              parkHere();
              return all.apply(stmt, params);
            };
            return stmt;
          };
        }
        return db;
      },
    },
  );
}

require(worker);
