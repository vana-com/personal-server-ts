"use strict";

/**
 * Test-only seam for `better-sqlite3-worker.cjs` (see `TestSeam`). Each hook
 * runs at one fixed step of the open sequence.
 */
const { renameSync, writeFileSync } = require("node:fs");

module.exports = {
  /** Writer: another file replaces the database between create and open. */
  afterCreate(path, data) {
    if (data?.replaceAfterCreate !== true) return;
    writeFileSync(`${path}.other`, "");
    renameSync(`${path}.other`, path);
  },
  /** Reader: stop before the read connection opens until the test releases it. */
  beforeOpen(data) {
    if (data?.park === "open") park(data.gate);
  },
  /** Reader: stop with a read in flight until the test releases it. */
  beforeRun(data) {
    if (data?.park === "run") park(data.gate);
  },
};

/** gate: Int32Array over a SharedArrayBuffer; [0] set when parked, [1] set to release. */
function park(buffer) {
  const gate = new Int32Array(buffer);
  Atomics.store(gate, 0, 1);
  Atomics.notify(gate, 0);
  Atomics.wait(gate, 1, 0);
}
