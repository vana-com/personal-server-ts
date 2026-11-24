// A rebase that fails before it moves the log position. Its seed (the changes
// and tombstones that put the lost history back) is already written when the
// move fails. That is by design (`log-rebase.ts`): every seeded row carries a
// stamp the lost history holds, so it changes no key when it merges, and the
// next rebase skips a key whose change is pending. These tests hold that: the
// retry ends in the same records, and queues no key twice.
import { afterEach, expect, it } from "vitest";
import type { SqlDriver } from "../../../core/src/localdb/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import {
  closeWorldDrivers,
  LOG,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const s = sName(0);

/** A database whose next write of the log position fails once armed. */
const failingPositionMove = (inner: SqlDriver, arm: { on: boolean }) =>
  ({
    ...inner,
    batch: async (statements: Parameters<SqlDriver["batch"]>[0]) => {
      if (
        arm.on &&
        statements.some((st) => st.sql.includes("INTO log_state"))
      ) {
        arm.on = false;
        throw new Error("the move of the position failed");
      }
      return inner.batch(statements);
    },
  }) as SqlDriver;

it("a rebase whose position move fails is finished by the next cycle, and queues no key twice", async () => {
  const arm = { on: false };
  const w = await world({
    streams: 1,
    database: (deviceId) =>
      deviceId === "a"
        ? failingPositionMove(openBetterSqlite3(":memory:"), arm)
        : openBetterSqlite3(":memory:"),
  });
  const a = await w.device("a");
  await a.run(
    "r1",
    [
      { stream: s, id: "x" },
      { stream: s, id: "v" },
      { stream: s, id: "w" },
    ],
    { observedAt: 1100 },
  );
  await a.cycle();
  const b = await w.device("b");
  await b.cycle();
  await a.run("r2", [{ stream: s, id: "x", remove: true }], {
    full: false,
    observedAt: 1300,
  });
  await a.cycle();
  await a.run(
    "r3",
    [
      { stream: s, id: "w" },
      { stream: s, id: "z" },
    ],
    { observedAt: 1400 },
  );
  await a.cycle();
  expect(await a.position()).toBe(3);

  // The registry goes back to position 1 and b writes another position 2.
  w.gateway.versions.get(LOG)!.splice(-2);
  await b.run("rb", [{ stream: s, id: "q" }], {
    full: false,
    observedAt: 1200,
  });
  await b.cycle();

  arm.on = true;
  const report = await a.sync.cycle();
  expect(report.connections.map((c) => c.error)).not.toEqual([null]);
  expect(arm.on).toBe(false);
  expect(await a.position()).toBe(3);

  // The next cycle does the whole rebase.
  const retry = await a.sync.cycle();
  expect(retry.connections.map((c) => c.error)).toEqual([null]);
  const ids = (await a.records()).map((r) => r.split("=")[0]);
  expect(ids).toEqual([`${s}/q`, `${s}/w`, `${s}/z`]);
  expect(await a.position()).toBeGreaterThan(0);
  const twice = await a.db.query(
    `SELECT c.stream, c.pk_hash FROM record_changes c
       JOIN stream_state s ON s.connection_id = c.connection_id AND s.stream = c.stream
      WHERE c.seq > s.publish_watermark
      GROUP BY c.stream, c.pk_hash HAVING COUNT(*) > 1`,
  );
  expect(twice).toEqual([]);
});
