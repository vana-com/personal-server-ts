// What one connection's sync asks the registry when it runs outside a cycle
// (`syncConnection`): with no cycle listing to read its log row from, the
// apply reads that one row. Real gateway adapter, drivers and SQLite against
// the fake gateway (fake-gateway.ts).
import { afterEach, expect, it } from "vitest";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  LOG,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("one connection's sync, outside a cycle, reads its log row and lists no rows", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("run-1", [{ stream: sName(0), id: "r1" }]);
  await a.cycle();
  const b = await w.device("b");
  await b.cycle();
  await a.run("run-2", [{ stream: sName(0), id: "r2" }], {
    full: false,
    covered: [sName(0)],
  });
  await a.cycle();
  w.gateway.calls.length = 0;
  const report = await b.sync.syncConnection(CONNECTION_ID);
  expect(report.error).toBeNull();
  expect(await b.rows()).toEqual(await a.rows());
  const kinds = w.gateway.calls.map((call) => call.kind);
  expect(kinds.filter((kind) => kind === "list")).toEqual([]);
  expect(
    w.gateway.calls.filter(
      (call) => call.kind === "read" && call.scope.includes(LOG),
    ),
  ).toHaveLength(1);
});
