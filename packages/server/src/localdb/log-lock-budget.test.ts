// A gateway's lock budget (`Batch-Policy: lockedScopes`) counts a batch's rows
// plus the distinct connection log rows it fences but does not write. A log
// publish writes the connection's log row and nothing else, so it fences none
// and the budget never binds it: the 30 streams that a per-stream publish had
// to split as 1, 25 and 4 rows (#777) go out as one row.
import { afterEach, describe, expect, it } from "vitest";
import {
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

describe("a gateway with a lock budget", () => {
  it("takes a 30-stream log publish as one row, with no refused request", async () => {
    const w = await world({
      streams: 30,
      policy: { rows: 31, requires: 40, bytes: 1_000_000, lockedScopes: 26 },
    });
    const a = await w.device("a");
    await a.run(
      "r1",
      Array.from({ length: 30 }, (_, i) => ({ stream: sName(i), id: `k${i}` })),
    );
    await a.cycle();

    const batches = w.gateway.batches();
    expect(batches).toHaveLength(1);
    expect(batches[0]!.body.rows.map((row) => row.scope)).toEqual([LOG]);
    expect(w.gateway.versions.get(LOG)).toHaveLength(1);
    // The client read the budget, so it was in force for the publish.
    expect(a.deps.registry.batchPolicy?.()).toMatchObject({ lockedScopes: 26 });
    expect((await a.records()).length).toBe(30);
  });
});
