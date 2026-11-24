// A purge that lands while a multi-object upload is blocked. The upload reads
// each object from the spool when its put starts; the purge deleted the spool,
// so a read that comes after it finds nothing. The publish must end as one
// whose connection was purged, not fail on the missing row.
import { afterEach, expect, it } from "vitest";
import { purgeConnection } from "../../../core/src/localdb/purge.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("settles a publish whose connection was purged while its uploads were blocked", async () => {
  const w = await world({ streams: 1, partTargetBytes: 1000 });
  const inFlight = 16;
  let started = 0;
  let released = false;
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let allBlocked!: () => void;
  const blocked = new Promise<void>((r) => {
    allBlocked = r;
  });
  const a = await w.device("a", {
    beforePut: async () => {
      if (released) return;
      if (++started >= inFlight) allBlocked();
      await gate;
    },
  });
  // Pieces are named by their bytes, so a repeated pad would be one object.
  // A period of 997 against a part target of 1000 makes every piece differ,
  // and 40 periods give more pieces than uploads in flight.
  const period = Array.from({ length: 997 }, (_, i) =>
    String.fromCharCode(97 + ((i * 7919 + (i >> 3)) % 26)),
  ).join("");
  await a.run("r1", [{ stream: sName(0), id: "x", pad: 40, padWith: period }]);
  const publishing = publishLog(a.deps, CONNECTION_ID).then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  await blocked;
  await purgeConnection(a.deps, CONNECTION_ID, { controlVersion: 9 });
  released = true;
  release();
  const outcome = await publishing;
  expect(outcome).not.toHaveProperty("error");
  expect(w.writes().batches).toBe(0);
  const [spool] = await a.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM log_spool",
  );
  expect(spool!.n).toBe(0);
});
