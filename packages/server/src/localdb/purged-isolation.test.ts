import { afterEach, expect, it } from "vitest";
import { closeWorldDrivers, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

/**
 * Two connections on one device. Another device deletes "beta" while this
 * device still holds work for it that it has not published. The device's next
 * publish adopts the delete (a purge, F.5) and must leave "alpha" published.
 */
async function deletedElsewhere(collecting: boolean) {
  const w = await world({ streams: 1, publishWhileCollecting: collecting });
  const d1 = await w.device("d1");
  const d2 = await w.device("d2");
  await d1.run("a1", [{ stream: "s0", id: "1" }], { connector: "alpha" });
  await d1.run("b1", [{ stream: "s0", id: "1" }], { connector: "beta" });
  await d1.sync.publish();
  if (collecting) {
    await d1.begin("b2", { connector: "beta" });
    await d1.sync.intake.batch("b2", {
      batch: 0,
      records: [{ stream: "s0", data: { id: "2" } }],
    });
  } else {
    await d1.run("b2", [{ stream: "s0", id: "2" }], { connector: "beta" });
  }
  await d2.cycle();
  await d2.sync.deleter.requestConnectionDelete("beta");
  expect(await d2.sync.deleter.resumeDeletes()).toEqual([]);
  await d1.run("a2", [{ stream: "s0", id: "2" }], { connector: "alpha" });
  return { w, d1 };
}

const outcomes = (
  report: Awaited<
    ReturnType<Awaited<ReturnType<typeof world>>["device"]>["sync"]["publish"]
  >,
  connectionId: string,
) =>
  report.connections
    .filter((c) => c.connectionId === connectionId)
    .flatMap((c) => c.published.map((r) => r.outcome));

it.each([
  ["an ended run", false],
  ["a collecting run", true],
])(
  "adopts another device's delete of a connection without blocking the others, once, for %s",
  async (_name, collecting) => {
    const { w, d1 } = await deletedElsewhere(collecting);
    // Committed versions of the deleted connection's log: a refused attempt
    // writes none.
    const betaLog = () => w.gateway.versions.get("pdpp.beta~.~log")?.length;
    const betaCommits = betaLog();

    const first = await d1.sync.publish();
    expect(outcomes(first, "pdpp.alpha~")).toContain("published");
    expect(outcomes(first, "pdpp.alpha~")).not.toContain("purged");
    expect(
      await d1.db.query(
        "SELECT control_state FROM connections WHERE connection_id = 'pdpp.beta~'",
      ),
    ).toEqual([{ control_state: "deleted" }]);

    // The delete is adopted: later publishes owe the deleted connection nothing.
    for (let i = 0; i < 2; i++) {
      const later = await d1.sync.publish();
      expect(
        later.connections.flatMap((c) => c.published).map((r) => r.outcome),
      ).not.toContain("purged");
    }
    if (!collecting)
      expect(await d1.sync.intake.publicationStatus("b2")).toMatchObject({
        state: "superseded",
      });
    // Nothing of the deleted connection is published again.
    expect(betaLog()).toBe(betaCommits);
  },
);
