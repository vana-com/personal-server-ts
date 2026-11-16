// What `intake.begin` tells its caller about the control row it read, so a
// host that needs the row's state before it collects (the Web save) reads it
// from `begin` and not from the registry a second time.
import { afterEach, describe, expect, it } from "vitest";
import { RunIntakeError } from "../../../core/src/stream-sync/intake.js";
import {
  CONNECTOR,
  CONTROL,
  OWNER,
  closeWorldDrivers,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const request = () => ({
  connector: CONNECTOR,
  artifactDigest: CONNECTOR,
  owner: { address: OWNER, leaseId: null },
  observedAt: 1000,
});

/** Registry reads of one row. The fake names a row it has never held by its path. */
const reads = (w: Awaited<ReturnType<typeof world>>) =>
  w.gateway.calls.filter((c) => c.kind === "read").length;

describe("begin returns the control row it read", () => {
  it("names a connection with no control row as absent, with one registry read", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    const begun = await d.sync.intake.begin("r1", request());
    expect(begun.control).toEqual({ kind: "absent" });
    expect(reads(w)).toBe(1);
  });

  it("names an active connection with its generation", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const d = await w.device("d1");
    await d.run("r1", [{ stream: "s0", id: "a" }]);
    await d.cycle();
    const begun = await d.sync.intake.begin("r2", request());
    expect(begun.control).toEqual({ kind: "active", generation: 1 });
  });

  it("refuses a foreign control row before any local write, leaving no connection row", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    w.gateway.write(CONTROL, {
      dataHash: `0x${"ab".repeat(32)}`,
      metadataHash: `0x${"cd".repeat(32)}`,
    });
    const d = await w.device("d1");
    await expect(d.sync.intake.begin("r1", request())).rejects.toMatchObject({
      name: RunIntakeError.name,
      code: "control_foreign",
    });
    expect(await d.db.query("SELECT 1 FROM connections")).toEqual([]);
    expect(await d.db.query("SELECT 1 FROM runs")).toEqual([]);
  });
});
