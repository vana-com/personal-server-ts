// A segment says, per stream it touches, the stream's primary key, profile and
// completeness (`LogStreamMeta`). A run can change those alone: a connector
// update that collects the same records declares a new profile version. The
// publish must compare the run with what the log last said, not with the
// local stream row, which the run's end has already set to the run's own.
import { afterEach, describe, expect, it } from "vitest";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const rows = [
  { stream: sName(0), id: "x" },
  { stream: sName(0), id: "y" },
];

async function profileVersion(
  device: { db: { query: <T>(sql: string, p: unknown[]) => Promise<T[]> } },
  stream: string,
): Promise<string | null> {
  const [row] = await device.db.query<{ profile_version: string | null }>(
    "SELECT profile_version FROM stream_state WHERE connection_id = ? AND stream = ?",
    [CONNECTION_ID, stream],
  );
  return row?.profile_version ?? null;
}

describe("a stream's meta reaches another device when no row changes", () => {
  it("a new connector version that collects the same records publishes its profile version", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", rows, { version: "1" });
    await a.cycle();
    const b = await w.device("b");
    await b.cycle();
    expect(await profileVersion(b, sName(0))).toBe("1");

    // The same records, collected incrementally by connector version 2: no
    // row changes and no completion, only the profile version.
    await a.run("r2", rows, { version: "2", full: false });
    await a.cycle();
    expect(await profileVersion(a, sName(0))).toBe("2");
    const segments = await w.segments();
    const newest = segments.get(Math.max(...segments.keys()))!;
    expect(
      newest.streams.find((m) => m.stream === sName(0))?.profile.version,
    ).toBe("2");
    // Only the meta changed: the segment carries no row operation.
    expect(newest.operations).toEqual([]);
    expect(segments.size).toBe(2);

    await b.cycle();
    expect(await profileVersion(b, sName(0))).toBe("2");
    expect(await b.records()).toEqual(await a.records());
  });

  it("a full run by a new connector version keeps the records it re-collected", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", rows, { version: "1" });
    await a.cycle();
    // The same records, collected in full by version 2. The publish must not
    // plan r1 again: it is published, and version 2's floor refuses it.
    await a.run("r2", rows, { version: "2" });
    await a.cycle();
    expect(await a.records()).toHaveLength(2);

    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
  });
});
