// One bad stream, or one unreadable name, must not turn a connection's work
// into an unexplained failure. Each test names what it pins.
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const records = (prefix: string) =>
  [0, 1].flatMap((s) =>
    [1, 2].map((i) => ({ stream: sName(s), id: `${prefix}-${s}-${i}` })),
  );

describe("a connection whose log a device cannot fully read", () => {
  it("reports degraded, naming each stream the load left failed and why", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
      full: false,
      covered: [sName(0)],
    });
    await peer.cycle();
    await peer.run("run-3", [{ stream: sName(1), id: "later" }], {
      full: false,
      covered: [sName(1)],
    });
    await peer.cycle();
    // The newest segment is readable; the one before it is gone.
    const keys = await w.segmentKeys();
    const newest = Math.max(...keys.keys());
    w.innerBlobs.delete(keys.get(newest - 1)!);

    // A host that shows a first load while it fills keeps a row per stream.
    const here = await w.device("here", { progressiveFirstLoad: true });
    const report = await here.sync.cycle();
    const connection = report.connections.find(
      (c) => c.connectionId === CONNECTION_ID,
    )!;
    expect(connection.error).toMatch(/missing log segment/);
    expect(connection.status).toBe("degraded");
    expect(connection.failedStreams).toEqual(
      expect.arrayContaining([
        { stream: sName(0), reason: "missing_log_segment_2" },
        { stream: sName(1), reason: "missing_log_segment_2" },
      ]),
    );
  });
});

describe("a stream name this build does not know", () => {
  it("is update_required, and no blob is fetched for it", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    const here = await w.device("here");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    // A later build reserved another `~` name beside the log.
    w.gateway.write(streamScope(CONNECTOR, "", "~future"), {
      dataHash: `0x${"ab".repeat(32)}`,
      metadataHash: `0x${"cd".repeat(32)}`,
    });
    const gets = here.gets.length;
    const report = await here.sync.cycle();
    const connection = report.connections.find(
      (c) => c.connectionId === CONNECTION_ID,
    )!;
    expect(connection.status).toBe("update_required");
    expect(connection.error).toMatch(/~future/);
    expect(here.gets.slice(gets).some((key) => key.includes("~future"))).toBe(
      false,
    );
    expect(here.gets.slice(gets).some((key) => key.includes("/h-"))).toBe(
      false,
    );
  });
});

describe("a publish that fails while a stream is already marked failed", () => {
  it("reports the publish error without the stale failed streams", async () => {
    const w = await world({ streams: 1 });
    const here = await w.device("here", {
      beforePut: async () => {
        throw new Error("storage unreachable");
      },
    });
    await here.run("run-1", [{ stream: sName(0), id: "a" }]);
    // A failed row an earlier load left; this pass's apply does not touch it.
    await here.db.batch([
      {
        sql: `INSERT INTO stream_partial (connection_id, stream, version, generation, data_hash, head_blob, observed_at, parts_applied, parts_total, records_total, failed, last_error)
       VALUES (?, ?, 1, 1, 'h', 'b', 0, 0, 1, 1, 1, 'missing_log_segment_2')`,
        params: [CONNECTION_ID, sName(0)],
      },
    ]);
    const report = await here.sync.cycle();
    const connection = report.connections.find(
      (c) => c.connectionId === CONNECTION_ID,
    )!;
    expect(connection.error).toMatch(/storage unreachable/);
    expect(connection.status).toBeUndefined();
    expect(connection.failedStreams).toBeUndefined();
  });
});
