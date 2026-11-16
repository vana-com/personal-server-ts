// A mixed fleet: devices of one owner that differ in their build and in the
// local `logProtocol` flag, on one connection. The protocol a connection uses
// is a property of the connection, recorded in the registry by its first log
// write (the log row). A device that can read it follows it whatever its own
// flag says; a device that cannot read it refuses to write that connection and
// says so. No device shows stale data as current, or writes beside the log.
import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, describe, expect, it } from "vitest";
import {
  deriveKeyCheck,
  digestSegment,
  encodeSegment,
  LOG_FORMAT,
  streamScope,
  type Segment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyStream,
  publishConnection,
} from "../../../core/src/localdb/index.js";
import { UpdateRequiredError } from "../../../core/src/localdb/update-required.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  CONTROL,
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const ids = (rows: readonly string[]) => rows.map((r) => r.split("=")[0]);

/** Scopes of the registry that are neither the control row nor the log. */
const streamRows = (w: Awaited<ReturnType<typeof world>>) =>
  [...w.gateway.versions.keys()].filter((s) => s !== CONTROL && s !== LOG);

describe("a device with the log flag off, on a connection that has a log", () => {
  it("reads what the log holds", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a", true);
    const b = await w.device("b", false);
    await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
    await a.cycle();
    await b.cycle();
    expect(ids(await b.records())).toEqual(["s0/a-1"]);
    expect(await b.position()).toBe(1);
  });

  it("writes through the log, never as a per-stream head, and no device loses a row", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    const a = await w.device("a", true);
    const b = await w.device("b", false);
    await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
    await a.cycle();
    await b.cycle();
    await b.run("run-b1", [{ stream: sName(0), id: "b-1" }], {
      full: false,
      covered: [sName(0)],
    });
    await b.cycle();
    await a.cycle();
    await b.cycle();
    expect(streamRows(w)).toEqual([]);
    expect(w.gateway.rowsOf(LOG)).toBe(2);
    const both = ["s0/a-1", "s0/b-1"];
    expect(ids(await a.records())).toEqual(both);
    expect(ids(await b.records())).toEqual(both);
    const fresh = await w.device("fresh", false);
    await fresh.cycle();
    expect(ids(await fresh.records())).toEqual(both);
  });

  it("asks the registry nothing more than before while no log exists", async () => {
    const w = await world({ streams: 2, logProtocol: false });
    const b = await w.device("b", false);
    await b.run("run-b1", [{ stream: sName(0), id: "b-1" }]);
    await b.cycle();
    await b.cycle();
    expect(
      w.gateway.calls.filter((c) => c.kind === "read" && c.scope === LOG),
    ).toEqual([]);
    expect(w.gateway.versions.has(LOG)).toBe(false);
    expect(streamRows(w)).toContain(streamScope(CONNECTOR, "", sName(0)));
  });
});

describe("a per-stream head written beside the log by a build without the gate", () => {
  // Known gap, closed only by a registry rule (docs/formal/mixed-fleet): a
  // client has no condition on a row being absent, so it cannot stop another
  // build's commit. `publishConnection` is what every build without the gate
  // does with the flag off; the gate lives in the cycle. A device that follows
  // the log meets that head and either throws or replaces rows the log holds.
  // `it.fails` keeps the gap visible: it turns red when the gap is closed.
  it.fails(
    "does not erase the rows the log holds on a device that follows the log",
    async () => {
      const w = await world({ streams: 2, logProtocol: true });
      const a = await w.device("a", true);
      const old = await w.device("old", false);
      await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
      await a.cycle();
      await old.run("run-b1", [{ stream: sName(0), id: "b-1" }], {
        full: false,
        covered: [sName(0)],
      });
      await publishConnection(old.deps, CONNECTION_ID);
      expect(streamRows(w)).toHaveLength(1);
      await a.cycle();
      expect(ids(await a.records())).toContain("s0/a-1");
    },
  );
});

/**
 * What a build that writes the older log format leaves in the registry: a log
 * row at the next position whose segment is format 1.
 */
async function olderFormatLogRow(
  w: Awaited<ReturnType<typeof world>>,
  position: number,
): Promise<void> {
  const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
  const segment: Segment = {
    format: LOG_FORMAT,
    connector: CONNECTOR,
    ns: "",
    generation: 1,
    keyCheck,
    position,
    observedAt: 5000,
    base: 0,
    snapshot: null,
    refs: Array.from({ length: position - 1 }, (_, i) => ({
      position: i + 1,
      dataHash: `0x${(i + 1).toString(16).padStart(64, "0")}` as const,
      bytes: 100,
    })),
    streams: [],
    operations: [],
  };
  const bytes = new TextEncoder().encode(
    new TextDecoder()
      .decode(encodeSegment(segment))
      .replace(`"format":${LOG_FORMAT}`, '"format":1'),
  );
  const { dataHash } = await digestSegment(async (b) => keccak_256(b), bytes);
  await w.innerBlobs.put(`${LOG}/s-${dataHash.slice(2)}`, bytes);
  const last = w.gateway.versions.get(LOG)?.at(-1);
  w.gateway.write(LOG, {
    dataHash,
    metadataHash: last?.metadataHash ?? `0x${"00".repeat(32)}`,
  });
}

describe("a log in a format this core cannot read", () => {
  for (const flag of [true, false]) {
    it(`flag ${flag ? "on" : "off"}: refuses to write, keeps the write, and says update required`, async () => {
      const w = await world({ streams: 2, logProtocol: true });
      const a = await w.device("a", true);
      await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
      await a.cycle();
      await olderFormatLogRow(w, 2);

      const b = await w.device("b", flag);
      await b.run("run-b1", [{ stream: sName(0), id: "b-1" }], {
        full: false,
        covered: [sName(0)],
      });
      const report = await b.sync.cycle();
      const [entry] = report.connections;
      expect(entry).toMatchObject({
        connectionId: CONNECTION_ID,
        status: "update_required",
      });
      // Nothing lands: no stream head, no log row beyond the older one. (A
      // log commit may be tried; its compare-and-set on the position loses,
      // because this device cannot have applied the older segment.)
      expect(streamRows(w)).toEqual([]);
      expect(w.gateway.rowsOf(LOG)).toBe(2);
      // The write is kept: the device still holds b-1 locally, unpublished.
      expect(ids(await b.records())).toContain("s0/b-1");
    });
  }
});

describe("applying one stream of a connection that keeps its data in a log", () => {
  // The apply of a stream is the apply of its connection: the log is the
  // connection's, and a stream asked for alone does not skip it.
  it("flag off: finds a log no cycle has seen, and applies it", async () => {
    const w = await world({ streams: 2, logProtocol: true });
    // The device has the connection, from a run of its own before any log.
    const b = await w.device("b", false);
    await b.run("run-b0", [{ stream: sName(1), id: "b-0" }], {
      full: false,
      covered: [sName(1)],
    });
    await b.cycle();
    const a = await w.device("a", true);
    await a.cycle();
    await a.run("run-a1", [{ stream: sName(0), id: "a-1" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    expect(w.gateway.rowsOf(LOG)).toBe(1);
    expect(ids(await b.records())).not.toContain("s0/a-1");

    await applyStream(b.deps, CONNECTION_ID, sName(0));

    expect(ids(await b.records())).toContain("s0/a-1");
  });

  for (const flag of [true, false]) {
    it(`flag ${flag ? "on" : "off"}: advances a log it already knows`, async () => {
      const w = await world({ streams: 2, logProtocol: true });
      const a = await w.device("a", true);
      const b = await w.device("b", flag);
      await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
      await a.cycle();
      await b.cycle();
      await a.run("run-a2", [{ stream: sName(0), id: "a-2" }], {
        full: false,
        covered: [sName(0)],
      });
      await a.cycle();

      await applyStream(b.deps, CONNECTION_ID, sName(0));

      expect(ids(await b.records())).toEqual(["s0/a-1", "s0/a-2"]);
    });

    it(`flag ${flag ? "on" : "off"}: refuses a log in a format it cannot read`, async () => {
      const w = await world({ streams: 2, logProtocol: true });
      const a = await w.device("a", true);
      await a.run("run-a1", [{ stream: sName(0), id: "a-1" }]);
      await a.cycle();
      const b = await w.device("b", flag);
      await b.cycle();
      await olderFormatLogRow(w, 2);

      await expect(
        applyStream(b.deps, CONNECTION_ID, sName(0)),
      ).rejects.toBeInstanceOf(UpdateRequiredError);
    });
  }
});
