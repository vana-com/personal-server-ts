// The requests of one log-mode save, counted rather than timed. Every gateway
// and storage request is held for a fixed latency (request-trace.test-utils.ts),
// so what a save costs is its serial depth (the longest chain of requests in
// which each began after the one before it ended) and its request count, both
// independent of the host's speed.
//
// The floor of a save is one segment PUT and one registry commit, the commit
// after the PUT because it names the object: depth 2. A first save of a new
// connection creates its control row in that same commit (the commit's
// condition is judged on the state it commits), so it is depth 2 as well.
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "@opendatalabs/personal-server-ts-core/localdb";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";
import { requestTrace } from "./request-trace.test-utils.js";

afterEach(closeWorldDrivers);

const six = (prefix: string) =>
  Array.from({ length: 6 }, (_, i) => ({
    stream: sName(i),
    id: `${prefix}${i}`,
  }));

async function openWorld(
  others: number,
  latencyMs: Parameters<typeof requestTrace>[0] = 2,
) {
  const trace = requestTrace(latencyMs);
  const w = await world({ streams: 6, trace });
  const a = await w.device("a");
  for (let c = 0; c < others; c++) {
    await a.run(`other-${c}`, six("o"), { connector: `other${c}` });
    await a.cycle();
  }
  return { trace, w, a };
}

describe("log publish: the requests of one save", () => {
  it("a first save of a new connection puts the segment, then commits the control row and the log row in one request: depth 2, no control post (mutant: FIRST_SAVE_READS_CONTROL)", async () => {
    const { trace, a } = await openWorld(0);
    await a.run("first", six("a"), { connector: "fresh" });
    trace.clear();
    await a.cycle();
    expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
    expect(trace.count("post"), trace.describe()).toBe(0);
    expect(trace.count("put"), trace.describe()).toBe(1);
    expect(trace.count("batch"), trace.describe()).toBe(1);
  });

  it("a later save is a PUT and a commit: depth 2", async () => {
    const { trace, a } = await openWorld(0);
    await a.run("first", six("a"), { connector: "fresh" });
    await a.cycle();
    await a.run("second", six("b"), {
      connector: "fresh",
      full: false,
      covered: [sName(0)],
    });
    trace.clear();
    await a.cycle();
    expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
  });

  // The applies of a cycle reach their listing when their own control read
  // answers. On a loaded host those answers spread over more than one
  // request's time; here each read is held 6 ms longer than the one before,
  // so the spread is set, not left to the host's scheduler.
  for (const [name, latency] of [
    ["at one latency", 2],
    [
      "when the control reads answer at different times",
      (kind: string, nth: number) => (kind === "read" ? 2 + 6 * nth : 2),
    ],
  ] as const)
    it(`listings of the owner's rows: one per cycle, however many other connections the owner has (${name})`, async () => {
      for (const others of [1, 9]) {
        const { trace, a } = await openWorld(others, latency);
        await a.run("save", six("b"), {
          connector: "other0",
          full: false,
          covered: [sName(0)],
        });
        trace.clear();
        await a.cycle();
        // The publish itself is a PUT and a commit, ahead of everything else.
        expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
        // Each connection's apply still reads its own control row (the
        // freshness contract of apply); nothing else is read one request at a
        // time.
        expect(trace.count("read"), trace.describe()).toBe(others);
        // The cycle's one listing, which every apply of the cycle reads its
        // log row from.
        expect(trace.count("list"), trace.describe()).toBe(1);
      }
    });

  it("an attachment goes up beside the segment, not before it: depth 3 (probe, PUT), not 4", async () => {
    const trace = requestTrace(2);
    const w = await world({ streams: 1, trace });
    const a = await w.device("a");
    const bytes = new Uint8Array(5000).fill(7);
    const hash = Buffer.from(sha256(bytes)).toString("hex");
    await a.run("first", [{ stream: sName(0), id: "plain" }]);
    await a.cycle();
    await a.run(
      "second",
      [{ stream: sName(0), id: "m", blobId: `sha256:${hash}` }],
      { blob: { hash, bytes }, full: false },
    );
    trace.clear();
    await a.cycle();
    const key = `${streamScope(CONNECTOR, "", sName(0))}/g1-b-${hash}`;
    expect(a.puts).toContain(key);
    expect(trace.count("put"), trace.describe()).toBe(2);
    expect(trace.depthToLast("batch"), trace.describe()).toBe(3);
  });
});

describe("log apply: the cycle's listing is a hint", () => {
  it("a listing taken before this device's own later commit is read again, not taken for a rolled-back registry", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    await a.run("first", [{ stream: sName(0), id: "x" }]);
    await a.cycle();
    // A listing a cycle took, then a commit of this device after it (a run's
    // end publishes while the cycle is still bootstrapping).
    const listed = await a.deps.registry.listOwnerRows!();
    await a.run("second", [{ stream: sName(0), id: "y" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    const position = await a.position();
    expect(position).toBe(2);
    await expect(
      applyConnection(a.deps, CONNECTION_ID, listed),
    ).resolves.toBeUndefined();
    expect(await a.position()).toBe(position);
  });
});
