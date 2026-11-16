// The requests of one log-mode save, counted rather than timed. Every gateway
// and storage request is held for a fixed latency (request-trace.test-utils.ts),
// so what a save costs is its serial depth (the longest chain of requests in
// which each began after the one before it ended) and its request count, both
// independent of the host's speed.
//
// The floor of a save is one segment PUT and one registry commit, the commit
// after the PUT because it names the object: depth 2. A first save of a new
// connection adds the one request that creates its control row, which the
// commit also needs (the commit's condition names it): depth 3 when the post
// comes first, since the PUT is planned after the control verdict.
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
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

async function openWorld(others: number) {
  const trace = requestTrace(2);
  const w = await world({ streams: 6, logProtocol: true, trace });
  const a = await w.device("a");
  for (let c = 0; c < others; c++) {
    await a.run(`other-${c}`, six("o"), { connector: `other${c}` });
    await a.cycle();
  }
  return { trace, w, a };
}

describe("log publish: the requests of one save", () => {
  it("a first save of a new connection creates its control row, puts the segment and commits: depth 3, one control post", async () => {
    const { trace, a } = await openWorld(0);
    await a.run("first", six("a"), { connector: "fresh" });
    trace.clear();
    await a.cycle();
    expect(trace.depthToLast("batch"), trace.describe()).toBe(3);
    expect(trace.count("post"), trace.describe()).toBe(1);
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

  it("listings of the owner's rows stay at three or fewer, however many other connections the owner has", async () => {
    const lists: number[] = [];
    for (const others of [1, 9]) {
      const { trace, a } = await openWorld(others);
      await a.run("save", six("b"), {
        connector: "other0",
        full: false,
        covered: [sName(0)],
      });
      trace.clear();
      await a.cycle();
      lists.push(trace.count("list"));
      // The publish itself is a PUT and a commit, ahead of everything else.
      expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
      // Each connection's apply still reads its own control row (the freshness
      // contract of apply); nothing else is read one request at a time.
      expect(trace.count("read"), trace.describe()).toBe(others);
    }
    // The cycle's own listing, and the listings concurrent applies share: at
    // most two, however many connections apply.
    for (const n of lists) expect(n, `lists ${lists}`).toBeLessThanOrEqual(3);
  });

  it("an attachment goes up beside the segment, not before it: depth 3 (probe, PUT), not 4", async () => {
    const trace = requestTrace(2);
    const w = await world({ streams: 1, logProtocol: true, trace });
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
