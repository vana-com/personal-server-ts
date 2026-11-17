// A record larger than a segment can hold goes out of line: its body is
// stored as encrypted, content-addressed pieces under the log scope, and the
// segment's upsert names them by hash. One such record must not stop the
// connection: it publishes, another device reads it byte for byte, and the
// connection's other records keep publishing after it.
import { afterEach, describe, expect, it } from "vitest";
import {
  closeWorldDrivers,
  LOG,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const s = sName(0);
const MiB = 1024 * 1024;

describe("log publish of a record larger than a segment", () => {
  it("publishes a 40 MiB record that a second device reads byte-exact, and keeps publishing", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", [
      { stream: s, id: "small" },
      { stream: s, id: "big", pad: 40 * MiB },
      { stream: s, id: "tail" },
    ]);
    const first = await a.sync.cycle();
    expect(first.connections.map((c) => c.error)).toEqual([null]);

    // The connection keeps publishing after it.
    await a.run("r2", [{ stream: s, id: "after" }], { full: false });
    await a.cycle();

    const b = await w.device("b");
    await b.cycle();
    const theirs = await b.records();
    expect(theirs.map((r) => r.split("=")[0])).toEqual([
      `${s}/after`,
      `${s}/big`,
      `${s}/small`,
      `${s}/tail`,
    ]);
    expect(theirs).toEqual(await a.records());
    const big = theirs.find((r) => r.startsWith(`${s}/big=`))!;
    expect(big.length).toBeGreaterThan(40 * MiB);

    // No segment carries the body itself.
    const segments = w.innerBlobs
      .keys()
      .filter((k) => k.startsWith(`${LOG}/s-`));
    expect(segments.length).toBeGreaterThan(0);
    for (const key of segments)
      expect((await w.innerBlobs.get(key))!.length).toBeLessThan(4 * MiB);
  }, 300_000);

  it("a reader refuses a body with a missing or altered piece and applies nothing", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", [
      { stream: s, id: "small" },
      { stream: s, id: "big", pad: 6 * MiB },
    ]);
    await a.cycle();
    const [piece] = w.innerBlobs
      .keys()
      .filter((k) => k.startsWith(`${LOG}/v-`));
    const kept = (await w.innerBlobs.get(piece!))!;

    w.innerBlobs.delete(piece!);
    const b = await w.device("b");
    expect((await b.sync.cycle()).connections[0]!.error).toContain(
      "missing a piece",
    );
    expect(await b.position()).toBe(0);
    expect(await b.records()).toEqual([]);

    const altered = kept.slice();
    altered[altered.length - 1]! ^= 1;
    await w.innerBlobs.put(piece!, altered);
    expect((await b.sync.cycle()).connections[0]!.error).toMatch(
      /piece fails its hash|decrypt|tag|auth/i,
    );
    expect(await b.position()).toBe(0);

    await w.innerBlobs.put(piece!, kept);
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
  }, 300_000);

  it("a snapshot names the same pieces, uploads none again, and a device behind it reads the record", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("r1", [
      { stream: s, id: "small" },
      { stream: s, id: "big", pad: 20 * MiB },
    ]);
    await a.cycle();
    const pieces = () =>
      w.innerBlobs.keys().filter((k) => k.startsWith(`${LOG}/v-`));
    const written = pieces();
    expect(written.length).toBeGreaterThan(0);
    const piecePuts = () => a.puts.filter((k) => k.startsWith(`${LOG}/v-`));
    const putBefore = piecePuts().length;

    // Small segments until the writer compacts (its own cost rule decides).
    for (let i = 0; ; i++) {
      const segments = await w.segments();
      if (segments.get(Math.max(...segments.keys()))!.snapshot !== null) break;
      await a.run(`g${i}`, [{ stream: s, id: "x", v: i }], {
        full: false,
        observedAt: 2000 + i,
      });
      await a.cycle();
    }
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    const entries = (await w.snapshotParts(head)).flatMap((p) => p.entries);
    const big = entries.find((e) => e.kind === "upsert-ref");
    if (big?.kind !== "upsert-ref") throw new Error("no out-of-line entry");
    // The same pieces (equal pieces share one name), and no piece PUT again.
    expect(
      [...new Set(big.body.pieces.map((h) => `${LOG}/v-${h.slice(2)}`))].sort(),
    ).toEqual([...written].sort());
    expect(pieces()).toEqual(written);
    expect(piecePuts()).toHaveLength(putBefore);

    const c = await w.device("c");
    await c.cycle();
    expect(await c.records()).toEqual(await a.records());
  }, 300_000);
});
