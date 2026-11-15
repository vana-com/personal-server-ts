// One sync cycle commits the streams of several connections in shared registry
// requests (`deps.crossConnectionBatch`). The world is in
// cross-connection-world.test-helper.ts: the real gateway adapter, publish
// driver, SQLite driver and connection queue, against a fake gateway that
// implements the batch contract, the `Batch-Policy` header and its bounds.
//
// Every arrival order below is made, not hoped for: part uploads park, a test
// releases them one by one, and the first request is held in flight so that
// the commits that become ready meanwhile are all waiting when it returns.
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  holdSlots,
  runCycle,
  type LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { parseBatchPolicy } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  closeWorlds,
  connectionIdOf,
  connectorOf,
  controlOf,
  scopeOf,
  world,
} from "./cross-connection-world.test-helper.js";

afterEach(closeWorlds);

/** The connections a request carries rows of, by control scope. */
const connectionsOf = (rows: readonly { scope: string }[]) =>
  [...new Set(rows.map((r) => r.scope.split(".")[1]!.split("~")[0]!))].sort();

describe("a sync cycle commits several connections in one request", () => {
  it("connections that finish together share the request: 3 connections, 1 + 1 requests", async () => {
    const w = await world({
      streams: [2, 2, 2],
      hold: true,
      crossConnectionBatch: true,
      gateway: { policy: { rows: 64, requires: 1010, bytes: 1_964_499 } },
    });
    const report = await w.cycleWithFirstHeld();
    for (const connection of report.connections) {
      expect(connection.error).toBeNull();
      expect(connection.published.map((r) => r.outcome)).toEqual([
        "published",
        "published",
      ]);
    }
    const batches = w.gateway.batches();
    expect(batches.map((b) => b.body.rows.length)).toEqual([1, 5]);
    // The second request is one gateway transaction over rows of every
    // connection, with one condition per connection on its control row.
    const second = batches[1]!.body;
    expect(second.requires.map((r) => r.scope).sort()).toEqual(
      [0, 1, 2].map(controlOf).sort(),
    );
    expect(
      connectionsOf(second.rows.concat(batches[0]!.body.rows)),
    ).toHaveLength(3);
    for (const c of [0, 1, 2]) {
      for (const i of [0, 1]) expect(w.gateway.rowsOf(scopeOf(c, i))).toBe(1);
    }
  });

  it("without the flag no request carries rows of two connections", async () => {
    const w = await world({
      streams: [2, 2, 2],
      hold: true,
      gateway: { policy: { rows: 64, requires: 1010, bytes: 1_964_499 } },
    });
    await w.cycleWithFirstHeld();
    for (const batch of w.gateway.batches()) {
      expect(connectionsOf(batch.body.rows)).toHaveLength(1);
    }
    // At least one request per connection.
    expect(w.gateway.batches().length).toBeGreaterThanOrEqual(3);
  });

  it("one connection deleted: nothing of the failed request lands; the others go again without it", async () => {
    const w = await world({
      streams: [2, 2, 2],
      hold: true,
      crossConnectionBatch: true,
      gateway: { policy: { rows: 64, requires: 1010, bytes: 1_964_499 } },
    });
    let deleted = -1;
    const report = await w.cycleWithFirstHeld((first) => {
      // Delete a connection that the held request does not carry.
      const lead = connectionsOf(first.rows)[0]!;
      deleted = [0, 1, 2].find((c) => connectorOf(c) !== lead)!;
      w.tombstone(deleted);
    });
    const kept = [0, 1, 2].filter((c) => c !== deleted);
    expect(report.connections.map((c) => c.error)).toEqual([null, null, null]);
    const outcomesOf = (c: number) =>
      report.connections
        .find((r) => r.connectionId === connectionIdOf(c))!
        .published.map((r) => r.outcome);
    expect(outcomesOf(deleted)).toEqual(["purged", "purged"]);
    for (const c of kept) {
      expect(outcomesOf(c)).toEqual(["published", "published"]);
      for (const i of [0, 1]) expect(w.gateway.rowsOf(scopeOf(c, i))).toBe(1);
    }
    for (const i of [0, 1])
      expect(w.gateway.rowsOf(scopeOf(deleted, i))).toBe(0);
    const batches = w.gateway.batches();
    // lead alone; then every connection (refused: the deleted one's control
    // row); then the other connections without it.
    expect(batches.map((b) => b.body.rows.length)).toEqual([1, 5, 3]);
    expect(connectionsOf(batches[1]!.body.rows)).toHaveLength(3);
    expect(connectionsOf(batches[2]!.body.rows)).not.toContain(
      connectorOf(deleted),
    );
    expect(batches[2]!.body.requires.map((r) => r.scope)).not.toContain(
      controlOf(deleted),
    );
  });

  it("a gateway that advertises bounds above 16 gets requests above 16 rows", async () => {
    // 4 connections x 8 streams = 32 rows; after the lead request the other
    // 31 go in requests of at most 24 rows (the advertised bound), never
    // splitting a stream, and never 16 as the old gateway's cap.
    const w = await world({
      streams: [8, 8, 8, 8],
      hold: true,
      crossConnectionBatch: true,
      gateway: { policy: { rows: 24, requires: 40, bytes: 1_000_000 } },
    });
    const report = await w.cycleWithFirstHeld();
    for (const connection of report.connections) {
      expect(connection.error).toBeNull();
    }
    expect(w.gateway.batches().map((b) => b.body.rows.length)).toEqual([
      1, 24, 7,
    ]);
    for (const b of w.gateway.batches()) {
      expect(b.body.requires.length).toBeLessThanOrEqual(40);
    }
  });

  it("one connection of 20 streams uses the advertised bound too", async () => {
    const w = await world({
      streams: [20],
      hold: true,
      gateway: { policy: { rows: 24, requires: 40, bytes: 1_000_000 } },
    });
    await w.cycleWithFirstHeld();
    expect(w.gateway.batches().map((b) => b.body.rows.length)).toEqual([1, 19]);
  });

  it("a gateway with no Batch-Policy keeps the 16-row cap, across connections too", async () => {
    const w = await world({
      streams: [8, 8, 8, 8],
      hold: true,
      crossConnectionBatch: true,
    });
    const report = await w.cycleWithFirstHeld();
    for (const connection of report.connections) {
      expect(connection.error).toBeNull();
    }
    const sizes = w.gateway.batches().map((b) => b.body.rows.length);
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(32);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(16);
    expect(sizes.length).toBeLessThan(5);
  });

  it("a gateway without the batch route: every stream commits alone", async () => {
    const w = await world({
      streams: [2, 2],
      crossConnectionBatch: true,
      gateway: { batchRoute: 404 },
    });
    const report = await runCycle(w.deps);
    for (const connection of report.connections) {
      expect(connection.error).toBeNull();
      expect(connection.published.map((r) => r.outcome)).toEqual([
        "published",
        "published",
      ]);
    }
    for (const c of [0, 1]) {
      for (const i of [0, 1]) expect(w.gateway.rowsOf(scopeOf(c, i))).toBe(1);
    }
  });
});

describe("Batch-Policy", () => {
  it("parses the header the gateway sends", () => {
    expect(parseBatchPolicy("rows=64;bytes=1964499;requires=1010")).toEqual({
      rows: 64,
      bytes: 1964499,
      requires: 1010,
    });
  });
  it("reads nothing from a header it cannot read", () => {
    for (const bad of [
      null,
      "",
      "rows=16",
      "rows=0;bytes=1;requires=1",
      "rows=x;bytes=1;requires=1",
      "rows=1;bytes=1",
    ]) {
      expect(parseBatchPolicy(bad)).toBeUndefined();
    }
  });
});

describe("holdSlots", () => {
  it("turns that share connections in opposite orders both finish", async () => {
    const deps = { queue: connectionQueue() } as unknown as LocalSyncDeps;
    const order: string[] = [];
    const turn = (name: string, ids: string[]) =>
      holdSlots(deps, ids, async () => {
        order.push(`${name}:start`);
        await new Promise((r) => setTimeout(r, 5));
        order.push(`${name}:end`);
      });
    await Promise.all([turn("x", ["b", "a"]), turn("y", ["a", "b"])]);
    // One turn finishes before the other starts: the same slots, one holder.
    expect(order).toHaveLength(4);
    expect(order[0]!.split(":")[1]).toBe("start");
    expect(order[1]!.split(":")[1]).toBe("end");
  });
});
