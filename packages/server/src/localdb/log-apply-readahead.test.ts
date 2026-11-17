// A log's first load fetches the segments that follow while the ones before
// them are written, and commits the segments it has already fetched together.
// What stays the same is what a reader may see: the rows and the position
// move together, in position order, and a failure keeps what came before it.
// Real publisher, real gateway adapter, real SQLite (log-world.test-utils.ts).
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_STORAGE_ACCESS_POLICY } from "../../../core/src/stream-sync/storage-retry.js";
import { applyConnection } from "../../../core/src/localdb/index.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const STREAM = sName(0);
const SEGMENTS = 8;
/** A budget under one segment: one segment is held at a time. */
const ONE_AT_A_TIME = 1;

/** One stream over `count` segments, each its own run, 20 KB per row. */
async function published(count: number) {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  for (let i = 0; i < count; i++) {
    await a.run(
      `run-${i}`,
      [
        { stream: STREAM, id: `k${i}`, pad: 20_000 },
        // Every run rewrites one shared key: later segments win.
        { stream: STREAM, id: "shared", v: i },
      ],
      { full: false, covered: [STREAM], observedAt: 1000 + i },
    );
    await a.cycle();
  }
  const segments = await w.segments();
  expect([...segments.keys()].sort((x, y) => x - y)).toEqual(
    Array.from({ length: count }, (_, i) => i + 1),
  );
  return w;
}

/** The weight of the heaviest segment, as the head's refs state it. */
async function segmentBytes(w: World) {
  const segments = await w.segments();
  const head = segments.get(Math.max(...segments.keys()))!;
  return Math.max(...head.refs.map((r) => r.bytes));
}

const WRITES_POSITION = "INSERT OR REPLACE INTO log_state";

/** The positions each commit of `d` writes, in order. */
function commitsOf(d: Device) {
  const sizes: number[][] = [];
  const db = d.db as unknown as { batch: Device["db"]["batch"] };
  const batch = db.batch.bind(db);
  db.batch = async (statements) => {
    const positions = statements
      .filter((s) => s.sql.includes(WRITES_POSITION))
      .map((s) => s.params?.[1] as number);
    if (positions.length > 0) sizes.push(positions);
    return batch(statements);
  };
  return sizes;
}

/** Holds the first commit that writes a position until `release`. */
function holdFirstCommit(d: Device) {
  const db = d.db as unknown as { batch: Device["db"]["batch"] };
  const batch = db.batch.bind(db);
  let release!: () => void;
  const open = new Promise<void>((r) => (release = r));
  let held = false;
  db.batch = async (statements) => {
    if (!held && statements.some((s) => s.sql.includes(WRITES_POSITION))) {
      held = true;
      await open;
    }
    return batch(statements);
  };
  return { release };
}

async function connected(w: World, id: string, hooks = {}) {
  // These test the segment-by-segment pass; the keyed load has its own tests.
  const d = await w.device(id, { keyedFirstLoad: false, ...hooks });
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, "fixture"],
    },
  ]);
  return d;
}

async function sequential(w: World) {
  const c = await connected(w, "sequential", {
    maxBytesInFlight: ONE_AT_A_TIME,
  });
  await applyConnection(c.deps, CONNECTION_ID);
  return c;
}

describe("log first load, read-ahead and group commit", () => {
  it("fetches the segments that follow while the first commit is writing", async () => {
    const w = await published(SEGMENTS);
    const b = await connected(w, "b");
    const held = holdFirstCommit(b);
    const applying = applyConnection(b.deps, CONNECTION_ID);
    await new Promise((r) => setTimeout(r, 200));
    // The head was read to plan the pass; the rest are fetched ahead.
    const fetchedWhileWriting = b.gets.filter((k) => k.includes("/s-")).length;
    held.release();
    await applying;
    expect(fetchedWhileWriting).toBe(SEGMENTS);
    expect(await b.position()).toBe(SEGMENTS);
  });

  it("reads no further ahead than the memory budget holds", async () => {
    const w = await published(SEGMENTS);
    // A segment is held as plain and as encrypted bytes: three fit.
    const b = await connected(w, "b", {
      maxBytesInFlight: 2 * 3 * (await segmentBytes(w)),
    });
    const held = holdFirstCommit(b);
    const applying = applyConnection(b.deps, CONNECTION_ID);
    await new Promise((r) => setTimeout(r, 200));
    const fetchedWhileWriting = b.gets.filter((k) => k.includes("/s-")).length;
    held.release();
    await applying;
    // The head, and the three the budget holds.
    expect(fetchedWhileWriting).toBe(1 + 3);
    expect(await b.position()).toBe(SEGMENTS);
  });

  it("commits segments it has fetched together, never more than the budget holds", async () => {
    const w = await published(SEGMENTS);
    const b = await connected(w, "b", {
      maxBytesInFlight: 2 * 3 * (await segmentBytes(w)),
    });
    const commits = commitsOf(b);
    await applyConnection(b.deps, CONNECTION_ID);
    expect(commits.flat()).toEqual(
      Array.from({ length: SEGMENTS }, (_, i) => i + 1),
    );
    expect(commits.length).toBeLessThan(SEGMENTS);
    expect(Math.max(...commits.map((c) => c.length))).toBeLessThanOrEqual(3);
  });

  it("ends in the rows and the position a segment-by-segment apply ends in", async () => {
    const w = await published(SEGMENTS);
    const one = await sequential(w);
    const grouped = await connected(w, "grouped");
    const commits = commitsOf(grouped);
    await applyConnection(grouped.deps, CONNECTION_ID);
    expect(commits.length).toBeLessThan(SEGMENTS);
    expect(await grouped.rows()).toEqual(await one.rows());
    expect(await grouped.position()).toBe(await one.position());
    expect((await grouped.rows()).length).toBe(SEGMENTS + 1);
  });

  it("writes a position only in the commit that holds every row up to it", async () => {
    const w = await published(SEGMENTS);
    const b = await connected(w, "b");
    // After each commit, the rows are those of the segments up to the position.
    const db = b.db as unknown as { batch: Device["db"]["batch"] };
    const batch = db.batch.bind(db);
    const seen: { position: number; keys: number }[] = [];
    db.batch = async (statements) => {
      const out = await batch(statements);
      if (statements.some((s) => s.sql.includes(WRITES_POSITION)))
        seen.push({
          position: await b.position(),
          keys: (await b.records()).length,
        });
      return out;
    };
    await applyConnection(b.deps, CONNECTION_ID);
    for (const { position, keys } of seen) expect(keys).toBe(position + 1);
    expect(seen.at(-1)).toEqual({ position: SEGMENTS, keys: SEGMENTS + 1 });
  });

  it("keeps what precedes a segment it cannot fetch, raises the error, and goes on when it is there", async () => {
    const w = await published(SEGMENTS);
    const keys = await w.segmentKeys();
    const missing = keys.get(5)!;
    const bytes = (await w.innerBlobs.get(missing))!;
    await w.innerBlobs.delete(missing);

    const b = await connected(w, "b");
    await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow();
    // Segments 1 to 4 are in, with their position; nothing of 5 or after.
    expect(await b.position()).toBe(4);
    expect((await b.records()).length).toBe(4 + 1);

    await w.innerBlobs.put(missing, bytes);
    await applyConnection(b.deps, CONNECTION_ID);
    const one = await sequential(w);
    expect(await b.rows()).toEqual(await one.rows());
    expect(await b.position()).toBe(SEGMENTS);
  });

  it("gives its memory back when the apply fails", async () => {
    const w = await published(SEGMENTS);
    const keys = await w.segmentKeys();
    await w.innerBlobs.delete(keys.get(3)!);
    const b = await connected(w, "b");
    await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow();
    const whole = b.deps.blobs.governor.reserve(
      DEFAULT_STORAGE_ACCESS_POLICY.maxBytesInFlight,
    );
    const outcome = await Promise.race([
      whole.then((release) => (release(), "granted")),
      new Promise((resolve) => setTimeout(() => resolve("waiting"), 100)),
    ]);
    expect(outcome).toBe("granted");
  });
});
