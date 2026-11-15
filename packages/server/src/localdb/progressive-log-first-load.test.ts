// Progressive first load over the log: a stream a device has no complete head
// of is readable from its first applied segment (or snapshot part), in the
// partial state, and fills in as the log applies, even with the log protocol
// on. Real publisher, real gateway adapter, real SQLite, the real apply and
// the real resolver (log-world.ts). The apply is stopped between two batches by
// a gate on the database write that carries the next log position, or where it
// fetches one snapshot part's blob, so each state is read while it is still the
// state.
//
// The rule these tests hold to: a row is shown only if the finished log keeps
// it. A segment is applied only after every later segment is fetched, so a key
// that a later segment deletes or omits is never shown, at any point.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  logScope,
  type Segment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  createConnectionDeleter,
} from "../../../core/src/localdb/index.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import {
  PartialViewMoved,
  partialBody,
} from "../../../core/src/localdb/partial-read.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  idHash,
  sName,
  world,
} from "./log-world.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const SCOPE = `pdpp.${CONNECTOR}.${sName(0)}`;
const STREAM = sName(0);
const LOG = logScope(CONNECTOR, "");
const BLOCKED = "blocked" as const;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** One run of `a` that publishes as its own segment. */
async function publish(
  a: Device,
  runId: string,
  ids: readonly string[],
  options: { remove?: boolean; full?: boolean; observedAt: number },
) {
  await a.run(
    runId,
    ids.map((id) => ({
      stream: STREAM,
      id,
      ...(options.remove ? { remove: true } : {}),
    })),
    {
      full: options.full ?? false,
      covered: [STREAM],
      observedAt: options.observedAt,
    },
  );
  await a.cycle();
}

/** Stops `d`'s apply just before it writes the log position `position`. */
function gate(d: Device) {
  const db = d.db as unknown as { batch: Device["db"]["batch"] };
  const batch = db.batch.bind(db);
  const gates = new Map<number, { reached: () => void; open: Promise<void> }>();
  db.batch = async (statements) => {
    const write = statements.find((s) =>
      s.sql.includes("INSERT OR REPLACE INTO log_state"),
    );
    const position = write?.params?.[1];
    const held = typeof position === "number" ? gates.get(position) : undefined;
    if (held) {
      held.reached();
      await held.open;
    }
    return batch(statements);
  };
  return {
    /** Holds the batch that moves the position to `position`. */
    before(position: number) {
      let reached!: () => void;
      let release!: () => void;
      const arrived = new Promise<void>((r) => (reached = r));
      const open = new Promise<void>((r) => (release = r));
      gates.set(position, { reached, open });
      return { arrived, release };
    },
  };
}

async function connect(d: Device) {
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
}

function reader(d: Device) {
  const resolver = createLocalResolver(d.deps, {
    query: createRecordQuery(d.db),
    olderVersions: { read: vi.fn(), list: vi.fn(), counts: vi.fn() } as never,
  });
  async function read() {
    const decision = await resolver.resolve({
      scope: SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    if (decision.kind !== "view")
      return {
        kind: decision.kind === "unavailable" ? decision.reason : decision.kind,
        ids: [] as string[],
        partial: undefined,
      };
    const body = JSON.parse(await new Response(decision.body).text()) as {
      data: { records: { id: string }[] };
    };
    return {
      kind: "view" as const,
      ids: body.data.records.map((r) => r.id).sort(),
      partial: decision.partial,
    };
  }
  /** A read that does not wait for an apply it is blocked behind. */
  async function readNow() {
    const reading = read();
    const first = await Promise.race([reading, sleep(400).then(() => BLOCKED)]);
    if (first === BLOCKED) void reading.catch(() => undefined);
    return first;
  }
  return { read, readNow };
}

/** Starts an apply of `d` and waits until `held` has stopped it. */
async function stopAt(
  d: Device,
  held: { arrived: Promise<void> },
): Promise<{ applying: Promise<unknown> }> {
  const applying = applyConnection(d.deps, CONNECTION_ID);
  const failed = applying.then(() => {
    throw new Error("the apply ended before it reached the gate");
  });
  failed.catch(() => undefined);
  await Promise.race([held.arrived, failed]);
  return { applying };
}

const count = async (d: Device, table: string) =>
  (await d.db.query<{ n: number }>(`SELECT count(*) AS n FROM ${table}`))[0]!.n;
const idsOf = async (d: Device) =>
  (
    await d.db.query<{ body: string }>(
      "SELECT body FROM records WHERE stream = ?",
      [STREAM],
    )
  )
    .map((r) => (JSON.parse(r.body) as { id: string }).id)
    .sort();

/**
 * One stream over seven segments. Position 4 deletes A2; position 6 is a full
 * pass that does not list A3, so it omits A3. The finished stream is A1, B, C,
 * D and E.
 */
async function sevenSegments(w: World) {
  const a = await w.device("a");
  await publish(a, "run-1", ["A1", "A2", "A3"], {
    full: true,
    observedAt: 1100,
  });
  await publish(a, "run-2", ["B"], { observedAt: 1200 });
  await publish(a, "run-3", ["C"], { observedAt: 1300 });
  await publish(a, "run-4", ["A2"], { remove: true, observedAt: 1400 });
  await publish(a, "run-5", ["D"], { observedAt: 1500 });
  await publish(a, "run-6", ["A1", "B", "C", "D"], {
    full: true,
    observedAt: 1600,
  });
  await publish(a, "run-7", ["E"], { observedAt: 1700 });
  const segments = await w.segments();
  expect([...segments.keys()].sort()).toEqual([1, 2, 3, 4, 5, 6, 7]);
  // The setup holds: position 6 omits A3 by name.
  const omits = segments
    .get(6)!
    .operations.flatMap((op) => (op.kind === "complete" ? op.omitted : []));
  expect(omits).toEqual([await idHash("A3")]);
  return a;
}

describe("progressive first load, log protocol on", () => {
  it("a stream over many segments is readable before the last segment applies, and complete after", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await sevenSegments(w);
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const reads = reader(b);
    const held = gate(b).before(7);
    const { applying } = await stopAt(b, held);

    // Six segments are applied, the seventh is not.
    const view = await reads.readNow();
    expect(view).not.toBe(BLOCKED);
    expect(view).toMatchObject({ kind: "view" });
    if (view === BLOCKED) return;
    // A2 and A3 are gone in the log's later segments: never shown.
    expect(view.ids).toEqual(["A1", "B", "C", "D"]);
    expect(view.partial).toMatchObject({ partsApplied: 6, partsTotal: 7 });

    held.release();
    await applying;
    const done = await reads.read();
    expect(done.kind).toBe("view");
    expect(done.partial).toBeUndefined();
    expect(done.ids).toEqual(["A1", "B", "C", "D", "E"]);
  });

  it("a key a later fetched segment deletes or omits is never readable, at any point", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await sevenSegments(w);
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const reads = reader(b);
    const gates = gate(b);
    const seen: string[][] = [];
    const held = new Map(
      [2, 3, 4, 5, 6, 7].map((p) => [p, gates.before(p)] as const),
    );
    const applying = applyConnection(b.deps, CONNECTION_ID);
    for (const [position, g] of held) {
      await Promise.race([g.arrived, applying]);
      const view = await reads.readNow();
      expect(view, `before position ${position}`).not.toBe(BLOCKED);
      if (view === BLOCKED) break;
      expect(view.kind).toBe("view");
      seen.push(view.ids);
      g.release();
    }
    await applying;
    // After 1, 2, 3, 4, 5 and 6 segments. A2 (deleted at 4) and A3 (omitted at
    // 6) are in no view, though both are stored from the first segment on.
    expect(seen).toEqual([
      ["A1"],
      ["A1", "B"],
      ["A1", "B", "C"],
      ["A1", "B", "C"],
      ["A1", "B", "C", "D"],
      ["A1", "B", "C", "D"],
    ]);
    expect(await count(b, "stream_partial")).toBe(0);
  });

  it("a key that a later segment deletes and a still later segment writes again is readable once it is written again", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    await publish(a, "run-1", ["A", "B"], { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["A"], { remove: true, observedAt: 1200 });
    await publish(a, "run-3", ["C"], { observedAt: 1300 });
    await publish(a, "run-4", ["A"], { observedAt: 1400 });
    await publish(a, "run-5", ["D"], { observedAt: 1500 });
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const reads = reader(b);
    const gates = gate(b);
    const held = [2, 3, 4, 5].map((p) => gates.before(p));
    const applying = applyConnection(b.deps, CONNECTION_ID);
    const seen: string[][] = [];
    for (const g of held) {
      await Promise.race([g.arrived, applying]);
      const view = await reads.readNow();
      expect(view).not.toBe(BLOCKED);
      if (view === BLOCKED) break;
      seen.push(view.ids);
      g.release();
    }
    await applying;
    // A is deleted at 2 and written again at 4: hidden until 4 applies.
    expect(seen).toEqual([["B"], ["B"], ["B", "C"], ["A", "B", "C"]]);
    expect((await reads.read()).ids).toEqual(["A", "B", "C", "D"]);
  });

  it("the finished stream is the one a device with the flag off gets, and the view clears its mark", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await sevenSegments(w);
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const held = gate(b).before(7);
    const { applying } = await stopAt(b, held);
    expect(await count(b, "stream_partial")).toBe(1);
    expect(await count(b, "partial_hidden")).toBeGreaterThan(0);
    held.release();
    await applying;

    expect(await count(b, "stream_partial")).toBe(0);
    expect(await count(b, "partial_hidden")).toBe(0);
    const plain = await w.device("plain", true);
    await plain.cycle();
    expect(await idsOf(b)).toEqual(await idsOf(plain));
    expect(await b.records()).toEqual(await plain.records());
    const state = await b.db.query<{ complete: number; head_version: number }>(
      "SELECT complete, head_version FROM stream_state WHERE stream = ?",
      [STREAM],
    );
    expect(state[0]!.complete).toBe(1);
  });

  it("a body that is reading when the load completes goes on to the end", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const ids = Array.from(
      { length: 205 },
      (_, i) => `r${String(i).padStart(3, "0")}`,
    );
    await publish(a, "run-1", ids, { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["tail"], { observedAt: 1200 });
    await publish(a, "run-3", ["tail2"], { observedAt: 1300 });
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const held = gate(b).before(3);
    const { applying } = await stopAt(b, held);
    const [load] = await b.db.query<{ version: number; data_hash: string }>(
      "SELECT version, data_hash FROM stream_partial",
    );
    const body = partialBody(b.db, {
      connectionId: CONNECTION_ID,
      generation: 1,
      stream: STREAM,
      version: load!.version,
      dataHash: load!.data_hash,
    });
    expect((await body.next()).value).toBe('{"records":[');
    for (let i = 0; i < 100; i++) expect((await body.next()).done).toBe(false);
    held.release();
    await applying;
    // The load completed under the body; the second page is of the same head.
    let rest = 0;
    for await (const _ of body) rest++;
    expect(rest).toBeGreaterThan(0);
  });

  it("a body that is reading when a delete intent is saved ends in an error while the purge waits for the apply", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    const a = await w.device("a");
    const ids = Array.from(
      { length: 205 },
      (_, i) => `r${String(i).padStart(3, "0")}`,
    );
    await publish(a, "run-1", ids, { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["tail"], { observedAt: 1200 });
    await publish(a, "run-3", ["tail2"], { observedAt: 1300 });
    const b = await w.device("b", true, { progressiveFirstLoad: true });
    await connect(b);
    const held = gate(b).before(3);
    const { applying } = await stopAt(b, held);
    const [load] = await b.db.query<{ version: number; data_hash: string }>(
      "SELECT version, data_hash FROM stream_partial",
    );
    const body = partialBody(b.db, {
      connectionId: CONNECTION_ID,
      generation: 1,
      stream: STREAM,
      version: load!.version,
      dataHash: load!.data_hash,
    });
    expect((await body.next()).value).toBe('{"records":[');
    for (let i = 0; i < 100; i++) expect((await body.next()).done).toBe(false);
    const deleter = createConnectionDeleter(b.deps, {
      declaredStreams: () => [STREAM],
    });
    const requested = deleter
      .requestConnectionDelete(CONNECTOR)
      .catch(() => undefined);
    for (let turn = 0; turn < 500; turn++) {
      if (
        (await b.db.query("SELECT 1 FROM delete_intents")).length > 0 ||
        turn === 499
      )
        break;
      await sleep(10);
    }
    expect(await b.db.query("SELECT 1 FROM delete_intents")).toHaveLength(1);
    expect(await count(b, "stream_partial")).toBe(1); // the purge has not run
    await expect(body.next()).rejects.toBeInstanceOf(PartialViewMoved);
    held.release();
    await Promise.allSettled([applying, requested]);
  });
});

describe(
  "progressive first load over a snapshot, log protocol on",
  { timeout: 90_000 },
  () => {
    /**
     * 24 rows of 400 KB, then updates of one key until the log compacts into
     * several snapshot parts, then a deletion of a row that sits in the
     * snapshot's first part: it is in the tail, after the snapshot. Rows this
     * large make the cost rule (`shouldCompact`) cut more than one part at the
     * default part target. Built once: the publisher's world is only read after.
     */
    let built: ReturnType<typeof build> | undefined;
    const compacted = () => (built ??= build());
    async function build() {
      const w = await world({ streams: 1, logProtocol: true });
      const a = await w.device("a");
      const ids = Array.from(
        { length: 24 },
        (_, i) => `r${String(i).padStart(2, "0")}`,
      );
      await a.run(
        "run-1",
        ids.map((id) => ({ stream: STREAM, id, pad: 400_000 })),
        {
          observedAt: 1100,
        },
      );
      await a.cycle();
      let head: Segment | undefined;
      for (let i = 0; i < 160 && !head?.snapshot; i++) {
        await a.run(`run-g${i}`, [{ stream: STREAM, id: "r00", v: i }], {
          full: false,
          covered: [STREAM],
          observedAt: 2000 + i,
        });
        await a.cycle();
        const segments = await w.segments();
        head = segments.get(Math.max(...segments.keys()));
      }
      expect(head?.snapshot?.parts.length).toBeGreaterThanOrEqual(3);
      const parts = await w.snapshotParts(head!);
      const first = parts[0]!.entries.find((e) => e.kind === "upsert")!;
      const victim = (first as { value: { id: string } }).value.id;
      await publish(a, "run-del", [victim], {
        remove: true,
        observedAt: 3000,
      });
      const segments = await w.segments();
      head = segments.get(Math.max(...segments.keys()))!;
      expect(head.snapshot).not.toBeNull();
      return { w, a, head, parts, victim, ids };
    }

    const partKey = (head: Segment, index: number) =>
      `${LOG}/q-${head.snapshot!.parts[index]!.dataHash.slice(2)}`;

    it("rows of the first parts are readable while a later part is still arriving, minus a key the tail deletes", async () => {
      const { w, head, parts, victim } = await compacted();
      let release!: () => void;
      const open = new Promise<void>((r) => (release = r));
      const slow = partKey(head, 2);
      let blocked!: () => void;
      const arrived = new Promise<void>((r) => (blocked = r));
      const b = await w.device("b", true, {
        progressiveFirstLoad: true,
        beforeGet: async (key) => {
          if (key !== slow) return;
          blocked();
          await open;
        },
      });
      await connect(b);
      const reads = reader(b);
      const applying = applyConnection(b.deps, CONNECTION_ID);
      await Promise.race([arrived, applying]);
      for (let i = 0; i < 300 && (await count(b, "stream_partial")) === 0; i++)
        await sleep(10);

      const view = await reads.readNow();
      expect(view).not.toBe(BLOCKED);
      if (view !== BLOCKED) {
        const inFirstTwo = parts
          .slice(0, 2)
          .flatMap((p) => p.entries)
          .flatMap((e) =>
            e.kind === "upsert" ? [(e.value as { id: string }).id] : [],
          )
          .filter((id) => id !== victim)
          .sort();
        expect(view.kind).toBe("view");
        expect(view.ids).toEqual(inFirstTwo);
        expect(view.ids.length).toBeGreaterThan(0);
        expect(view.ids).not.toContain(victim);
      }
      release();
      await applying;
      const done = await reads.read();
      expect(done.partial).toBeUndefined();
      expect(done.ids).not.toContain(victim);
      const plain = await w.device("plain", true);
      await plain.cycle();
      expect(await idsOf(b)).toEqual(await idsOf(plain));
    });

    it("a snapshot part that is missing stops the load on its row; the next apply carries it on to the end", async () => {
      const { w, head, victim } = await compacted();
      const key = partKey(head, 2);
      const bytes = (await w.innerBlobs.get(key))!;
      w.innerBlobs.delete(key);
      const b = await w.device("b", true, { progressiveFirstLoad: true });
      await connect(b);
      const reads = reader(b);
      await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow(
        "missing log snapshot part",
      );
      const view = await reads.readNow();
      expect(view).not.toBe(BLOCKED);
      if (view !== BLOCKED) {
        expect(view.kind).toBe("view");
        expect(view.ids.length).toBeGreaterThan(0);
        expect(view.ids).not.toContain(victim);
        expect(view.partial?.failed).toEqual({
          code: "missing_log_snapshot_part",
        });
      }
      await w.innerBlobs.put(key, bytes);
      await applyConnection(b.deps, CONNECTION_ID);
      const done = await reads.read();
      expect(done.partial).toBeUndefined();
      const plain = await w.device("plain", true);
      await plain.cycle();
      expect(await idsOf(b)).toEqual(await idsOf(plain));
      expect(await count(b, "stream_partial")).toBe(0);
      expect(await count(b, "partial_hidden")).toBe(0);
    });
  },
);

describe("progressive first load, log protocol on, flag off", () => {
  it("is as before: nothing is readable until the whole log is applied, and no load row is written", async () => {
    const w = await world({ streams: 1, logProtocol: true });
    await sevenSegments(w);
    const b = await w.device("b", true);
    await connect(b);
    await b.db.batch([
      { sql: "CREATE TABLE writes_seen (n INTEGER)" },
      {
        sql: "CREATE TRIGGER writes_seen_ai AFTER INSERT ON stream_partial BEGIN INSERT INTO writes_seen VALUES (1); END",
      },
    ]);
    const reads = reader(b);
    const held = gate(b).before(7);
    const { applying } = await stopAt(b, held);
    expect(await reads.readNow()).toBe(BLOCKED);
    held.release();
    await applying;
    const done = await reads.read();
    expect(done.ids).toEqual(["A1", "B", "C", "D", "E"]);
    expect(done.partial).toBeUndefined();
    expect(await b.db.query("SELECT * FROM writes_seen")).toEqual([]);
    expect(await count(b, "stream_partial")).toBe(0);
  });
});
