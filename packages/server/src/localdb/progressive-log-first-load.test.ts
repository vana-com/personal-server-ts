// Progressive first load over the log: a stream a device has no complete head
// of is readable from its first applied segment (or snapshot part), in the
// partial state, and fills in as the log applies, even with the log protocol
// on. Real publisher, real gateway adapter, real SQLite, the real apply and
// the real resolver (log-world.test-utils.ts). The apply is stopped between two batches by
// a gate on the database write that carries the next log position, or where it
// fetches one snapshot part's blob, so each state is read while it is still the
// state.
//
// The rule these tests hold to: a row is shown only if the finished log keeps
// it. The segments that delete or omit a key are read before the first apply
// (the head's refs say which), so a key that a later segment deletes or omits is
// never shown, at any point. `streaming-first-load.test.ts` holds the timing:
// listed before a segment is fetched, first rows before the last one is.
//
// The devices set `keyedFirstLoad: false`, which a progressive host no longer
// needs: it loads segment by segment whatever its budget.
import { afterEach, describe, expect, it } from "vitest";
import {
  logScope,
  type Segment,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  createConnectionDeleter,
} from "../../../core/src/localdb/index.js";
import { nextApplied } from "../../../core/src/localdb/apply-progress.js";
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
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const SCOPE = `pdpp.${CONNECTOR}.${sName(0)}`;
const STREAM = sName(0);
const LOG = logScope(CONNECTOR, "");
const BLOCKED = "blocked" as const;
/**
 * A budget under one segment: an apply holds one segment at a time, so each
 * commits by itself and a gate on a position sees the state before it.
 */
const ONE_AT_A_TIME = 1;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const WRITES_POSITION = "INSERT OR REPLACE INTO log_state";
const TABLES: readonly [string, string][] = [
  [
    "records",
    "connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o",
  ],
  [
    "record_changes",
    "connection_id, stream, pk_hash, record_key, op, stamp_o, stamp_r, origin",
  ],
  ["log_tombstones", "*"],
  ["stream_state", "*"],
  ["stream_versions", "*"],
  ["stream_partial", "*"],
  ["partial_hidden", "*"],
  ["log_state", "*"],
];

/** Every table a load writes, as sorted rows of text (not the sequence numbers). */
async function dump(d: Device) {
  const out: Record<string, string[]> = {};
  for (const [table, columns] of TABLES)
    out[table] = (
      await d.db.query<Record<string, unknown>>(
        `SELECT ${columns} FROM ${table}`,
      )
    )
      .map((r) => JSON.stringify(r))
      .sort();
  return out;
}

/** Runs `after` once each commit that writes a log position has landed. */
function afterCommits(
  d: Device,
  after: (positions: number[]) => Promise<void>,
  options: { failCommit?: number } = {},
) {
  const db = d.db as unknown as { batch: Device["db"]["batch"] };
  const batch = db.batch.bind(db);
  const commits: number[][] = [];
  let writing = 0;
  db.batch = async (statements) => {
    const positions = statements
      .filter((s) => s.sql.includes(WRITES_POSITION))
      .map((s) => s.params?.[1] as number);
    if (positions.length > 0 && ++writing === options.failCommit)
      throw new Error("injected: the commit failed");
    const out = await batch(statements);
    if (positions.length > 0) {
      commits.push(positions);
      await after(positions);
    }
    return out;
  };
  return commits;
}

async function reference(w: World, hooks = {}) {
  const d = await w.device("reference", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    maxBytesInFlight: ONE_AT_A_TIME,
    ...hooks,
  });
  await connect(d);
  return d;
}

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
    // The last position a batch writes is where the log is after it.
    const write = statements.findLast((s) =>
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
  expect(omits.map((o) => o.pkHash)).toEqual([await idHash("A3")]);
  return a;
}

describe("progressive first load, log protocol on", () => {
  it("a stream over many segments is readable before the last segment applies, and complete after", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
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
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
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
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await publish(a, "run-1", ["A", "B"], { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["A"], { remove: true, observedAt: 1200 });
    await publish(a, "run-3", ["C"], { observedAt: 1300 });
    await publish(a, "run-4", ["A"], { observedAt: 1400 });
    await publish(a, "run-5", ["D"], { observedAt: 1500 });
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
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
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
    await connect(b);
    const held = gate(b).before(7);
    const { applying } = await stopAt(b, held);
    expect(await count(b, "stream_partial")).toBe(1);
    expect(await count(b, "partial_hidden")).toBeGreaterThan(0);
    held.release();
    await applying;

    expect(await count(b, "stream_partial")).toBe(0);
    expect(await count(b, "partial_hidden")).toBe(0);
    const plain = await w.device("plain");
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
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    const ids = Array.from(
      { length: 205 },
      (_, i) => `r${String(i).padStart(3, "0")}`,
    );
    await publish(a, "run-1", ids, { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["tail"], { observedAt: 1200 });
    await publish(a, "run-3", ["tail2"], { observedAt: 1300 });
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
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
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    const ids = Array.from(
      { length: 205 },
      (_, i) => `r${String(i).padStart(3, "0")}`,
    );
    await publish(a, "run-1", ids, { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["tail"], { observedAt: 1200 });
    await publish(a, "run-3", ["tail2"], { observedAt: 1300 });
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: ONE_AT_A_TIME,
    });
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
    const deleter = createConnectionDeleter(b.deps);
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
      const w = await world({ streams: 1 });
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
      const b = await w.device("b", {
        progressiveFirstLoad: true,
        keyedFirstLoad: false,
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
      const plain = await w.device("plain");
      await plain.cycle();
      expect(await idsOf(b)).toEqual(await idsOf(plain));
    });

    it("a snapshot part that is missing stops the load on its row; the next apply carries it on to the end", async () => {
      const { w, head, victim } = await compacted();
      const key = partKey(head, 2);
      const bytes = (await w.innerBlobs.get(key))!;
      w.innerBlobs.delete(key);
      const b = await w.device("b", {
        progressiveFirstLoad: true,
        keyedFirstLoad: false,
        maxBytesInFlight: ONE_AT_A_TIME,
      });
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
      const plain = await w.device("plain");
      await plain.cycle();
      expect(await idsOf(b)).toEqual(await idsOf(plain));
      expect(await count(b, "stream_partial")).toBe(0);
      expect(await count(b, "partial_hidden")).toBe(0);
    });

    it("with parts committed together, the snapshot's position is written only with its last part, and the tables end as a part-by-part load leaves them", async () => {
      const { w, head } = await compacted();
      const one = await reference(w);
      await applyConnection(one.deps, CONNECTION_ID);

      const b = await w.device("b", {
        progressiveFirstLoad: true,
        keyedFirstLoad: false,
      });
      await connect(b);
      const db = b.db as unknown as { batch: Device["db"]["batch"] };
      const batch = db.batch.bind(db);
      const writes: { position: number | null; rows: number }[] = [];
      let stated = false;
      db.batch = async (statements) => {
        const state = statements.find((s) => s.sql.includes(WRITES_POSITION));
        const out = await batch(statements);
        // Before the snapshot's last part there is no state to read.
        writes.push({
          position: state ? (state.params?.[1] as number) : null,
          rows: await count(b, "records"),
        });
        if (!state && !stated) expect(await count(b, "log_state")).toBe(0);
        if (state) stated = true;
        return out;
      };
      await applyConnection(b.deps, CONNECTION_ID);

      const firstState = writes.findIndex((x) => x.position !== null);
      expect(writes[firstState]!.position).toBe(head.snapshot!.position);
      // Earlier commits wrote rows without writing the state.
      const before = writes.slice(0, firstState).filter((x) => x.rows > 0);
      expect(before.length).toBeGreaterThan(0);
      expect(await dump(b)).toEqual(await dump(one));
    });

    it("a last part that is missing leaves the committed parts' rows without a snapshot position, and the next apply finishes, with parts committed together", async () => {
      const { w, head, victim } = await compacted();
      const last = head.snapshot!.parts.length - 1;
      const key = partKey(head, last);
      const bytes = (await w.innerBlobs.get(key))!;
      w.innerBlobs.delete(key);
      const b = await w.device("b", {
        progressiveFirstLoad: true,
        keyedFirstLoad: false,
      });
      await connect(b);
      await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow(
        "missing log snapshot part",
      );
      expect(await count(b, "log_state")).toBe(0);
      expect(await count(b, "records")).toBeGreaterThan(0);
      const marker = await b.db.query<{
        failed: number;
        parts_applied: number;
      }>("SELECT failed, parts_applied FROM stream_partial");
      expect(marker).toHaveLength(1);
      expect(marker[0]!.failed).toBe(1);
      expect(marker[0]!.parts_applied).toBe(last);

      await w.innerBlobs.put(key, bytes);
      await applyConnection(b.deps, CONNECTION_ID);
      const plain = await w.device("plain");
      await plain.cycle();
      expect(await idsOf(b)).toEqual(await idsOf(plain));
      expect(await idsOf(b)).not.toContain(victim);
      expect(await b.position()).toBe(await plain.position());
      expect(await count(b, "stream_partial")).toBe(0);
    });
  },
);

it("marks a failed removal prerequisite and wakes a waiting reader before retry", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await publish(a, "first", ["safe", "victim"], {
    full: true,
    observedAt: 1100,
  });
  await publish(a, "remove", ["victim"], { remove: true, observedAt: 1200 });
  await publish(a, "last", ["tail"], { observedAt: 1300 });
  const key = (await w.segmentKeys()).get(2)!;
  let arrived!: () => void;
  const reached = new Promise<void>((resolve) => {
    arrived = resolve;
  });
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const failure = new Error("removal prerequisite failed");
  let fail = true;
  const b = await w.device("b", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    beforeGet: async (requested) => {
      if (requested !== key || !fail) return;
      arrived();
      await held;
      fail = false;
      throw failure;
    },
  });
  await connect(b);
  const listed = nextApplied(b.deps, CONNECTION_ID);
  const applying = applyConnection(b.deps, CONNECTION_ID);
  const outcome = applying.then(
    () => null,
    (error: unknown) => error,
  );
  await Promise.race([
    reached,
    outcome.then((error) => {
      throw error;
    }),
  ]);
  await Promise.race([
    listed,
    outcome.then((error) => {
      throw error;
    }),
  ]);
  expect(await b.db.query("SELECT failed FROM stream_partial")).toEqual([
    { failed: 0 },
  ]);
  let woke = false;
  const waiter = nextApplied(b.deps, CONNECTION_ID).then(() => {
    woke = true;
  });
  release();
  expect(await outcome).toBe(failure);
  expect(await b.position()).toBe(0);
  expect(await b.rows()).toEqual([]);
  expect(await b.db.query("SELECT failed FROM stream_partial")).toEqual([
    { failed: 1 },
  ]);
  expect(woke).toBe(true);
  await waiter;
  await applyConnection(b.deps, CONNECTION_ID);
  expect(await idsOf(b)).toEqual(["safe", "tail"]);
  expect(await b.position()).toBe(3);
  expect(await count(b, "stream_partial")).toBe(0);
  await applyConnection(b.deps, CONNECTION_ID);
  expect(await idsOf(b)).toEqual(["safe", "tail"]);
});

describe("progressive first load, log protocol on, flag off", () => {
  it("is as before: nothing is readable until the whole log is applied, and no load row is written", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const b = await w.device("b");
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

// Commits that carry several batches (the default budget: a batch is
// committed together with the ones fetched while it was written). The load's
// rules do not depend on how many commit together. The tests below hold each
// rule to the answer of a load that commits one batch at a time.
describe("progressive first load, batches committed together", () => {
  it("ends in every table a one-batch-at-a-time load ends in, and commits fewer times", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const one = await reference(w);
    await applyConnection(one.deps, CONNECTION_ID);

    const grouped = await w.device("grouped", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(grouped);
    const commits = afterCommits(grouped, async () => undefined);
    await applyConnection(grouped.deps, CONNECTION_ID);

    expect(commits.flat()).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(commits.length).toBeLessThan(7);
    expect(await dump(grouped)).toEqual(await dump(one));
  });

  it("a key a later batch deletes or omits is in no view, at any commit, though the batches commit together", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(b);
    const reads = reader(b);
    const views: string[][] = [];
    const commits = afterCommits(b, async (positions) => {
      // The last commit ends the load; a read then waits for the apply's end.
      if (positions.at(-1) === 7) return;
      const view = await reads.readNow();
      expect(view).not.toBe(BLOCKED);
      if (view !== BLOCKED && view.kind === "view") views.push(view.ids);
    });
    await applyConnection(b.deps, CONNECTION_ID);
    expect(commits.length).toBeLessThan(7);
    for (const ids of views) {
      // A2 is deleted at position 4 and A3 omitted at 6: never shown.
      expect(ids).not.toContain("A2");
      expect(ids).not.toContain("A3");
    }
    expect(views.length).toBe(commits.length - 1);
    expect((await reads.read()).ids).toEqual(["A1", "B", "C", "D", "E"]);
  });

  it("a key deleted and then written again is shown once written, with batches committed together", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await publish(a, "run-1", ["A", "B"], { full: true, observedAt: 1100 });
    await publish(a, "run-2", ["A"], { remove: true, observedAt: 1200 });
    await publish(a, "run-3", ["C"], { observedAt: 1300 });
    await publish(a, "run-4", ["A"], { observedAt: 1400 });
    await publish(a, "run-5", ["D"], { observedAt: 1500 });
    const one = await reference(w);
    await applyConnection(one.deps, CONNECTION_ID);
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(b);
    const reads = reader(b);
    const views: string[][] = [];
    afterCommits(b, async () => {
      const view = await reads.readNow();
      if (view !== BLOCKED && view.kind === "view") views.push(view.ids);
    });
    await applyConnection(b.deps, CONNECTION_ID);
    for (const ids of views)
      if (!ids.includes("C")) expect(ids).not.toContain("A");
    expect((await reads.read()).ids).toEqual(["A", "B", "C", "D"]);
    expect(await dump(b)).toEqual(await dump(one));
  });

  /** Three streams: x over positions 1, 3; y over 2, 4, 5; z in position 2 only. */
  async function threeStreams() {
    const w = await world({ streams: 3 });
    const [x, y, z] = w.names as [string, string, string];
    const a = await w.device("a");
    let observedAt = 1100;
    const run = async (
      id: string,
      records: { stream: string; id: string }[],
    ) => {
      // Each run selects only the streams it writes, so each succeeds.
      await a.run(id, records, {
        full: false,
        selected: [...new Set(records.map((r) => r.stream))],
        observedAt: (observedAt += 100),
      });
      await a.cycle();
    };
    await run("run-1", [{ stream: x, id: "x1" }]);
    await run("run-2", [
      { stream: y, id: "y1" },
      { stream: z, id: "z1" },
    ]);
    await run("run-3", [{ stream: x, id: "x2" }]);
    await run("run-4", [{ stream: y, id: "y2" }]);
    await run("run-5", [{ stream: y, id: "y3" }]);
    expect([...(await w.segments()).keys()]).toEqual([1, 2, 3, 4, 5]);
    return { w, x, y, z };
  }

  it("every stream of the connection finishes in the pass's last commit, and is listed as partial from the first", async () => {
    const { w, x, y, z } = await threeStreams();
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(b);
    const states: { last: number; partial: string[]; complete: string[] }[] =
      [];
    const commits = afterCommits(b, async (positions) => {
      states.push({
        last: positions.at(-1)!,
        partial: (
          await b.db.query<{ stream: string }>(
            "SELECT stream FROM stream_partial ORDER BY stream",
          )
        ).map((r) => r.stream),
        complete: (
          await b.db.query<{ stream: string }>(
            "SELECT stream FROM stream_state WHERE complete = 1",
          )
        ).map((r) => r.stream),
      });
    });
    await applyConnection(b.deps, CONNECTION_ID);
    expect(commits.flat()).toEqual([1, 2, 3, 4, 5]);
    // Which segment holds a stream's last batch is not known before the
    // segments are read, so no stream is complete before the pass's last commit
    // and every stream the head names is partial until then.
    const before = states.slice(0, -1);
    expect(before.length).toBeGreaterThan(0);
    // The head names y and the first batch names x: both are listed from the
    // first commit. z is listed with the batch that first names it.
    expect(before[0]!.partial).toEqual([x, y].sort());
    for (const s of before) expect(s.complete).toEqual([]);
    expect(states.at(-1)!.partial).toEqual([]);
    expect(states.at(-1)!.complete.sort()).toEqual([x, y, z].sort());
  });

  it("a batch that is missing in the tail stops the load at the batch before it, marks the streams unfinished, and a retry ends right", async () => {
    const { w, x, y, z } = await threeStreams();
    const keys = await w.segmentKeys();
    const missing = keys.get(4)!;
    const bytes = (await w.innerBlobs.get(missing))!;
    await w.innerBlobs.delete(missing);

    const grouped = await w.device("grouped", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(grouped);
    await expect(
      applyConnection(grouped.deps, CONNECTION_ID),
    ).rejects.toThrow();
    // Segments are read as the apply reaches them: the prefix before the
    // missing one is kept, the missing one and the ones after it are not.
    expect(await grouped.position()).toBeLessThan(4);
    const complete = await grouped.db.query<{ stream: string }>(
      "SELECT stream FROM stream_state WHERE complete = 1",
    );
    expect(complete).toEqual([]);
    const marked = await grouped.db.query<{ stream: string; failed: number }>(
      "SELECT stream, failed FROM stream_partial ORDER BY stream",
    );
    expect(marked).toEqual(
      [x, y, z].sort().map((stream) => ({ stream, failed: 1 })),
    );

    await w.innerBlobs.put(missing, bytes);
    await applyConnection(grouped.deps, CONNECTION_ID);
    expect(await grouped.position()).toBe(5);
    expect(await count(grouped, "stream_partial")).toBe(0);
    const whole = await reference(w);
    await applyConnection(whole.deps, CONNECTION_ID);
    expect(await dump(grouped)).toEqual(await dump(whole));
  });

  it("a commit that fails keeps the commits before it, marks every stream unfinished, and a retry ends where an uninterrupted load ends", async () => {
    const { w, x, y } = await threeStreams();
    const grouped = await w.device("grouped", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(grouped);
    const commits = afterCommits(grouped, async () => undefined, {
      failCommit: 2,
    });
    await expect(applyConnection(grouped.deps, CONNECTION_ID)).rejects.toThrow(
      "injected",
    );
    expect(commits).toEqual([[1]]);
    expect(await grouped.position()).toBe(1);
    const complete = await grouped.db.query<{ stream: string }>(
      "SELECT stream FROM stream_state WHERE complete = 1",
    );
    expect(complete).toEqual([]);
    const rows = await grouped.db.query<{ stream: string; failed: number }>(
      "SELECT stream, failed FROM stream_partial ORDER BY stream",
    );
    expect(rows).toEqual(
      [x, y].sort().map((stream) => ({ stream, failed: 1 })),
    );

    await applyConnection(grouped.deps, CONNECTION_ID);
    const whole = await reference(w);
    await applyConnection(whole.deps, CONNECTION_ID);
    expect(await dump(grouped)).toEqual(await dump(whole));
    expect(await count(grouped, "stream_partial")).toBe(0);
  });

  it("a commit that fails writes none of its batches, keeps the commits before it, and a retry ends right", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const one = await reference(w);
    const oneCommits = afterCommits(one, async () => undefined);
    await applyConnection(one.deps, CONNECTION_ID);
    expect(oneCommits.length).toBe(7);

    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
    });
    await connect(b);
    // The first commit is one batch; the second carries the ones fetched with it.
    const commits = afterCommits(b, async () => undefined, { failCommit: 2 });
    await expect(applyConnection(b.deps, CONNECTION_ID)).rejects.toThrow(
      "injected",
    );
    expect(commits).toEqual([[1]]);
    expect(await b.position()).toBe(1);
    const stored = await b.db.query<{ n: number }>(
      "SELECT count(*) AS n FROM records",
    );
    // Only the rows of position 1: A1, A2, A3.
    expect(stored[0]!.n).toBe(3);
    const marker = await b.db.query<{ parts_applied: number; failed: number }>(
      "SELECT parts_applied, failed FROM stream_partial",
    );
    expect(marker).toEqual([{ parts_applied: 1, failed: 1 }]);

    await applyConnection(b.deps, CONNECTION_ID);
    const fresh = await reference(w);
    await applyConnection(fresh.deps, CONNECTION_ID);
    expect(await dump(b)).toEqual(await dump(fresh));
  });
});
