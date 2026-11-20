// The first load of a large source on a second device (floor row 3b). Three
// moments are held here, each by stopping the apply where it fetches a blob
// (`beforeGet`) and reading the device then:
//
//   listed      the owner's listing names the source, loading, as soon as the
//               head is read and before one segment is fetched;
//   first rows  the rows of the segments applied so far are readable while a
//               later segment is still downloading;
//   exact       no row the finished log has deleted is ever readable, because
//               the segments that remove a key are read before the first apply
//               (the head's refs say which: `SegmentRef.removes`).
//
// A fourth test compares the durable staged replay with the same rows a
// key-ordered load ends with. The Node bench
// (`bench/first-load-bench.workload.ts`) counts page writes for the same claim
// on 198k rows.
import { afterEach, describe, expect, it, vi } from "vitest";
import type * as StreamSync from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "../../../core/src/localdb/index.js";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

// What the writer says about a segment's removals, for the tests that publish
// a log an older or a faulty writer would. Reads always see the truth.
const writer = vi.hoisted(() => ({
  says: "truth" as "truth" | "lie" | "none",
}));
vi.mock("@opendatalabs/personal-server-ts-stream-sync", async (original) => {
  const real = await original<typeof StreamSync>();
  return {
    ...real,
    segmentRemoves: (operations: Parameters<typeof real.segmentRemoves>[0]) =>
      writer.says === "truth"
        ? real.segmentRemoves(operations)
        : writer.says === "lie"
          ? false
          : undefined,
  };
});

afterEach(async () => {
  writer.says = "truth";
  await closeWorldDrivers();
});

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const STREAM = sName(0);
const SCOPE = `pdpp.${CONNECTOR}.${STREAM}`;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function connect(d: Device) {
  await d.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
}

/**
 * Seven segments of one stream. Position 4 deletes A2; position 6 is a full
 * pass that does not list A3, so it omits A3. The finished stream is A1, B, C,
 * D and E. Positions 1, 2, 3, 5 and 7 remove nothing.
 */
async function sevenSegments(w: World) {
  const a = await w.device("a");
  const publish = async (
    runId: string,
    ids: readonly string[],
    options: { remove?: boolean; full?: boolean; observedAt: number },
  ) => {
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
  };
  await publish("run-1", ["A1", "A2", "A3"], { full: true, observedAt: 1100 });
  await publish("run-2", ["B"], { observedAt: 1200 });
  await publish("run-3", ["C"], { observedAt: 1300 });
  await publish("run-4", ["A2"], { remove: true, observedAt: 1400 });
  await publish("run-5", ["D"], { observedAt: 1500 });
  await publish("run-6", ["A1", "B", "C", "D"], {
    full: true,
    observedAt: 1600,
  });
  await publish("run-7", ["E"], { observedAt: 1700 });
  expect([...(await w.segments()).keys()].sort()).toEqual([
    1, 2, 3, 4, 5, 6, 7,
  ]);
}

/** A device that stops its own fetch of the blobs `held` names, until released. */
async function heldDevice(
  w: World,
  held: ReadonlySet<string>,
  afterScan = false,
) {
  const arrived = new Map<string, () => void>();
  const arrivals = new Map<string, Promise<void>>();
  let release!: () => void;
  const open = new Promise<void>((resolve) => (release = resolve));
  for (const key of held)
    arrivals.set(
      key,
      new Promise<void>((resolve) => arrived.set(key, resolve)),
    );
  const counts = new Map<string, number>();
  const d = await w.device("b", {
    progressiveFirstLoad: true,
    beforeGet: async (key) => {
      if (!held.has(key)) return;
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);
      if (afterScan && count === 1) return;
      arrived.get(key)!();
      await open;
    },
  });
  await connect(d);
  return { d, release, reached: (key: string) => arrivals.get(key)! };
}

function reads(d: Device) {
  const resolver = createLocalResolver(d.deps, {
    query: createRecordQuery(d.db),
  });
  return async () => {
    const decision = await resolver.resolve({
      scope: SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    if (decision.kind !== "view")
      return { kind: decision.kind, ids: [] as string[], partial: undefined };
    const body = JSON.parse(await new Response(decision.body).text()) as {
      data: { records: { id: string }[] };
    };
    return {
      kind: "view" as const,
      ids: body.data.records.map((r) => r.id).sort(),
      partial: decision.partial,
    };
  };
}

const listOwner = (d: Device) =>
  createLocalListing(d.deps).listScopes({
    canRead: () => true,
    includeLoading: true,
  });

describe("first load of a large source on a second device", () => {
  it("lists the source, loading, before one segment is fetched", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const keys = await w.segmentKeys();
    const { d, release, reached } = await heldDevice(
      w,
      new Set([keys.get(1)!]),
    );
    const applying = applyConnection(d.deps, CONNECTION_ID);
    await Promise.race([reached(keys.get(1)!), applying]);

    // Segment 1 is still downloading: nothing is applied, and the source is listed.
    expect(await d.db.query("SELECT 1 FROM records")).toEqual([]);
    const listed = await listOwner(d);
    expect(listed.map((s) => [s.scope, s.dataStatus])).toEqual([
      [SCOPE, "indexing"],
    ]);
    expect(listed[0]!.records).toBe(0);
    // A grantee's listing never names a load in progress.
    expect(
      await createLocalListing(d.deps).listScopes({ canRead: () => true }),
    ).toEqual([]);
    // A read of the listed scope answers, with no rows, and says it is partial.
    expect(await reads(d)()).toMatchObject({
      kind: "view",
      ids: [],
      partial: { partsApplied: 0, partsTotal: 7 },
    });

    release();
    await applying;
    const done = await listOwner(d);
    expect(done.map((s) => [s.scope, s.dataStatus])).toEqual([
      [SCOPE, undefined],
    ]);
    expect(await reads(d)()).toMatchObject({
      ids: ["A1", "B", "C", "D", "E"],
      partial: undefined,
    });
  });

  it("shows the rows of the segments applied while a later segment is still downloading, and never a row the log deletes", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const keys = await w.segmentKeys();
    // Hold the application reread after the bounded prerequisite scan.
    const { d, release, reached } = await heldDevice(
      w,
      new Set([keys.get(5)!]),
      true,
    );
    const applying = applyConnection(d.deps, CONNECTION_ID);
    await Promise.race([reached(keys.get(5)!), applying]);
    // Wait for the committed prefix before inspecting the view.
    for (let i = 0; i < 20 && (await d.position()) < 4; i++) await sleep(25);

    const view = await reads(d)();
    // A2 is deleted at 4 and A3 omitted at 6: shown at no point, though
    // segment 1 carries both.
    expect(view.ids).toEqual(["A1", "B", "C"]);
    expect(view.partial).toMatchObject({ partsTotal: 7 });
    expect(await d.position()).toBe(4);
    expect((await listOwner(d)).map((s) => s.dataStatus)).toEqual(["indexing"]);

    release();
    await applying;
    expect((await reads(d)()).ids).toEqual(["A1", "B", "C", "D", "E"]);
  });

  it("reads the segments the refs do not say remove nothing before the first apply, so a ref without the fact shows nothing early", async () => {
    // A log written before the fact existed: every ref counts as removing.
    writer.says = "none";
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    writer.says = "truth";
    const keys = await w.segmentKeys();
    const { d, release, reached } = await heldDevice(
      w,
      new Set([keys.get(5)!]),
    );
    const applying = applyConnection(d.deps, CONNECTION_ID);
    await Promise.race([reached(keys.get(5)!), applying]);
    await sleep(100);
    // Exact, not early: nothing is applied until every segment is in hand.
    expect(await d.db.query("SELECT 1 FROM records")).toEqual([]);
    expect(await reads(d)()).toMatchObject({ ids: [] });
    release();
    await applying;
    expect((await reads(d)()).ids).toEqual(["A1", "B", "C", "D", "E"]);
  });

  it("refuses a segment that removes a key its ref says it does not, and finishes nothing", async () => {
    writer.says = "lie";
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    writer.says = "truth";
    const d = await w.device("b", { progressiveFirstLoad: true });
    await connect(d);
    await expect(applyConnection(d.deps, CONNECTION_ID)).rejects.toThrow(
      /removes a key its ref says it does not/,
    );
    const done = await d.db.query<{ n: number }>(
      "SELECT count(*) AS n FROM stream_state WHERE complete = 1",
    );
    expect(done[0]!.n).toBe(0);
    expect(await d.db.query("SELECT failed FROM stream_partial")).toEqual([
      { failed: 1 },
    ]);
  });

  it("names, in the head, which segments remove a key", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const head = (await w.segments()).get(7)!;
    expect(head.refs.map((r) => [r.position, r.removes])).toEqual([
      [1, false],
      [2, false],
      [3, false],
      [4, true],
      [5, false],
      [6, true],
    ]);
  });

  it("stages records durably and ends with the rows a key-ordered load ends with", async () => {
    const w = await world({ streams: 1 });
    await sevenSegments(w);
    const statementsOf = async (hooks: { keyedFirstLoad: boolean }) => {
      const d = await w.device(`d${Math.random()}`, {
        progressiveFirstLoad: true,
        ...hooks,
      });
      await connect(d);
      const seen: string[] = [];
      const db = d.db as unknown as { batch: Device["db"]["batch"] };
      const batch = db.batch.bind(db);
      db.batch = async (statements) => {
        for (const s of statements) seen.push(s.sql);
        return batch(statements);
      };
      await applyConnection(d.deps, CONNECTION_ID);
      return { d, seen };
    };
    // A log that fits one commit's budget loads segment by segment. The
    // control forces the key-ordered load on the same log.
    const keyed = await statementsOf({ keyedFirstLoad: true });
    const streaming = await statementsOf({ keyedFirstLoad: false });
    const staged = (seen: string[]) =>
      seen.filter((sql) => sql.includes("log_stage_")).length;
    expect(staged(streaming.seen)).toBe(0);
    expect(await streaming.d.records()).toEqual(await keyed.d.records());
  });
});
