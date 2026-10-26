import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { createPdppSyncSessionService } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalConnectionSelection,
  type CanonicalLegacyReadStore,
} from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import type { RecordDataValidator } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

/**
 * Read-time compatibility for the two Strava scopes Desktop exported, read
 * through the real SQLite record store. The rows are synthetic: they are
 * shaped from the schemas and emit calls of the digest-pinned Strava 1.0.8
 * producer (sha256:b330…7c82c). Nothing here says a real account holds them.
 */

const SOURCE = "https://registry.pdpp.dev/sources/strava";
const METHOD = "strava_export";
const COLLECTED = "2026-09-10T08:30:00+02:00";
const COLLECTED_ISO = "2026-09-10T06:30:00.000Z";
const EXPORTED_AT = "2026-08-30T12:00:00.000Z";
/** The pinned producer stamps every record of one run with one time. */
const RUN_1 = "2026-09-01T00:00:00.000Z";
const RUN_2 = "2026-09-02T00:00:00.000Z";

const activity = (id: string, extra: Record<string, unknown> = {}) => ({
  id,
  activity_type: "Run",
  start_date: "2026-08-01",
  start_time: "2026-08-01T07:15:00",
  start_time_basis: "unknown",
  distance_m: 5012.5,
  moving_time_s: 1500,
  elapsed_time_s: 1620,
  total_elevation_gain_m: null,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "snapshot",
  exported_at: EXPORTED_AT,
  ...extra,
});

const diagnostic = (extra: Record<string, unknown> = {}) => ({
  id: `activities:${EXPORTED_AT}`,
  stream: "activities",
  status: "partial",
  reason: "records_unreadable",
  record_count: 3,
  fields_unavailable: ["calories_kcal", "gear"],
  window_requested_from: null,
  window_requested_to: null,
  window_covered_from: "2026-08-01T07:15:00",
  window_covered_to: "2026-08-09T18:00:00",
  freshness: "snapshot",
  exported_at: EXPORTED_AT,
  ...extra,
});

/** What the pinned Desktop `project_export_scopes` returns for one scope. */
const desktopScope = (stream: string, snapshot: Record<string, unknown>[]) => ({
  [stream]: snapshot,
});

type Store = ReturnType<typeof createSqliteRecordStore>;
type Scope = "strava.activities" | "strava.coverage_diagnostics";

function connectTo(target: Store, instance: string) {
  target.registerConnection({
    instance,
    sourceId: SOURCE,
    method: METHOD,
    label: instance,
  });
  return { instance, sourceId: SOURCE, method: METHOD };
}

/** One RECORD ingest call, in the order Desktop sent the records. */
function ingestTo(
  target: Store,
  instance: string,
  rows: (Record<string, unknown> | { delete: string })[],
  options: {
    emittedAt?: string;
    generation?: number;
    validateData?: RecordDataValidator;
  } = {},
) {
  const emittedAt = options.emittedAt ?? RUN_1;
  return target.ingestBatch(
    rows.map((row) =>
      "delete" in row
        ? {
            instance,
            stream: "activities",
            key: row.delete as string,
            data: null,
            emitted_at: emittedAt,
            op: "delete" as const,
          }
        : {
            instance,
            stream: "activities",
            key: String(row.id),
            data: row,
            emitted_at: emittedAt,
          },
    ),
    () => "mutable_state",
    () => ["id"],
    { method: METHOD, generation: options.generation ?? 1 },
    options.validateData,
  );
}

const ids = (result: Awaited<ReturnType<typeof readCanonicalLegacyScope>>) => {
  if (!result.ok) throw new Error(`read failed: ${JSON.stringify(result)}`);
  const [rows] = Object.values(result.envelope.data) as { id: string }[][];
  return rows!.map((row) => row.id);
};

describe("strava legacy scopes over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: Store;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
  });
  afterEach(() => store.close());

  const connect = (instance: string) => connectTo(store, instance);
  const ingest = (
    instance: string,
    rows: Parameters<typeof ingestTo>[2],
    options?: Parameters<typeof ingestTo>[3],
  ) => ingestTo(store, instance, rows, options);

  /** A full replace that names a producer time, so it leaves a receipt. */
  function replace(
    instance: string,
    stream: string,
    rows: Record<string, unknown>[],
    sourceCollectedAt: string | null = COLLECTED,
  ) {
    const result = store.replaceStream({
      instance,
      stream,
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-10T07:00:00.000Z",
      primaryKey: ["id"],
      envelopes: rows.map((data) => ({
        instance,
        stream,
        key: String(data.id),
        data,
        emitted_at: "2026-09-10T07:00:00.000Z",
      })),
      ...(sourceCollectedAt === null ? {} : { sourceCollectedAt }),
    });
    expect(result.applied).toBe(true);
    return result;
  }

  const read = (scope: Scope, selection: CanonicalConnectionSelection) =>
    readCanonicalLegacyScope({ store, scope, selection, pageSize: 2 });

  it("serves both scopes the old export served, with every native field kept", async () => {
    const a = connect("conn_a");
    const rows = [
      activity("11", {
        average_heartrate: 141,
        gear: "Road bike",
        // Not in the pinned schema. The store and the signed ingest decide
        // what is admitted; the view must not drop what they kept.
        future_field: { nested: [1, null] },
      }),
      activity("12", {
        exported_at: null,
        freshness: null,
        start_time: "2026-08-01T07:15:00+02:00",
        start_time_basis: "utc",
      }),
    ];
    replace("conn_a", "activities", rows);
    replace("conn_a", "coverage_diagnostics", [diagnostic()]);

    const activities = await read("strava.activities", a);
    const diagnostics = await read("strava.coverage_diagnostics", a);

    expect(activities).toEqual({
      ok: true,
      envelope: {
        version: "1.0",
        scope: "strava.activities",
        collectedAt: COLLECTED_ISO,
        data: desktopScope("activities", rows),
      },
      revision: expect.stringMatching(/^v1:[0-9a-f]{64}$/),
      complete: true,
      diagnostics: {
        sourceRowCounts: { activities: 2 },
        omissions: [],
        partialRows: [],
      },
    });
    expect(diagnostics).toEqual({
      ok: true,
      envelope: {
        version: "1.0",
        scope: "strava.coverage_diagnostics",
        collectedAt: COLLECTED_ISO,
        data: desktopScope("coverage_diagnostics", [diagnostic()]),
      },
      revision: expect.stringMatching(/^v1:[0-9a-f]{64}$/),
      complete: true,
      diagnostics: {
        sourceRowCounts: { coverage_diagnostics: 1 },
        omissions: [],
        partialRows: [],
      },
    });
  });

  describe("source coverage is data, not a projection loss", () => {
    it("calls one activity with its own receipt complete, whatever the diagnostics say", async () => {
      const a = connect("conn_a");
      replace("conn_a", "activities", [activity("7")]);
      replace("conn_a", "coverage_diagnostics", [
        diagnostic({
          status: "complete",
          reason: "covered_in_full",
          record_count: 1,
          fields_unavailable: [],
        }),
      ]);

      const result = await read("strava.activities", a);
      expect(result).toMatchObject({ ok: true, complete: true });
      expect(ids(result)).toEqual(["7"]);
    });

    it("serves a partial coverage diagnostic as written and leaves activities fidelity to the activities rows", async () => {
      const a = connect("conn_a");
      replace("conn_a", "activities", [activity("11"), activity("12")]);
      const partial = diagnostic({
        status: "partial",
        reason: "collection_interrupted",
        window_requested_from: "2026-08-01",
        window_requested_to: null,
      });
      replace("conn_a", "coverage_diagnostics", [partial]);
      const streamsRead: string[] = [];
      const spy: CanonicalLegacyReadStore = {
        ...store,
        listRecords(stream, options) {
          streamsRead.push(stream);
          return store.listRecords(stream, options);
        },
      };

      const activities = await readCanonicalLegacyScope({
        store: spy,
        scope: "strava.activities",
        selection: a,
      });
      const diagnostics = await read("strava.coverage_diagnostics", a);

      expect(diagnostics.ok && diagnostics.envelope.data).toEqual({
        coverage_diagnostics: [partial],
      });
      // The activities rows are reproduced in full. Whether the source read
      // its whole archive is the diagnostics scope's data, which this read
      // neither reads nor interprets.
      expect(activities).toMatchObject({ ok: true, complete: true });
      expect(new Set(streamsRead)).toEqual(new Set(["activities"]));
    });

    it("keeps nonempty, known-empty and unknown streams distinct", async () => {
      const a = connect("conn_a");
      replace("conn_a", "activities", [activity("11")]);

      // The producer returns without a diagnostic record when the import dir
      // exists and only diagnostics were requested. No row is not "empty".
      expect(await read("strava.coverage_diagnostics", a)).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["coverage_diagnostics"],
      });

      replace("conn_a", "coverage_diagnostics", []);
      const empty = await read("strava.coverage_diagnostics", a);
      expect(empty).toMatchObject({ ok: true, complete: true });
      expect(empty.ok && empty.envelope.data).toEqual({
        coverage_diagnostics: [],
      });

      // An empty replace without a source time leaves no receipt.
      const b = connect("conn_b");
      replace("conn_b", "coverage_diagnostics", [diagnostic()]);
      replace("conn_b", "activities", [], null);
      expect(await read("strava.activities", b)).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["activities"],
      });
      replace("conn_b", "activities", []);
      const knownEmpty = await read("strava.activities", b);
      expect(knownEmpty).toMatchObject({ ok: true, complete: true });
      expect(knownEmpty.ok && knownEmpty.envelope.data).toEqual({
        activities: [],
      });
    });
  });

  it("leaves the result shape of an unrelated scope unchanged", async () => {
    store.registerConnection({
      instance: "conn_oura",
      sourceId: "https://registry.pdpp.dev/sources/oura",
      method: METHOD,
      label: "oura",
    });
    store.ingestBatch(
      [
        {
          instance: "conn_oura",
          stream: "activity",
          key: "o1",
          data: {
            id: "o1",
            day: "2026-08-01",
            score: 80,
            steps: 1000,
            contributors: {},
          },
          emitted_at: RUN_1,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: METHOD, generation: 1 },
    );

    const result = await readCanonicalLegacyScope({
      store,
      scope: "oura.activity",
      selection: {
        instance: "conn_oura",
        sourceId: "https://registry.pdpp.dev/sources/oura",
        method: METHOD,
      },
    });

    expect(result.ok && Object.keys(result)).toEqual([
      "ok",
      "envelope",
      "revision",
      "complete",
      "diagnostics",
    ]);
    expect(result.ok && result.diagnostics).toEqual({
      sourceRowCounts: { activity: 1 },
      omissions: [],
      partialRows: [],
    });
  });

  it("keeps two accounts of the same source apart", async () => {
    const a = connect("conn_a");
    const b = connect("conn_b");
    replace("conn_a", "activities", [activity("11")]);
    replace("conn_b", "activities", [activity("21"), activity("22")]);

    expect(ids(await read("strava.activities", a))).toEqual(["11"]);
    expect(ids(await read("strava.activities", b))).toEqual(["21", "22"]);
  });

  describe("record order", () => {
    // Desktop kept each stream's snapshot in arrival order: a full refresh
    // appends in emit order, and a re-emitted key, changed or not, moves to
    // the end. Numeric ids of different lengths make arrival order differ
    // from key order.
    const arrival = ["100", "9", "2000000000", "21", "3"];
    const afterRedelivered100 = ["9", "2000000000", "21", "3", "100"];

    /** Every native table a no-op must leave alone. */
    const nativeState = () =>
      JSON.stringify({
        records: db.prepare("SELECT * FROM pdpp_records ORDER BY rowid").all(),
        changes: db
          .prepare("SELECT * FROM pdpp_record_changes ORDER BY id")
          .all(),
        clock: db.prepare("SELECT * FROM pdpp_write_clock").all(),
        receipts: db
          .prepare("SELECT * FROM pdpp_stream_completion ORDER BY rowid")
          .all(),
        bindings: db.prepare("SELECT * FROM pdpp_instance_binding").all(),
      });

    it("serves activities in the order the source delivered them", async () => {
      const a = connect("conn_a");
      expect(
        ingest(
          "conn_a",
          arrival.map((id) => activity(id)),
        ).accepted,
      ).toBe(5);

      const result = await read("strava.activities", a);

      expect(ids(result)).toEqual(arrival);
      expect(result).toMatchObject({ ok: true, complete: true });
      expect(result.ok && "unproven" in result.diagnostics).toBe(false);
    });

    it("moves a re-delivered unchanged key to the end and leaves the native view alone", async () => {
      const a = connect("conn_a");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      const before = await read("strava.activities", a);
      // Opening a feed itself ticks the shared write clock, so it comes first.
      const feed = createPdppSyncSessionService(store).read({
        stream: "activities",
        instanceIds: ["conn_a"],
        limit: 10,
      }).nextChangesSince!;
      const nativeBefore = nativeState();
      const pageBefore = store.listRecords("activities", {
        instanceIds: ["conn_a"],
        limit: 10,
        order: "asc",
      });

      const replay = ingest("conn_a", [activity("100")], {
        emittedAt: RUN_2,
      });

      expect(replay).toMatchObject({ accepted: 0, unchanged: 1 });
      expect(nativeState()).toBe(nativeBefore);
      expect(
        store.listRecords("activities", {
          instanceIds: ["conn_a"],
          limit: 10,
          order: "asc",
        }),
      ).toEqual(pageBefore);
      expect(
        createPdppSyncSessionService(store).read({
          stream: "activities",
          instanceIds: ["conn_a"],
          limit: 10,
          changesSince: feed,
        }).data,
      ).toEqual([]);
      const after = await read("strava.activities", a);
      expect(ids(after)).toEqual(afterRedelivered100);
      expect(after).toMatchObject({ ok: true, complete: true });
      expect(after.ok && after.envelope.collectedAt).toBe(
        before.ok && before.envelope.collectedAt,
      );
      expect(after.ok && after.revision).not.toBe(before.ok && before.revision);

      // Re-delivering the key that is already last changes nothing.
      ingest("conn_a", [activity("100")], { emittedAt: RUN_2 });
      const again = await read("strava.activities", a);
      expect(JSON.stringify(again)).toBe(JSON.stringify(after));
    });

    it("orders a key repeated in one call by its last arrival", async () => {
      const a = connect("conn_a");
      ingest("conn_a", [
        activity("1"),
        activity("2"),
        activity("1"),
        activity("3"),
        activity("2", { gear: "Road bike" }),
      ]);

      const result = await read("strava.activities", a);
      expect(ids(result)).toEqual(["1", "3", "2"]);
      expect(result).toMatchObject({ ok: true, complete: true });
    });

    it("reproduces a full replace's snapshot order, unchanged keys included", async () => {
      const a = connect("conn_a");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );

      // 100 and 21 are unchanged, 3 is changed, 9 and 2000000000 are gone.
      const replaced = replace("conn_a", "activities", [
        activity("3", { gear: "Shoes" }),
        activity("100"),
        activity("21"),
      ]);
      expect(replaced).toMatchObject({ accepted: 1, unchanged: 2, deleted: 2 });
      expect(ids(await read("strava.activities", a))).toEqual([
        "3",
        "100",
        "21",
      ]);

      // A later delivery of a removed key arrives last.
      ingest("conn_a", [activity("9")], { emittedAt: RUN_2 });
      const result = await read("strava.activities", a);
      expect(ids(result)).toEqual(["3", "100", "21", "9"]);
      expect(result).toMatchObject({ ok: true, complete: true });
    });

    it("does not move the order for a rejected or rolled-back write", async () => {
      const a = connect("conn_a");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      const before = await read("strava.activities", a);

      // A rejected envelope (key does not match its data) is not an arrival.
      const rejected = store.ingestBatch(
        [
          {
            instance: "conn_a",
            stream: "activities",
            key: "100",
            data: activity("999"),
            emitted_at: RUN_2,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );
      expect(rejected.rejected).toHaveLength(1);

      // A fault after an unchanged re-delivery rolls the re-delivery back too.
      const fault: RecordDataValidator = (_stream, _instance, data) => {
        if (data.id === "boom") throw new Error("validator fault");
        return null;
      };
      expect(() =>
        ingest("conn_a", [activity("100"), activity("boom")], {
          emittedAt: RUN_2,
          validateData: fault,
        }),
      ).toThrow("validator fault");

      // A replace with one rejected record writes nothing.
      const refused = store.replaceStream({
        instance: "conn_a",
        stream: "activities",
        method: METHOD,
        generation: 1,
        emittedAt: RUN_2,
        primaryKey: ["id"],
        envelopes: [
          {
            instance: "conn_a",
            stream: "activities",
            key: "100",
            data: activity("100"),
            emitted_at: RUN_2,
          },
          {
            instance: "conn_a",
            stream: "activities",
            key: "9",
            data: activity("not-9"),
            emitted_at: RUN_2,
          },
        ],
      });
      expect(refused.applied).toBe(false);

      const after = await read("strava.activities", a);
      expect(ids(after)).toEqual(arrival);
      expect(after.ok && after.revision).toBe(before.ok && before.revision);
    });

    it("drops a deleted key from the order and appends it when it returns", async () => {
      const a = connect("conn_a");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );

      ingest("conn_a", [{ delete: "100" }], { emittedAt: RUN_2 });
      store.deleteRecord("conn_a", "activities", "21", RUN_2, "mutable_state");
      expect(ids(await read("strava.activities", a))).toEqual([
        "9",
        "2000000000",
        "3",
      ]);

      ingest("conn_a", [activity("21"), activity("100")], {
        emittedAt: RUN_2,
      });
      expect(ids(await read("strava.activities", a))).toEqual([
        "9",
        "2000000000",
        "3",
        "21",
        "100",
      ]);
    });

    it("starts a fresh order after a reset", async () => {
      const a = connect("conn_a");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      store.resetInstanceBinding({
        instance: "conn_a",
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: METHOD,
      });

      ingest("conn_a", [activity("3"), activity("100"), activity("9")], {
        generation: 2,
      });

      const result = await read("strava.activities", a);
      expect(ids(result)).toEqual(["3", "100", "9"]);
      expect(result).toMatchObject({ ok: true, complete: true });
    });

    it("keeps each account's order apart", async () => {
      const a = connect("conn_a");
      const b = connect("conn_b");
      ingest(
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      ingest(
        "conn_b",
        [...arrival].reverse().map((id) => activity(id)),
      );
      const aBefore = await read("strava.activities", a);

      ingest("conn_b", [activity("3")], { emittedAt: RUN_2 });

      const aAfter = await read("strava.activities", a);
      expect(ids(aAfter)).toEqual(arrival);
      expect(aAfter.ok && aAfter.revision).toBe(aBefore.ok && aBefore.revision);
      expect(ids(await read("strava.activities", b))).toEqual([
        "21",
        "2000000000",
        "9",
        "100",
        "3",
      ]);
    });

    it("orders coverage diagnostics the same way", async () => {
      const a = connect("conn_a");
      const d = (id: string) => diagnostic({ id });
      replace("conn_a", "coverage_diagnostics", [
        d("activities:unknown"),
        d(`activities:${EXPORTED_AT}`),
      ]);

      const result = await read("strava.coverage_diagnostics", a);
      expect(ids(result)).toEqual([
        "activities:unknown",
        `activities:${EXPORTED_AT}`,
      ]);
      expect(result).toMatchObject({ ok: true, complete: true });
    });
  });

  describe("record order across processes and upgrades", () => {
    const arrival = ["100", "9", "2000000000", "21", "3"];
    const byKey = ["100", "2000000000", "21", "3", "9"];
    let dir: string;
    let file: string;
    const opened: Store[] = [];
    const open = () => {
      const next = createSqliteRecordStore(new Database(file));
      opened.push(next);
      return next;
    };

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "strava-order-"));
      file = join(dir, "ps.sqlite");
    });
    afterEach(() => {
      for (const target of opened.splice(0)) target.close();
      rmSync(dir, { recursive: true, force: true });
    });

    it("keeps the order across a reopen", async () => {
      const first = open();
      const a = connectTo(first, "conn_a");
      ingestTo(
        first,
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      first.close();
      opened.splice(opened.indexOf(first), 1);

      const reopened = open();
      const result = await readCanonicalLegacyScope({
        store: reopened,
        scope: "strava.activities",
        selection: a,
      });
      expect(ids(result)).toEqual(arrival);
      expect(result).toMatchObject({ ok: true, complete: true });
    });

    it("says so when rows written before order was kept have no order evidence", async () => {
      // A database last opened by a build without arrival metadata: same
      // rows, no order evidence. Nothing is guessed from history.
      const legacy = open();
      const a = connectTo(legacy, "conn_a");
      ingestTo(
        legacy,
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      legacy.replaceStream({
        instance: "conn_a",
        stream: "coverage_diagnostics",
        method: METHOD,
        generation: 1,
        emittedAt: RUN_1,
        primaryKey: ["id"],
        envelopes: [
          {
            instance: "conn_a",
            stream: "coverage_diagnostics",
            key: "activities:unknown",
            data: diagnostic({ id: "activities:unknown" }),
            emitted_at: RUN_1,
          },
        ],
        sourceCollectedAt: RUN_1,
      });
      const legacyDb = new Database(file);
      legacyDb.exec("DROP TABLE IF EXISTS pdpp_record_arrival");
      legacyDb
        .prepare("UPDATE pdpp_schema_version SET version = 7 WHERE id = 1")
        .run();
      legacyDb.close();
      legacy.close();
      opened.splice(opened.indexOf(legacy), 1);

      const upgraded = open();
      const readScope = (scope: Scope) =>
        readCanonicalLegacyScope({ store: upgraded, scope, selection: a });

      const gap = await readScope("strava.activities");
      expect(ids(gap)).toEqual(byKey);
      expect(gap).toMatchObject({ ok: true, complete: false });
      expect(gap.ok && gap.diagnostics.unproven).toEqual([
        {
          stream: "activities",
          aspect: "record_order",
          reason: expect.any(String),
        },
      ]);
      // One row has only one order.
      const single = await readScope("strava.coverage_diagnostics");
      expect(single).toMatchObject({ ok: true, complete: true });
      expect(single.ok && "unproven" in single.diagnostics).toBe(false);

      // Re-delivering one key does not prove where the others belong.
      ingestTo(upgraded, "conn_a", [activity("9")], { emittedAt: RUN_2 });
      const stillGap = await readScope("strava.activities");
      expect(ids(stillGap)).toEqual(byKey);
      expect(stillGap).toMatchObject({ ok: true, complete: false });

      // A delivery of every live key does.
      const next = ["21", "3", "100", "9", "2000000000"];
      ingestTo(
        upgraded,
        "conn_a",
        next.map((id) => activity(id)),
        { emittedAt: RUN_2 },
      );
      const proven = await readScope("strava.activities");
      expect(ids(proven)).toEqual(next);
      expect(proven).toMatchObject({ ok: true, complete: true });
      expect(proven.ok && "unproven" in proven.diagnostics).toBe(false);
    });

    it("reads the order in the same snapshot as the rows", async () => {
      const reader = open();
      const writer = open();
      const a = connectTo(reader, "conn_a");
      ingestTo(
        reader,
        "conn_a",
        arrival.map((id) => activity(id)),
      );
      // Another process re-delivers 100 after the reader saw its rows.
      let injected = false;
      const racing: CanonicalLegacyReadStore = {
        ...reader,
        listRecords(stream, options) {
          const page = reader.listRecords(stream, options);
          if (!injected) {
            injected = true;
            ingestTo(writer, "conn_a", [activity("100")], {
              emittedAt: RUN_2,
            });
          }
          return page;
        },
      };

      const during = await readCanonicalLegacyScope({
        store: racing,
        scope: "strava.activities",
        selection: a,
        pageSize: 2,
      });
      const after = await readCanonicalLegacyScope({
        store: reader,
        scope: "strava.activities",
        selection: a,
      });

      expect(injected).toBe(true);
      expect(ids(during)).toEqual(arrival);
      expect(ids(after)).toEqual(["9", "2000000000", "21", "3", "100"]);
      expect(after.ok && after.revision).not.toBe(during.ok && during.revision);
    });
  });
});
