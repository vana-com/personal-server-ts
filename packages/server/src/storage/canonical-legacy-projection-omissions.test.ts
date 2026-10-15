import { readFileSync } from "node:fs";
import Ajv from "ajv";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalConnectionSelection,
  type CanonicalLegacyReadResult,
} from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

// Rows already in canonical storage must never read back as a complete legacy
// body when the projector could not carry them. These tests go through the
// public reader over the real SQLite store and check every successful body
// against the frozen legacy schema.

const SRC = (name: string) => `https://registry.pdpp.dev/sources/${name}`;
const METHOD = "test_method";

/** Legacy `format: date` is a real calendar day. Written here, not imported, so the oracle is independent of the projector. */
function isRealDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const [year, month, day] = match.slice(1).map(Number);
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1];
}

// `strict` is an Ajv 8 option (the declared dependency); Ajv 6 ignores it.
const ajvStrictOff = { strict: false };
const ajv = new Ajv({ allErrors: true, ...ajvStrictOff });
ajv.addFormat("date", isRealDate);
ajv.addFormat("date-time", (value: string) => !Number.isNaN(Date.parse(value)));
ajv.addFormat("uri", (value: string) => /^[a-z][a-z0-9+.-]*:/i.test(value));

function legacySchemaValid(scope: string, payload: unknown): void {
  const file = new URL(
    `../../../core/src/legacy-projection/legacy-schemas/${scope}.json`,
    import.meta.url,
  );
  const { schema } = JSON.parse(readFileSync(file, "utf8")) as {
    schema: Record<string, unknown>;
  };
  const validate = ajv.compile(schema);
  expect(validate(payload), JSON.stringify(validate.errors)).toBe(true);
}

describe("canonical legacy reader: rows the projector cannot carry", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
  });
  afterEach(() => store.close());

  function connect(
    instance: string,
    source: string,
    method = METHOD,
  ): CanonicalConnectionSelection {
    store.registerConnection({
      instance,
      sourceId: SRC(source),
      method,
      label: instance,
    });
    return { instance, sourceId: SRC(source), method };
  }

  /** Rows keyed by `keyField`, so a row with a malformed `id` can still be stored. */
  function put(
    selection: CanonicalConnectionSelection,
    stream: string,
    rows: Record<string, unknown>[],
    { keyField = "id", emittedAt = "2026-09-01T00:00:00.000Z" } = {},
  ) {
    const envelopes: PdppRecordEnvelopeInput[] = rows.map((data) => ({
      instance: selection.instance,
      stream,
      key: String(data[keyField]),
      data,
      emitted_at: emittedAt,
    }));
    const result = store.ingestBatch(
      envelopes,
      () => "mutable_state",
      () => [keyField],
      { method: selection.method, generation: 1 },
    );
    expect(result.rejected).toEqual([]);
  }

  const read = (selection: CanonicalConnectionSelection, scope: string) =>
    readCanonicalLegacyScope({ store, scope, selection });

  const writes = () =>
    (db.prepare("SELECT total_changes() AS n").get() as { n: number }).n;

  function expectAllRejected(
    result: CanonicalLegacyReadResult,
    stream: string,
    rows: number,
  ) {
    expect(result).toMatchObject({
      ok: false,
      status: "incomplete",
      reason: "all_rows_rejected",
      stream,
      sourceRows: rows,
      dropped: rows,
    });
  }

  function okBody(result: CanonicalLegacyReadResult) {
    expect(result.ok, JSON.stringify(result)).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    return result;
  }

  /** Sum of omission counts per stream. */
  function omitted(result: CanonicalLegacyReadResult) {
    const byStream: Record<string, number> = {};
    for (const entry of okBody(result).diagnostics.omissions) {
      byStream[entry.stream] = (byStream[entry.stream] ?? 0) + entry.count;
    }
    return byStream;
  }

  describe("GitHub events and contributions", () => {
    const event = (id: string, extra: Record<string, unknown> = {}) => ({
      id,
      type: "PushEvent",
      created_at: "2026-10-13T00:00:00Z",
      repository_full_name: "synthetic/repo",
      is_public: true,
      ...extra,
    });

    it("refuses nonempty events that all lack a required field", async () => {
      const a = connect("conn_a", "github");
      put(a, "events", [
        event("e1", { type: undefined }),
        event("e2", { is_public: "yes" }),
      ]);
      expectAllRejected(await read(a, "github.events"), "events", 2);
    });

    it("delivers valid events with exact omission counts, schema-valid", async () => {
      const a = connect("conn_a", "github");
      put(a, "events", [
        event("e1"),
        event("e2", { type: undefined }),
        event("e3", { created_at: 7 }),
        event("e4"),
      ]);
      const result = okBody(await read(a, "github.events"));
      expect(result.complete).toBe(false);
      expect(
        (result.envelope.data.events as { id: string }[]).map((e) => e.id),
      ).toEqual(["e1", "e4"]);
      expect(omitted(result)).toEqual({ events: 2 });
      expect(result.diagnostics.sourceRowCounts).toEqual({ events: 4 });
      legacySchemaValid("github.events", result.envelope.data);
    });

    it("refuses nonempty contribution days that all lack a count", async () => {
      const a = connect("conn_a", "github");
      put(a, "contributions", [
        { id: "d1", date: "2026-10-13" },
        { id: "d2", date: "2026-10-14", contribution_count: "3" },
      ]);
      expectAllRejected(
        await read(a, "github.contributions"),
        "contributions",
        2,
      );
    });

    it("delivers valid contribution days with exact omission counts, schema-valid", async () => {
      const a = connect("conn_a", "github");
      put(a, "contributions", [
        { id: "d1", date: "2026-10-13", contribution_count: 4 },
        { id: "d2", date: "2026-10-14" },
        { id: "d3", date: "2026-10-15", contribution_count: 0 },
      ]);
      const result = okBody(await read(a, "github.contributions"));
      expect(result.complete).toBe(false);
      expect(result.envelope.data.days).toEqual([
        { date: "2026-10-13", count: 4 },
        { date: "2026-10-15", count: 0 },
      ]);
      expect(omitted(result)).toEqual({ contributions: 1 });
      legacySchemaValid("github.contributions", result.envelope.data);
    });

    it("serves a signed GitHub-browser snapshot whose events list is explicitly empty", async () => {
      const a = connect("conn_a", "github-browser");
      put(a, "events", [
        {
          id: "events",
          events: [],
          fetchedAt: "2026-10-13T00:00:00.000Z",
          windowDescription: "browser window",
        },
      ]);
      const result = okBody(await read(a, "github.events"));
      expect(result.complete).toBe(true);
      expect(result.envelope.data.events).toEqual([]);
      expect(result.diagnostics.sourceRowCounts).toEqual({ events: 1 });
      legacySchemaValid("github.events", result.envelope.data);
    });
  });

  describe("other bindings that used to drop rows silently", () => {
    it("instagram.following and instagram.ads: all bad is refused, mixed is partial", async () => {
      const a = connect("conn_a", "meta");
      put(a, "following", [
        { id: "f1", username: "" },
        { id: "f2", username: 5 },
      ]);
      put(a, "ads", [
        { id: "ad1", kind: "advertiser", name: "Shop" },
        { id: "ad2", kind: "unknown", name: "Other" },
        { id: "ad3", kind: "ad_topic" },
      ]);
      expectAllRejected(await read(a, "instagram.following"), "following", 2);
      const ads = okBody(await read(a, "instagram.ads"));
      expect(ads.complete).toBe(false);
      expect(ads.envelope.data.advertisers).toEqual([{ name: "Shop" }]);
      expect(omitted(ads)).toEqual({ ads: 2 });
      legacySchemaValid("instagram.ads", ads.envelope.data);

      put(a, "following", [{ id: "f3", username: "kept" }]);
      const following = okBody(await read(a, "instagram.following"));
      expect(following.complete).toBe(false);
      expect(following.envelope.data.total).toBe(1);
      expect(omitted(following)).toEqual({ following: 2 });
      legacySchemaValid("instagram.following", following.envelope.data);
    });

    it("instagram.posts counts likers it cannot attach", async () => {
      const a = connect("conn_a", "meta");
      put(a, "posts", [{ id: "p1", caption: "c", like_count: 1 }]);
      put(
        a,
        "post_likes",
        [
          {
            k: "1",
            liker_ordinal: 0,
            post_id: "p1",
            user_id: "u1",
            username: "one",
          },
          {
            k: "2",
            liker_ordinal: 1,
            post_id: "p-gone",
            user_id: "u2",
            username: "two",
          },
          { k: "3", liker_ordinal: 2, post_id: "p1", user_id: "u3" },
        ],
        { keyField: "k" },
      );
      const result = okBody(await read(a, "instagram.posts"));
      expect(result.complete).toBe(false);
      expect(
        (result.envelope.data.posts as { who_liked: unknown[] }[])[0]
          ?.who_liked,
      ).toHaveLength(1);
      expect(omitted(result)).toEqual({ post_likes: 2 });
      legacySchemaValid("instagram.posts", result.envelope.data);
    });

    it("amazon.orders counts order items with no order", async () => {
      const a = connect("conn_a", "amazon");
      put(a, "orders", [{ id: "o1", order_date: "2026-01-02" }]);
      put(a, "order_items", [
        { id: "i1", order_id: "o1", name: "kept" },
        { id: "i2", order_id: "o-gone", name: "orphan" },
      ]);
      const result = okBody(await read(a, "amazon.orders"));
      expect(result.complete).toBe(false);
      expect(omitted(result)).toEqual({ order_items: 1 });
      legacySchemaValid("amazon.orders", result.envelope.data);
    });

    it("github.profile counts pinned repositories and organizations it cannot name", async () => {
      const a = connect("conn_a", "github");
      put(a, "user", [{ id: "u", login: "octo" }]);
      put(a, "user_stats", [
        { id: "s", observed_on: "2026-10-01", followers: 1 },
      ]);
      put(a, "pinned_repositories", [
        { id: "r1", full_name: "octo/a" },
        { id: "r2" },
      ]);
      put(a, "organizations", [{ id: "g1" }]);
      const result = okBody(await read(a, "github.profile"));
      expect(result.complete).toBe(false);
      expect(omitted(result)).toEqual({
        pinned_repositories: 1,
        organizations: 1,
      });
      legacySchemaValid("github.profile", result.envelope.data);
    });

    it("github.history refuses an authored issue it cannot classify", async () => {
      const a = connect("conn_a", "github");
      put(a, "user", [{ id: "u", login: "octo" }]);
      put(a, "pull_requests", [{ id: "pr1", repository_full_name: "octo/a" }]);
      put(a, "issues", [
        { id: "i1", user_login: "octo", repository_full_name: "octo/a" },
      ]);
      expect(await read(a, "github.history")).toMatchObject({
        ok: false,
        reason: "projection_rejected",
        error: { kind: "incomplete_scope" },
      });
    });

    it("spotify.playlists refuses a playlist item with no playlist id", async () => {
      const a = connect("conn_a", "spotify");
      put(a, "playlists", [{ id: "pl", name: "Mix" }]);
      put(a, "playlist_items", [
        { id: "x1", playlist_id: "pl", position: 0, uri: "spotify:track:a" },
        { id: "x2", position: 1, uri: "spotify:track:b" },
      ]);
      expect(await read(a, "spotify.playlists")).toMatchObject({
        ok: false,
        reason: "projection_rejected",
      });
    });
  });

  describe("Oura scores and calendar days", () => {
    const cases = [
      {
        scope: "oura.activity",
        stream: "activity",
        list: "days",
        score: "score",
      },
      {
        scope: "oura.readiness",
        stream: "readiness",
        list: "days",
        score: "score",
      },
      {
        scope: "oura.sleep",
        stream: "sleep",
        list: "dailyScores",
        score: "sleep_score",
      },
    ];
    const absent = Symbol("absent");

    for (const c of cases) {
      const row = (id: string, day: string, score: unknown = 80) => ({
        id,
        day,
        ...(score === absent ? {} : { [c.score]: score }),
      });

      it(`${c.scope}: keeps integer, rounded and null scores; drops absent, malformed and impossible-day rows`, async () => {
        const a = connect("conn_a", "oura");
        put(a, c.stream, [
          row("good", "2026-02-01", 80),
          row("null", "2026-02-02", null),
          row("zero", "2026-02-03", 0),
          row("absent", "2026-02-04", absent),
          row("string", "2026-02-05", "80"),
          row("fraction", "2026-02-06", 80.5),
          row("too-high", "2026-02-07", 101),
          row("feb-30", "2026-02-30", 80),
        ]);
        const result = okBody(await read(a, c.scope));
        const list = result.envelope.data[c.list] as {
          id: string;
          score: unknown;
        }[];
        expect(list.map((entry) => [entry.id, entry.score])).toEqual([
          ["fraction", 81],
          ["good", 80],
          ["null", null],
          ["zero", 0],
        ]);
        expect(result.complete).toBe(false);
        expect(omitted(result)).toEqual({ [c.stream]: 4 });
        legacySchemaValid(c.scope, result.envelope.data);
      });

      it(`${c.scope}: refuses nonempty rows that all lack a score`, async () => {
        const a = connect("conn_a", "oura");
        put(a, c.stream, [
          row("a", "2026-02-01", absent),
          row("b", "2026-02-02", absent),
        ]);
        expectAllRejected(await read(a, c.scope), c.stream, 2);
      });
    }

    it("selects the base profile by source identity, not by a browser-looking method", async () => {
      const a = connect("conn_a", "oura", "browser");
      // A base sleep row has no record_type; the Browser profile would refuse it.
      put(a, "sleep", [{ id: "s1", day: "2026-02-01", sleep_score: 70 }]);
      const result = okBody(await read(a, "oura.sleep"));
      expect(result.complete).toBe(true);
      expect(result.envelope.data.sleepPeriods).toEqual([
        { id: "s1", day: "2026-02-01" },
      ]);
      legacySchemaValid("oura.sleep", result.envelope.data);
    });

    it("keeps PAT sleep periods when sleep_score is null", async () => {
      const a = connect("conn_a", "oura");
      put(a, "sleep", [
        {
          id: "s-null",
          day: "2026-02-01",
          sleep_score: null,
          type: "long_sleep",
          total_sleep_duration: 3600,
        },
      ]);
      const result = okBody(await read(a, "oura.sleep"));
      expect(result.complete).toBe(true);
      expect(result.envelope.data).toEqual({
        dailyScores: [{ id: "s-null", day: "2026-02-01", score: null }],
        sleepPeriods: [
          {
            id: "s-null",
            day: "2026-02-01",
            type: "long_sleep",
            totalSleepDuration: 3600,
          },
        ],
      });
      legacySchemaValid("oura.sleep", result.envelope.data);
    });

    it("carries Oura omission provenance beside the projected payload", async () => {
      const a = connect("conn_a", "oura-browser");
      put(a, "sleep", [
        {
          id: "d1",
          day: "2026-02-01",
          record_type: "daily_score",
          sleep_score: 70,
          daily_sleep_timestamp: null,
        },
        {
          id: "s1",
          day: "2026-02-01",
          record_type: "sleep_session",
          sleep_score: null,
          type: "awake",
          bedtime_start: null,
          bedtime_end: null,
        },
      ]);
      const result = okBody(await read(a, "oura.sleep"));
      expect(result.projectionOmissions).toEqual([
        {
          entityPath: "$.sleepPeriods[]",
          entityKey: "s1",
          fieldPath: "type",
          reason: "off_enum_type",
        },
        {
          entityPath: "$.sleepPeriods[]",
          entityKey: "s1",
          fieldPath: "bedtimeStart",
          reason: "null_timestamp",
        },
        {
          entityPath: "$.sleepPeriods[]",
          entityKey: "s1",
          fieldPath: "bedtimeEnd",
          reason: "null_timestamp",
        },
        {
          entityPath: "$.dailyScores[]",
          entityKey: "d1",
          fieldPath: "timestamp",
          reason: "null_timestamp",
        },
      ]);
      legacySchemaValid("oura.sleep", result.envelope.data);
    });

    describe("Oura Browser profile", () => {
      const score = (id: string, day: string, value: unknown) => ({
        id,
        day,
        record_type: "daily_score",
        ...(value === absent ? {} : { sleep_score: value }),
      });
      const session = (id: string, day: string) => ({
        id,
        day,
        record_type: "sleep_session",
        sleep_score: null,
      });

      it("keeps null daily scores in an otherwise valid score-only stream", async () => {
        const a = connect("conn_a", "oura-browser");
        put(a, "sleep", [
          score("d1", "2026-02-01", 70),
          score("d2", "2026-02-02", null),
        ]);
        const result = okBody(await read(a, "oura.sleep"));
        expect(result.complete).toBe(true);
        expect(result.envelope.data).toEqual({
          dailyScores: [
            { id: "d1", day: "2026-02-01", score: 70 },
            { id: "d2", day: "2026-02-02", score: null },
          ],
          sleepPeriods: [],
        });
        expect(omitted(result)).toEqual({});
        legacySchemaValid("oura.sleep", result.envelope.data);
      });

      it("drops daily scores with an impossible day, an absent score or a malformed score", async () => {
        const a = connect("conn_a", "oura-browser");
        put(a, "sleep", [
          score("d1", "2026-02-01", 70),
          score("feb-30", "2026-02-30", 70),
          score("absent", "2026-02-03", absent),
          score("string", "2026-02-04", "70"),
          session("s1", "2026-02-01"),
          session("s-feb-30", "2026-02-30"),
        ]);
        const result = okBody(await read(a, "oura.sleep"));
        expect(
          (result.envelope.data.dailyScores as { id: string }[]).map(
            (entry) => entry.id,
          ),
        ).toEqual(["d1"]);
        expect(
          (result.envelope.data.sleepPeriods as { id: string }[]).map(
            (entry) => entry.id,
          ),
        ).toEqual(["s1"]);
        expect(result.complete).toBe(false);
        expect(omitted(result)).toEqual({ sleep: 4 });
        legacySchemaValid("oura.sleep", result.envelope.data);
      });

      it("refuses a stream whose every row is dropped", async () => {
        const a = connect("conn_a", "oura-browser");
        put(a, "sleep", [
          score("feb-30", "2026-02-30", 70),
          score("absent", "2026-02-03", absent),
        ]);
        expectAllRejected(await read(a, "oura.sleep"), "sleep", 2);
      });

      it("applies the same day and score rules to activity", async () => {
        const a = connect("conn_a", "oura-browser");
        put(a, "activity", [
          { id: "a1", day: "2026-02-01", score: 60 },
          { id: "a2", day: "2026-02-02" },
          { id: "a3", day: "2026-02-30", score: 60 },
        ]);
        const result = okBody(await read(a, "oura.activity"));
        expect(result.complete).toBe(false);
        expect(omitted(result)).toEqual({ activity: 2 });
        legacySchemaValid("oura.activity", result.envelope.data);
      });
    });
  });

  describe("Claude source identity", () => {
    // Retained profiles name the connector, not a public sources/anthropic declaration.
    it.each(["source", "method"] as const)(
      "refuses the undeclared sources/anthropic alias when selected by %s",
      async (profileBy) => {
        const a = connect("conn_a", "anthropic", "anthropic");
        put(a, "account_profile", [{ id: "org", organization_id: "org" }]);
        for (const scope of ["claude.conversations", "claude.projects"]) {
          expect(
            await readCanonicalLegacyScope({
              store,
              scope,
              selection: a,
              profileBy,
            }),
          ).toMatchObject({
            ok: false,
            status: "unavailable",
            reason: "scope_source_mismatch",
            scope,
          });
        }
      },
    );
  });

  describe("grocery orders: partial first read, complete after repair", () => {
    const grocers = [
      {
        source: "heb",
        scope: "heb.orders",
        line: (id: string, orderId: string, extra = {}) => ({
          id,
          order_id: orderId,
          name: `Item ${id}`,
          product_id: `p-${id}`,
          quantity: 1,
          ...extra,
        }),
      },
      {
        source: "wholefoods",
        scope: "wholefoods.orders",
        line: (id: string, orderId: string, extra = {}) => ({
          id,
          order_id: orderId,
          name: `Item ${id}`,
          product_id: `B-${id}`,
          quantity: 1,
          ...extra,
        }),
      },
    ];
    const order = (id: string, itemCount: unknown = 1) => ({
      id,
      order_date: "2026-09-01",
      item_count: itemCount,
    });
    const orderIds = (result: CanonicalLegacyReadResult) =>
      (okBody(result).envelope.data.orders as { orderId: string }[]).map(
        (entry) => entry.orderId,
      );

    for (const g of grocers) {
      it(`${g.scope}: serves the hydrated order first, both once the gap's detail lands, writing nothing`, async () => {
        const a = connect("conn_a", g.source);
        put(a, "orders", [order("good"), order("gap")]);
        put(a, "order_items", [g.line("good-1", "good")]);

        const before = writes();
        const first = await read(a, g.scope);
        expect(writes()).toBe(before);
        expect(orderIds(first)).toEqual(["good"]);
        expect(okBody(first).complete).toBe(false);
        expect(okBody(first).diagnostics.omissions).toEqual([
          {
            stream: "orders",
            count: 1,
            reasons: ["projection_order_items_gap"],
          },
        ]);

        put(a, "order_items", [g.line("gap-1", "gap")], {
          emittedAt: "2026-09-02T00:00:00.000Z",
        });
        const afterRepair = writes();
        const second = await read(a, g.scope);
        expect(writes()).toBe(afterRepair);
        expect(orderIds(second)).toEqual(["gap", "good"]);
        expect(okBody(second).complete).toBe(true);
        expect(okBody(second).diagnostics.omissions).toEqual([]);
      });

      it(`${g.scope}: refuses orders that all have detail gaps`, async () => {
        const a = connect("conn_a", g.source);
        put(a, "orders", [order("gap-a"), order("gap-b", null)]);
        put(a, "order_items", [g.line("bad", "gap-a", { product_id: "" })]);
        expect(await read(a, g.scope)).toMatchObject({
          ok: false,
          status: "incomplete",
          reason: "projection_rejected",
          error: {
            kind: "incomplete_scope",
            diagnostics: expect.arrayContaining([
              expect.objectContaining({
                stream: "orders",
                count: 2,
                reasons: ["projection_order_items_gap"],
              }),
              expect.objectContaining({
                stream: "order_items",
                count: 1,
                reasons: ["projection_order_item_missing_product_id"],
              }),
            ]),
          },
        });
      });

      it(`${g.scope}: keeps a known-zero order and counts an unusable line beside a valid one`, async () => {
        const a = connect("conn_a", g.source);
        put(a, "orders", [order("empty", 0), order("mixed", 1)]);
        put(a, "order_items", [
          g.line("ok", "mixed"),
          g.line("no-name", "mixed", { name: "" }),
        ]);
        const result = okBody(await read(a, g.scope));
        expect(orderIds(result)).toEqual(["empty", "mixed"]);
        expect(result.complete).toBe(false);
        expect(omitted(result)).toEqual({ order_items: 1 });
      });

      it(`${g.scope}: never fills a gap with another account's detail`, async () => {
        const a = connect("conn_a", g.source);
        const b = connect("conn_b", g.source);
        put(a, "orders", [order("good"), order("gap")]);
        put(a, "order_items", [g.line("good-1", "good")]);
        put(b, "orders", [order("gap")]);
        put(b, "order_items", [g.line("gap-1", "gap")]);
        const result = await read(a, g.scope);
        expect(orderIds(result)).toEqual(["good"]);
        expect(okBody(result).complete).toBe(false);
        expect(orderIds(await read(b, g.scope))).toEqual(["gap"]);
      });
    }

    it("heb.orders: item_count counts quantity units, not lines", async () => {
      const a = connect("conn_a", "heb");
      put(a, "orders", [order("units", 5), order("short", 4)]);
      put(a, "order_items", [
        grocers[0].line("u1", "units", { quantity: 3 }),
        grocers[0].line("u2", "units", { quantity: 2 }),
        grocers[0].line("s1", "short", { quantity: 1 }),
      ]);
      const result = okBody(await read(a, "heb.orders"));
      expect(orderIds(result)).toEqual(["short", "units"]);
      expect(result.diagnostics.omissions).toEqual([]);
      expect(result.diagnostics.partialRows).toEqual([
        {
          stream: "orders",
          count: 1,
          reasons: ["projection_order_unit_count_mismatch"],
        },
      ]);
      expect(result.complete).toBe(false);
    });

    it("heb.orders: an unkeyable order is counted beside valid peers; with only a gap left it is refused", async () => {
      const a = connect("conn_a", "heb");
      put(
        a,
        "orders",
        [
          { row: "bad", id: "", item_count: 0 },
          { row: "good", ...order("good") },
        ],
        { keyField: "row" },
      );
      put(a, "order_items", [grocers[0].line("g1", "good")]);
      const mixed = okBody(await read(a, "heb.orders"));
      expect(orderIds(mixed)).toEqual(["good"]);
      expect(mixed.diagnostics.omissions).toEqual([
        { stream: "orders", count: 1, reasons: ["projection_invalid_order"] },
      ]);

      const b = connect("conn_b", "heb");
      put(
        b,
        "orders",
        [
          { row: "bad", id: "", item_count: 0 },
          { row: "gap", ...order("gap") },
        ],
        { keyField: "row" },
      );
      put(b, "order_items", [grocers[0].line("x", "gap", { name: "" })]);
      expect(await read(b, "heb.orders")).toMatchObject({
        ok: false,
        reason: "projection_rejected",
        error: {
          diagnostics: expect.arrayContaining([
            expect.objectContaining({
              stream: "orders",
              reasons: ["projection_invalid_order"],
            }),
            expect.objectContaining({
              stream: "orders",
              reasons: ["projection_order_items_gap"],
            }),
          ]),
        },
      });
    });

    it("wholefoods.orders: a malformed order id still fails the whole scope", async () => {
      const a = connect("conn_a", "wholefoods");
      put(
        a,
        "orders",
        [
          { row: "bad", id: "", item_count: 0 },
          { row: "good", ...order("good") },
        ],
        { keyField: "row" },
      );
      put(a, "order_items", [grocers[1].line("g1", "good")]);
      expect(await read(a, "wholefoods.orders")).toMatchObject({
        ok: false,
        reason: "projection_rejected",
        error: { reason: "orders contain a missing or duplicate id" },
      });
    });
  });
});
