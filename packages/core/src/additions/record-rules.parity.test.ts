/**
 * Rows form versus legacy form, for every legacy binding the test has a
 * fixture for. The fixture's rows go through the binding's own projection;
 * the keys the rules extract from the stored ROWS form must equal the keys
 * extracted from the projected LEGACY body, or the collection must be
 * untracked (counted, no keys) in both. Bindings with no fixture here must be
 * untracked. Otherwise a scope moving from one stored form to the other would
 * report every existing record as newly added.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
} from "../legacy-projection/index.js";
import { extractRecordKeys } from "./first-added.js";
import { MEMORY_RECORD_RULES } from "./record-rules.js";

type Rows = Record<string, Record<string, unknown>[]>;

/**
 * Rows per PDPP stream, shaped by each binding's `fieldsRead`. `own` is the
 * stream stored under the scope itself (the rows form of that scope).
 */
const FIXTURES: Record<string, { own: string; streams: Rows }> = {
  "chatgpt.conversations": {
    own: "conversations",
    streams: {
      conversations: [
        {
          id: "c1",
          title: "T",
          create_time: "2026-09-01T10:00:00Z",
          update_time: "2026-09-01T10:05:00Z",
          current_node: "m1",
          message_count_on_current_branch: 1,
        },
        {
          id: "c2",
          title: "U",
          create_time: "2026-09-02T10:00:00Z",
          update_time: "2026-09-02T10:05:00Z",
          current_node: "m2",
          message_count_on_current_branch: 1,
        },
      ],
      messages: [
        {
          id: "m1",
          conversation_id: "c1",
          parent_id: null,
          role: "user",
          content: "hi",
          content_type: "text",
          model_slug: null,
          create_time: "2026-09-01T10:01:00Z",
          on_current_branch: true,
        },
        {
          id: "m2",
          conversation_id: "c2",
          parent_id: null,
          role: "user",
          content: "yo",
          content_type: "text",
          model_slug: null,
          create_time: "2026-09-02T10:01:00Z",
          on_current_branch: true,
        },
      ],
    },
  },
  "github.repositories": {
    own: "repositories",
    streams: {
      repositories: [
        { id: 1, name: "r1", html_url: "https://github.com/o/r1" },
        { id: 2, name: "r2", html_url: "https://github.com/o/r2" },
      ],
    },
  },
  "github.starred": {
    own: "starred",
    streams: {
      starred: [
        { id: 1, full_name: "o/r1", html_url: "https://github.com/o/r1" },
        { id: 2, full_name: "o/r2", html_url: "https://github.com/o/r2" },
      ],
    },
  },
  "github.events": {
    own: "events",
    streams: {
      events: [
        {
          id: "e1",
          type: "PushEvent",
          created_at: "2026-09-01T10:00:00Z",
          repository_full_name: "o/r",
          is_public: true,
        },
      ],
    },
  },
  "github.contributions": {
    own: "contributions",
    streams: {
      contributions: [
        { id: "x1", date: "2026-09-01", contribution_count: 3 },
        { id: "x2", date: "2026-09-02", contribution_count: 0 },
      ],
    },
  },
  "icloud_notes.notes": {
    own: "notes",
    streams: {
      folders: [{ id: "f1", name: "Folder" }],
      notes: [
        {
          id: "n1",
          title: "A",
          snippet: null,
          folder_id: "f1",
          is_pinned: false,
          created_at: "2026-09-01T10:00:00Z",
          modified_at: "2026-09-01T10:00:00Z",
          has_attachments: false,
          text_content: "hi",
        },
        {
          id: "n2",
          title: "B",
          snippet: null,
          folder_id: null,
          is_pinned: true,
          created_at: null,
          modified_at: null,
          has_attachments: false,
          text_content: null,
        },
      ],
    },
  },
  "icloud_notes.folders": {
    own: "folders",
    streams: {
      folders: [
        { id: "f1", name: "One" },
        { id: "f2", name: "Two" },
      ],
    },
  },
  "instagram.posts": {
    own: "posts",
    streams: {
      posts: [
        { id: "p1", taken_at: "2026-09-01T10:00:00Z", caption: "a" },
        { id: "p2", taken_at: "2026-09-02T10:00:00Z", caption: "b" },
      ],
      post_likes: [],
    },
  },
  "instagram.following": {
    own: "following",
    streams: {
      following: [
        { id: "77", username: "bob" },
        { id: "78", username: "amy" },
      ],
    },
  },
  "instagram.ads": {
    own: "ads",
    streams: {
      ads: [
        { id: "1", kind: "ad_topic", name: "Cars" },
        { id: "2", kind: "advertiser", name: "Acme" },
        { id: "3", kind: "ad_category", name: "Ignored", description: null },
      ],
    },
  },
  "linkedin.experience": {
    own: "experience",
    streams: {
      experience: [
        { id: "e1", title: "Dev", company: "X" },
        { id: "e2", title: "Lead", company: "Y" },
      ],
    },
  },
  "linkedin.education": {
    own: "education",
    streams: {
      education: [
        { id: "d1", school: "S" },
        { id: "d2", school: "T" },
      ],
    },
  },
  "spotify.playlists": {
    own: "playlists",
    streams: {
      playlists: [
        { id: "1", name: "P", uri: "spotify:playlist:1" },
        { id: "2", name: "Q", uri: "spotify:playlist:2" },
      ],
      playlist_items: [],
    },
  },
  "spotify.savedTracks": {
    own: "saved_tracks",
    streams: {
      saved_tracks: [
        { id: "t1", name: "T", artist_names: ["A"], uri: "spotify:track:1" },
        { id: "t2", name: "U", artist_names: [], uri: "spotify:track:2" },
      ],
    },
  },
  "oura.activity": {
    own: "activity",
    streams: {
      activity: [
        { id: "a1", day: "2026-09-01" },
        { id: "a2", day: "2026-09-02" },
      ],
    },
  },
  "oura.readiness": {
    own: "readiness",
    streams: { readiness: [{ id: "r1", day: "2026-09-01" }] },
  },
  // One stream feeds two legacy arrays: untracked.
  "oura.sleep": {
    own: "sleep",
    streams: { sleep: [{ id: "s1", day: "2026-09-01", type: "long_sleep" }] },
  },
  "youtube.playlists": {
    own: "playlists",
    streams: {
      playlists: [
        {
          id: "PL1",
          url: "https://www.youtube.com/playlist?list=PL1",
          title: "t",
        },
      ],
    },
  },
  "shop.orders": {
    own: "orders",
    streams: { orders: [{ id: "o1" }, { id: "o2" }] },
  },
  "linkedin.connections": {
    own: "connections",
    streams: {
      connections: [
        { id: "c1", full_name: "A" },
        { id: "c2", full_name: "B" },
      ],
    },
  },
  "linkedin.skills": {
    own: "skills",
    streams: { skills: [{ id: "s1", name: "A" }] },
  },
  "linkedin.languages": {
    own: "languages",
    streams: { languages: [{ id: "l1", name: "A" }] },
  },
};

type RepoFixture = { own: string; streams: Rows };

/** Fixtures the repo ships for its projection tests. */
function repoFixtures(): Record<string, RepoFixture> {
  const read = (name: string) =>
    JSON.parse(
      readFileSync(
        new URL(`../legacy-projection/__fixtures__/${name}`, import.meta.url),
        "utf8",
      ),
    ) as Record<string, unknown>;
  const group = (
    records: { stream: string; data: Record<string, unknown> }[],
  ) => {
    const streams: Rows = {};
    for (const record of records)
      (streams[record.stream] ??= []).push(record.data);
    return streams;
  };
  const claude = read("claude-projection.json") as Record<
    string,
    { stream: string; data: Record<string, unknown> }[]
  >;
  const amazon = read("amazon.orders.pdpp-input.json") as {
    records: { stream: string; data: Record<string, unknown> }[];
  };
  return {
    "claude.conversations": {
      own: "conversations",
      streams: group(claude["claude.conversations"]!),
    },
    "claude.projects": {
      own: "projects",
      streams: group(claude["claude.projects"]!),
    },
    "amazon.orders": { own: "orders", streams: group(amazon.records) },
  };
}

function project(scope: string, streams: Rows) {
  const records = Object.entries(streams).flatMap(([stream, rows]) =>
    rows.map((data) => ({ stream, data })),
  );
  return projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams: Object.keys(streams),
    now: "2026-10-01T00:00:00.000Z",
    allowMissingJoinStreams: true,
  });
}

const tracksAnything = (scope: string) =>
  (MEMORY_RECORD_RULES[scope] ?? []).some(
    (rule) => rule.idFields.length > 0 || rule.rowIdFields.length > 0,
  );

/**
 * What the owner app counts for each fixture, in each stored form (the app's
 * `buildPersonalMemoryRecords`: one record per item of the scope's list, one
 * per profile object). `legacy` is only given where the app counts a legacy
 * body differently from the rows.
 */
const EXPECTED_TOTALS: Record<
  string,
  { rows: number; legacy?: number; why: string }
> = {
  "chatgpt.conversations": { rows: 2, why: "one per conversation" },
  "github.repositories": { rows: 2, why: "one per repository" },
  "github.starred": { rows: 2, why: "one per starred repository" },
  "github.events": { rows: 1, why: "one per event" },
  "github.contributions": { rows: 2, why: "one per day" },
  "icloud_notes.notes": { rows: 2, why: "one per note" },
  "icloud_notes.folders": { rows: 2, why: "one per folder" },
  "instagram.posts": { rows: 2, why: "one per post" },
  "instagram.following": { rows: 2, why: "one per account" },
  "instagram.ads": {
    rows: 3,
    why: "topics, advertisers and categories all count (the app lists every ad row)",
  },
  "linkedin.experience": { rows: 2, why: "one per experience" },
  "linkedin.education": { rows: 2, why: "one per school" },
  "linkedin.connections": { rows: 2, why: "one per connection" },
  "linkedin.skills": { rows: 1, why: "one per skill" },
  "linkedin.languages": { rows: 1, why: "one per language" },
  "spotify.playlists": { rows: 2, why: "one per playlist" },
  "spotify.savedTracks": { rows: 2, why: "one per saved track" },
  "oura.activity": { rows: 2, why: "one per day" },
  "oura.readiness": { rows: 1, why: "one per day" },
  "oura.sleep": {
    rows: 1,
    legacy: 2,
    why: "the app counts every record array of the legacy body: the sleep row appears in dailyScores and in sleepPeriods",
  },
  "youtube.playlists": { rows: 1, why: "one per playlist" },
  "shop.orders": { rows: 2, why: "one per order" },
  "claude.conversations": { rows: 1, why: "one per conversation" },
  "claude.projects": { rows: 1, why: "one per project" },
  "amazon.orders": { rows: 1, why: "one per order" },
};

describe("record rules: rows form and legacy form agree for every fixture-backed binding", () => {
  const fixtures = { ...FIXTURES, ...repoFixtures() };

  for (const [scope, fixture] of Object.entries(fixtures)) {
    it(`${scope}: consistent in both forms, or untracked in both`, async () => {
      const source = scope.slice(0, scope.indexOf("."));
      const projected = project(scope, fixture.streams);
      if (!projected.ok) throw new Error(JSON.stringify(projected.error));
      const legacy = await extractRecordKeys(scope, projected.payload);
      // Rows are stored under `<source>.<stream>`.
      const rows = await extractRecordKeys(`${source}.${fixture.own}`, {
        records: fixture.streams[fixture.own]!,
      });

      expect(legacy).not.toBeNull();
      expect(rows).not.toBeNull();
      expect(
        MEMORY_RECORD_RULES[scope],
        "needs an explicit rule",
      ).toBeDefined();
      expect(new Set(rows!.keys)).toEqual(new Set(legacy!.keys));
      const expected = EXPECTED_TOTALS[scope];
      expect(expected, `${scope} needs an expected total`).toBeDefined();
      expect(rows!.total, `${scope} rows total: ${expected!.why}`).toBe(
        expected!.rows,
      );
      expect(legacy!.total, `${scope} legacy total: ${expected!.why}`).toBe(
        expected!.legacy ?? expected!.rows,
      );
      // Tracked scopes really produce keys in both forms.
      if (tracksAnything(scope)) expect(legacy!.keys.length).toBeGreaterThan(0);
      else expect(legacy!.keys).toEqual([]);
    });
  }

  it("every other binding is untracked, so it cannot disagree between forms", () => {
    const withoutFixture = [...LEGACY_SCOPE_BINDINGS.keys()].filter(
      (scope) => !(scope in fixtures) && scope !== "github.history",
    );
    expect(withoutFixture.length).toBeGreaterThan(0);
    const tracked = withoutFixture.filter(tracksAnything);
    expect(tracked, "tracked without a fixture proving both forms").toEqual([]);
    for (const scope of withoutFixture) {
      expect(MEMORY_RECORD_RULES[scope], scope).toBeDefined();
    }
  });

  it("every stream a binding joins in has an explicit rule", () => {
    for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
      const source = scope.slice(0, scope.indexOf("."));
      for (const stream of binding.pdppStreams) {
        expect(
          MEMORY_RECORD_RULES[`${source}.${stream}`],
          `${source}.${stream}`,
        ).toBeDefined();
      }
    }
  });

  it("github.history: the real projection's keys are a subset of the issues and pull_requests scopes' keys", async () => {
    // The PDPP streams are stored as github.issues, github.pull_requests and
    // github.user, never as one github.history rows scope; the legacy body is
    // a filtered view (authored issues only).
    const streams: Rows = {
      user: [{ id: "u1", login: "me" }],
      issues: [
        {
          id: "i1",
          repository_full_name: "o/r",
          user_login: "me",
          is_pull_request: false,
        },
        {
          id: "i2",
          repository_full_name: "o/r",
          user_login: "other",
          is_pull_request: false,
        },
      ],
      pull_requests: [{ id: "p1", repository_full_name: "o/r" }],
    };
    const projected = project("github.history", streams);
    if (!projected.ok) throw new Error(JSON.stringify(projected.error));
    const legacy = await extractRecordKeys("github.history", projected.payload);
    const issues = await extractRecordKeys("github.issues", {
      records: streams.issues!,
    });
    const pulls = await extractRecordKeys("github.pull_requests", {
      records: streams.pull_requests!,
    });
    expect(legacy!.keys.length).toBeGreaterThan(0);
    const rowsKeys = new Set([...issues!.keys, ...pulls!.keys]);
    for (const key of legacy!.keys) expect(rowsKeys.has(key)).toBe(true);
  });
});

describe("the server's total equals the owner app's count for scopes without a projection fixture", () => {
  // [scope, rows body, rows total, legacy body, legacy total, why]
  const cases: [
    string,
    Record<string, unknown>,
    number,
    Record<string, unknown> | null,
    number,
    string,
  ][] = [
    [
      "linkedin.profile",
      { records: [{ id: "p" }] },
      1,
      { fullName: "A" },
      1,
      "the profile object is one record",
    ],
    [
      "spotify.profile",
      { records: [{ id: "u" }] },
      1,
      { id: "u", display_name: "A", images: [{}, {}] },
      1,
      "one profile, whatever arrays it carries (the generic rule gave 2)",
    ],
    [
      "youtube.profile",
      { records: [{ id: "c" }] },
      1,
      { channelTitle: "A" },
      1,
      "the profile object is one record",
    ],
    [
      "heb.profile",
      { records: [{ id: "h" }] },
      1,
      { name: "A", deliveryAddresses: [] },
      1,
      "the profile object is one record",
    ],
    [
      "wholefoods.profile",
      { records: [{ id: "w" }] },
      1,
      { name: "A" },
      1,
      "the profile object is one record",
    ],
    [
      "youtube.subscriptions",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      { subscriptions: [{}, {}] },
      2,
      "one per subscription",
    ],
    [
      "youtube.likes",
      { records: [{ id: "a" }] },
      1,
      { likedVideos: [{}] },
      1,
      "one per liked video",
    ],
    [
      "youtube.watchLater",
      { records: [{ id: "a" }] },
      1,
      { watchLater: [{}] },
      1,
      "one per video",
    ],
    [
      "youtube.watch_later",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      null,
      0,
      "rows scope of watchLater",
    ],
    [
      "youtube.history",
      { records: [{ id: "a" }] },
      1,
      { history: [{}, {}] },
      2,
      "one per watched video",
    ],
    [
      "youtube.watch_history",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      null,
      0,
      "rows scope of history",
    ],
    [
      "youtube.playlistItems",
      { records: [{ id: "a" }] },
      1,
      { playlists: [{}] },
      1,
      "one per item",
    ],
    [
      "youtube.playlist_items",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      null,
      0,
      "rows scope of playlistItems",
    ],
    [
      "heb.nutrition",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      { nutrition: [{}, {}] },
      2,
      "one per product",
    ],
    [
      "wholefoods.nutrition",
      { records: [{ id: "a" }] },
      1,
      { nutrition: [{}] },
      1,
      "one per product",
    ],
    [
      "heb.orders",
      { records: [{ id: "a" }] },
      1,
      { orders: [{}] },
      1,
      "one per order",
    ],
    [
      "wholefoods.orders",
      { records: [{ id: "a" }] },
      1,
      { orders: [{}] },
      1,
      "one per order",
    ],
    [
      "amazon.order_items",
      { records: [{ id: "a" }, { id: "b" }] },
      2,
      null,
      0,
      "join-only stream, counted as its own scope",
    ],
    [
      "heb.order_items",
      { records: [{ id: "a" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "wholefoods.order_items",
      { records: [{ id: "a" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "claude.messages",
      { records: [{ id: "m" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "claude.account_profile",
      { records: [{ id: "m" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "claude.project_documents",
      { records: [{ id: "m" }, { id: "n" }] },
      2,
      null,
      0,
      "join-only stream",
    ],
    ["github.user", { records: [{ id: "u" }] }, 1, null, 0, "join-only stream"],
    [
      "github.user_stats",
      { records: [{ id: "u" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "github.organizations",
      { records: [{ id: "o" }, { id: "p" }] },
      2,
      null,
      0,
      "join-only stream",
    ],
    [
      "github.pinned_repositories",
      { records: [{ id: "r" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "instagram.post_likes",
      { records: [{ id: "l" }, { id: "m" }] },
      2,
      null,
      0,
      "join-only stream",
    ],
    [
      "spotify.playlist_items",
      { records: [{ id: "i" }] },
      1,
      null,
      0,
      "join-only stream",
    ],
    [
      "chatgpt.memories",
      { records: [{ id: "m" }] },
      0,
      { memories: [{}] },
      0,
      "the app counts none",
    ],
    [
      "chatgpt.messages",
      { records: [{ id: "m" }] },
      0,
      null,
      0,
      "the app counts none",
    ],
    [
      "github.profile",
      { records: [{ id: "g" }] },
      0,
      { username: "a", pinnedRepositories: [{}] },
      0,
      "the app counts none",
    ],
    [
      "instagram.profile",
      { records: [{ id: "i" }] },
      0,
      { username: "a" },
      0,
      "the app counts none",
    ],
  ];

  it.each(cases)(
    "%s",
    async (scope, rows, rowsTotal, legacy, legacyTotal, why) => {
      expect(
        (await extractRecordKeys(scope, rows))!.total,
        `rows: ${why}`,
      ).toBe(rowsTotal);
      if (legacy) {
        expect(
          (await extractRecordKeys(scope, legacy))!.total,
          `legacy: ${why}`,
        ).toBe(legacyTotal);
      }
      // Counted here, never tracked: none of these produce additions.
      expect((await extractRecordKeys(scope, rows))!.keys).toEqual([]);
    },
  );

  it("an empty profile body is not a record", async () => {
    expect((await extractRecordKeys("youtube.profile", {}))!.total).toBe(0);
  });
});
