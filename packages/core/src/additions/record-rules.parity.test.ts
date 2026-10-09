/**
 * For every legacy binding that has a record rule: rows go through the
 * binding's own projection, and the keys the rule extracts from the stored
 * ROWS form must equal the keys it extracts from the projected LEGACY body.
 * Otherwise a scope moving from one stored form to the other would report
 * every existing record as newly added.
 */

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
};

/** Bindings whose rows are not stored under the legacy scope's own name. */
const NOT_ONE_ROWS_SCOPE = new Set(["github.history"]);

describe("record rules: rows form and legacy form agree for every binding", () => {
  const ruled = [...LEGACY_SCOPE_BINDINGS.keys()].filter(
    (scope) => MEMORY_RECORD_RULES[scope] !== undefined,
  );

  it("has a fixture for every ruled binding", () => {
    const missing = ruled.filter(
      (scope) => !FIXTURES[scope] && !NOT_ONE_ROWS_SCOPE.has(scope),
    );
    // Rule-less bindings (empty list) project nothing trackable.
    expect(
      missing.filter((scope) => MEMORY_RECORD_RULES[scope]!.length > 0),
    ).toEqual([]);
  });

  for (const [scope, fixture] of Object.entries(FIXTURES)) {
    it(`${scope}: rows keys equal projected legacy keys`, async () => {
      const source = scope.slice(0, scope.indexOf("."));
      const records = Object.entries(fixture.streams).flatMap(
        ([stream, rows]) => rows.map((data) => ({ stream, data })),
      );
      const projected = projectPdppRecordsToLegacyPayload(scope, records, {
        fetchedStreams: Object.keys(fixture.streams),
        now: "2026-10-01T00:00:00.000Z",
        allowMissingJoinStreams: true,
      });
      if (!projected.ok) throw new Error(JSON.stringify(projected.error));

      const legacy = await extractRecordKeys(scope, projected.payload);
      // The rows are stored under `<source>.<stream>`, which is the legacy
      // scope itself unless the stream is named differently.
      const rowsScope = `${source}.${fixture.own}`;
      const rows = await extractRecordKeys(rowsScope, {
        records: fixture.streams[fixture.own]!,
      });

      expect(legacy).not.toBeNull();
      expect(rows).not.toBeNull();
      expect(new Set(rows!.keys)).toEqual(new Set(legacy!.keys));
      expect(rows!.total).toBe(legacy!.total);
      const rule = MEMORY_RECORD_RULES[scope]!;
      const tracked = rule.some((r) => r.idFields.length > 0);
      expect(legacy!.keys.length > 0).toBe(tracked);
    });
  }

  it("github.history: the PDPP streams are stored as their own scopes", async () => {
    // issues and pull_requests are stored under github.issues and
    // github.pull_requests, never as one github.history rows scope, and their
    // rules produce the same collection keys as the legacy body.
    const legacy = await extractRecordKeys("github.history", {
      issues: [{ id: "i1" }],
      pullRequests: [{ id: "p1" }],
    });
    const issues = await extractRecordKeys("github.issues", {
      records: [{ id: "i1" }],
    });
    const pulls = await extractRecordKeys("github.pull_requests", {
      records: [{ id: "p1" }],
    });
    expect(new Set(legacy!.keys)).toEqual(
      new Set([...issues!.keys, ...pulls!.keys]),
    );
  });

  it("untracks every join-only stream the bindings read", () => {
    const joinOnly = new Set<string>();
    for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
      const source = scope.slice(0, scope.indexOf("."));
      for (const stream of binding.pdppStreams) {
        const storedScope = `${source}.${stream}`;
        if (!LEGACY_SCOPE_BINDINGS.has(storedScope)) joinOnly.add(storedScope);
      }
    }
    const trackedByRule = [...joinOnly].filter(
      (scope) =>
        MEMORY_RECORD_RULES[scope] !== undefined &&
        MEMORY_RECORD_RULES[scope]!.some((r) => r.rowIdFields.length > 0),
    );
    // Streams a rule tracks on purpose: each is a list of records of its own.
    expect(trackedByRule.sort()).toEqual(
      ["github.issues", "github.pull_requests", "spotify.saved_tracks"].sort(),
    );
    for (const scope of [
      "claude.messages",
      "claude.account_profile",
      "claude.project_documents",
      "chatgpt.messages",
      "instagram.post_likes",
      "spotify.playlist_items",
      "github.user",
      "amazon.order_items",
      "heb.order_items",
      "wholefoods.order_items",
    ]) {
      expect(MEMORY_RECORD_RULES[scope]).toEqual([]);
    }
  });
});
