import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import instagramProfileEmpty from "./__fixtures__/instagram.profile.empty.json";
import instagramProfileLarge from "./__fixtures__/instagram.profile.large.json";
import instagramProfileSmall from "./__fixtures__/instagram.profile.small.json";
import amazonPdppInput from "./__fixtures__/amazon.orders.pdpp-input.json";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import amazonOrdersSchema from "./legacy-schemas/amazon.orders.json";
import chatgptConversationsSchema from "./legacy-schemas/chatgpt.conversations.json";
import chatgptMemoriesSchema from "./legacy-schemas/chatgpt.memories.json";
import githubRepositoriesSchema from "./legacy-schemas/github.repositories.json";
import githubStarredSchema from "./legacy-schemas/github.starred.json";
import instagramProfileSchema from "./legacy-schemas/instagram.profile.json";
import instagramPostsSchema from "./legacy-schemas/instagram.posts.json";
import instagramPostLikesFixture from "./__fixtures__/instagram-post-likes-projection.json";
import instagramAdsSchema from "./legacy-schemas/instagram.ads.json";
import instagramFollowingSchema from "./legacy-schemas/instagram.following.json";
import githubHistorySchema from "./legacy-schemas/github.history.json";
import githubProfileSchema from "./legacy-schemas/github.profile.json";
import githubEventsSchema from "./legacy-schemas/github.events.json";
import githubContributionsSchema from "./legacy-schemas/github.contributions.json";
import linkedinEducationSchema from "./legacy-schemas/linkedin.education.json";
import linkedinExperienceSchema from "./legacy-schemas/linkedin.experience.json";
import linkedinLanguagesSchema from "./legacy-schemas/linkedin.languages.json";
import linkedinProfileSchema from "./legacy-schemas/linkedin.profile.json";
import linkedinSkillsSchema from "./legacy-schemas/linkedin.skills.json";
import shopOrdersSchema from "./legacy-schemas/shop.orders.json";
import ouraActivitySchema from "./legacy-schemas/oura.activity.json";
import ouraReadinessSchema from "./legacy-schemas/oura.readiness.json";
import ouraSleepSchema from "./legacy-schemas/oura.sleep.json";
import spotifyPlaylistsSchema from "./legacy-schemas/spotify.playlists.json";
import spotifyProfileSchema from "./legacy-schemas/spotify.profile.json";
import icloudNotesSchema from "./legacy-schemas/icloud_notes.notes.json";
import icloudFoldersSchema from "./legacy-schemas/icloud_notes.folders.json";
import linkedinConnectionsSchema from "./legacy-schemas/linkedin.connections.json";
import youtubeProfileSchema from "./legacy-schemas/youtube.profile.json";
import youtubeHistorySchema from "./legacy-schemas/youtube.history.json";
import youtubeSubscriptionsSchema from "./legacy-schemas/youtube.subscriptions.json";
import youtubePlaylistsSchema from "./legacy-schemas/youtube.playlists.json";
import youtubePlaylistItemsSchema from "./legacy-schemas/youtube.playlistItems.json";
import youtubeLikesSchema from "./legacy-schemas/youtube.likes.json";
import youtubeWatchLaterSchema from "./legacy-schemas/youtube.watchLater.json";
import spotifySavedTracksSchema from "./legacy-schemas/spotify.savedTracks.json";
import requestedScopeFixtures from "./__fixtures__/requested-scope-projections.json";
import type { PdppRecord } from "./types.js";
import claudeProjectionFixture from "./__fixtures__/claude-projection.json";
import claudeConversationsSchema from "./legacy-schemas/claude.conversations.json";
import claudeProjectsSchema from "./legacy-schemas/claude.projects.json";

const ajv = new Ajv({ allErrors: true, strict: false });

function validateAgainst(
  schemaDoc: { schema: unknown },
  payload: unknown,
): void {
  const validate = ajv.compile(schemaDoc.schema as Record<string, unknown>);
  const valid = validate(payload);
  expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
}

describe("Vana legacy payload compatibility contract", () => {
  it("records the fields emitted by the legacy ChatGPT and Shop collectors", () => {
    const chatgptProperties =
      chatgptConversationsSchema.schema.properties.conversations.items
        .properties;
    expect(chatgptProperties).toMatchObject({
      create_time: { type: ["string", "number", "null"] },
      update_time: { type: ["string", "number", "null"] },
      fetched_at: { type: "string" },
    });
    expect(shopOrdersSchema.schema.properties).toMatchObject({
      total: { type: "number" },
    });
  });

  it("accepts numeric and null ChatGPT timestamps emitted by the legacy collector", () => {
    const validate = ajv.compile(
      chatgptConversationsSchema.schema as Record<string, unknown>,
    );
    const payload = {
      conversations: [
        {
          id: "conversation-1",
          title: "Legacy conversation",
          create_time: 1_000,
          update_time: null,
          fetched_at: "2026-09-25T00:00:00.000Z",
          message_count: 0,
          messages: [],
        },
      ],
      total: 1,
    };

    expect(validate(payload), JSON.stringify(validate.errors, null, 2)).toBe(
      true,
    );
    expect(
      validate({
        ...payload,
        conversations: [
          {
            ...payload.conversations[0],
            create_time: null,
            update_time: 2_000,
          },
        ],
      }),
      JSON.stringify(validate.errors, null, 2),
    ).toBe(true);
    expect(
      validate({
        ...payload,
        conversations: [
          {
            ...payload.conversations[0],
            create_time: "2026-09-24T00:00:00.000Z",
            update_time: "2026-09-25T00:00:00.000Z",
          },
        ],
      }),
      JSON.stringify(validate.errors, null, 2),
    ).toBe(true);
    expect(
      validate({
        ...payload,
        conversations: [{ ...payload.conversations[0], unexpected: true }],
      }),
    ).toBe(false);
    expect(validate.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          keyword: "additionalProperties",
          params: expect.objectContaining({ additionalProperty: "unexpected" }),
        }),
      ]),
    );
  });
});

/** Deep-sorts object keys so two structurally-equal payloads compare equal byte-for-byte after JSON.stringify. */
function normalizeKeyOrder(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(normalizeKeyOrder);
  }
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = normalizeKeyOrder((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

function assertByteForByte(actual: unknown, expected: unknown): void {
  expect(JSON.stringify(normalizeKeyOrder(actual))).toBe(
    JSON.stringify(normalizeKeyOrder(expected)),
  );
}

describe("legacyScopeToPdppSelection", () => {
  it("translates a known legacy scope to its PDPP selection, source as the connector_id URI (B5)", () => {
    const result = legacyScopeToPdppSelection("github.repositories");
    expect(result).toEqual({
      ok: true,
      selection: {
        source: "https://registry.pdpp.dev/connectors/github",
        streams: ["repositories"],
      },
    });
  });

  it("returns a typed error for an unknown scope, never a guess", () => {
    const result = legacyScopeToPdppSelection("totally.unheard.of");
    expect(result).toEqual({
      ok: false,
      error: { kind: "unknown_scope", scope: "totally.unheard.of" },
    });
  });

  it("does not prefix-match: a scope one character off a real one is unknown", () => {
    const result = legacyScopeToPdppSelection("github.repositorie");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.kind).toBe("unknown_scope");
    }
  });

  for (const [scope, reasonFragment] of [
    ["poc.spoof.1786512520782", "proof-of-concept"],
    ["r2.pending-revoke.1789618962059", "revocation-flow"],
    ["seedbot.alpha", "seedbot"],
    ["write:demo.answer", "grammar"],
  ] as const) {
    it(`classifies production test-debris scope "${scope}" explicitly, not as unknown`, () => {
      const result = legacyScopeToPdppSelection(scope);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.kind).toBe("test_debris_scope");
        if (result.error.kind === "test_debris_scope") {
          expect(result.error.reason).toContain(reasonFragment);
        }
      }
    });
  }

  // B4: LEGACY_SCOPE_BINDINGS is a Map, so prototype-chain property names
  // are never mistaken for scopes. `.get()` on a Map only ever returns an
  // entry actually `.set()` on it.
  for (const prototypeKey of [
    "constructor",
    "toString",
    "__proto__",
    "hasOwnProperty",
  ]) {
    it(`treats prototype-chain key "${prototypeKey}" as an unknown scope, not a match (B4)`, () => {
      const result = legacyScopeToPdppSelection(prototypeKey);
      expect(result).toEqual({
        ok: false,
        error: { kind: "unknown_scope", scope: prototypeKey },
      });
    });
  }
});

describe("projectPdppRecordsToLegacyPayload", () => {
  it("projects Claude browser-export records with verified metadata and retained conversation/document semantics", () => {
    const conversationRecords = claudeProjectionFixture[
      "claude.conversations"
    ] as PdppRecord[];
    const conversation = projectPdppRecordsToLegacyPayload(
      "claude.conversations",
      conversationRecords,
      {
        fetchedStreams: ["account_profile", "conversations", "messages"],
      },
    );
    expect(conversation.ok).toBe(true);
    if (conversation.ok) {
      validateAgainst(claudeConversationsSchema, conversation.payload);
      expect(conversation.payload).toMatchObject({
        profile: { name: "Ada Example", plan: "Pro" },
        organizationId: "org-1",
        total: 1,
        messageTotal: 2,
        source: "official-export",
        conversations: [
          {
            id: "chat-1",
            href: "/chat/chat-1",
            messageCount: 2,
            messages: [
              { id: "message-1", content: "Question" },
              { id: "message-2", content: "Answer" },
            ],
          },
        ],
      });
    }

    const projectRecords = claudeProjectionFixture[
      "claude.projects"
    ] as PdppRecord[];
    const projects = projectPdppRecordsToLegacyPayload(
      "claude.projects",
      projectRecords,
      {
        fetchedStreams: ["account_profile", "projects", "project_documents"],
      },
    );
    expect(projects.ok).toBe(true);
    if (projects.ok) {
      validateAgainst(claudeProjectsSchema, projects.payload);
      expect(projects.payload).toMatchObject({
        profile: { name: null, plan: null },
        organizationId: "org-1",
        total: 1,
        source: "official-export",
        projects: [
          {
            id: "project-1",
            href: "/project/project-1",
            detail: {
              docs: [
                {
                  uuid: "doc-1",
                  filename: "brief.md",
                  content: "Source text",
                  created_at: null,
                },
              ],
            },
          },
        ],
      });
      expect(
        (
          projects.payload as {
            projects: { detail: Record<string, unknown> }[];
          }
        ).projects[0].detail,
      ).not.toHaveProperty("documents");
    }
  });

  it("uses the legacy title fallback and fails closed without exactly one profile", () => {
    const records = claudeProjectionFixture[
      "claude.conversations"
    ] as PdppRecord[];
    const missingTitle = records.map((record) =>
      record.stream === "conversations"
        ? { ...record, data: { ...record.data, title: null } }
        : record,
    );
    // copy-assertion-ok: "Untitled" is the retained Claude collector's specified fallback for a null title.
    expect(
      projectPdppRecordsToLegacyPayload("claude.conversations", missingTitle, {
        fetchedStreams: ["account_profile", "conversations", "messages"],
      }),
    ).toMatchObject({
      ok: true,
      payload: { conversations: [{ title: "Untitled" }] },
    });
    expect(
      projectPdppRecordsToLegacyPayload("claude.projects", [], {
        fetchedStreams: ["account_profile", "projects", "project_documents"],
      }),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "claude.projects" },
    });
    expect(
      projectPdppRecordsToLegacyPayload(
        "claude.conversations",
        [...records, records[0]],
        {
          fetchedStreams: ["account_profile", "conversations", "messages"],
        },
      ),
    ).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "claude.conversations" },
    });
  });

  it("projects empty Claude content with one 0.1.3 profile in each scope", () => {
    for (const [scope, streams] of [
      [
        "claude.conversations",
        ["account_profile", "conversations", "messages"],
      ],
      ["claude.projects", ["account_profile", "projects", "project_documents"]],
    ] as const) {
      const profile = {
        stream: "account_profile",
        data: {
          id: "org-1",
          organization_id: "org-1",
          full_name: null,
          plan: null,
          name_source: "none",
          metadata_status: "absent",
        },
      };
      const result = projectPdppRecordsToLegacyPayload(scope, [profile], {
        fetchedStreams: [...streams],
      });
      expect(result).toMatchObject({
        ok: true,
        payload: { total: 0, profile: { name: null, plan: null } },
      });
      expect(
        projectPdppRecordsToLegacyPayload(scope, [], {
          fetchedStreams: [...streams],
        }),
      ).toMatchObject({
        ok: false,
        error: { kind: "incomplete_scope", scope },
      });
      expect(
        projectPdppRecordsToLegacyPayload(scope, [profile, profile], {
          fetchedStreams: [...streams],
        }),
      ).toMatchObject({
        ok: false,
        error: { kind: "incomplete_scope", scope },
      });
      expect(
        projectPdppRecordsToLegacyPayload(
          scope,
          [{ ...profile, data: { ...profile.data, organization_id: "other" } }],
          { fetchedStreams: [...streams] },
        ),
      ).toMatchObject({ ok: false, error: { kind: "invalid_value", scope } });
      expect(
        projectPdppRecordsToLegacyPayload(
          scope,
          [
            {
              ...profile,
              data: { ...profile.data, metadata_status: "unknown" },
            },
          ],
          { fetchedStreams: [...streams] },
        ),
      ).toMatchObject({ ok: false, error: { kind: "invalid_value", scope } });
    }
  });

  it("retains nullable Instagram posts alongside complete posts", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "instagram.posts",
      [
        {
          stream: "posts",
          data: {
            id: "good",
            media_url: "https://example.test/good.jpg",
            caption: "Good",
            like_count: 1,
          },
        },
        {
          stream: "posts",
          data: {
            id: "dropped",
            media_url: null,
            caption: null,
            like_count: null,
          },
        },
      ],
      { fetchedStreams: ["posts", "post_likes"] },
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        posts: [
          {
            img_url: "https://example.test/good.jpg",
            caption: "Good",
            num_of_likes: 1,
          },
          { img_url: "", caption: "", num_of_likes: 0 },
        ],
      },
    });
  });

  it("rejects an unavailable source identity", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "instagram.posts",
      [
        {
          stream: "posts",
          data: {
            id: null,
            media_url: "https://example.test/post.jpg",
            caption: "Good",
            like_count: 1,
          },
        },
      ],
      { fetchedStreams: ["posts", "post_likes"] },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "instagram.posts" },
    });
  });

  it("projects declaration-backed YouTube records into each retained legacy scope", () => {
    const examples: [string, PdppRecord[], string[], { schema: unknown }][] = [
      [
        "youtube.profile",
        [
          {
            stream: "profile",
            data: {
              id: "channel-1",
              channel_url: "https://youtube.com/@owner",
              title: "Owner",
              handle: "@owner",
              email: null,
              joined_at: null,
              avatar_url: null,
              description: "About",
              country: "US",
              subscriber_count: 12,
              view_count: 300,
              video_count: 4,
            },
          },
        ],
        ["profile"],
        youtubeProfileSchema,
      ],
      [
        "youtube.subscriptions",
        [
          {
            stream: "subscriptions",
            data: {
              id: "sub-1",
              channel_id: "channel-2",
              channel_title: "Subscribed",
              channel_url: "https://youtube.com/@subscribed",
              handle: null,
              avatar_url: null,
              subscriber_count: 8,
              description: null,
              is_verified: false,
              notifications: true,
            },
          },
        ],
        ["subscriptions"],
        youtubeSubscriptionsSchema,
      ],
      [
        "youtube.playlists",
        [
          {
            stream: "playlists",
            data: {
              id: "playlist-1",
              url: "https://youtube.com/playlist?list=1",
              title: "List",
              owner: null,
              owner_url: null,
              visibility: "Private",
              video_count: 1,
              view_count: 0,
            },
          },
        ],
        ["playlists"],
        youtubePlaylistsSchema,
      ],
      [
        "youtube.playlistItems",
        [
          {
            stream: "playlist_items",
            data: {
              id: "item-1",
              playlist_id: "playlist-1",
              video_id: "video-1",
              video_url: "https://youtube.com/watch?v=video-1",
              video_title: "Video",
              channel_title: "Channel",
              channel_url: null,
              duration_seconds: 65,
              thumbnail_url: null,
            },
          },
        ],
        ["playlist_items"],
        youtubePlaylistItemsSchema,
      ],
      [
        "youtube.likes",
        [
          {
            stream: "likes",
            data: {
              id: "like-1",
              video_id: "video-1",
              video_url: "https://youtube.com/watch?v=video-1",
              video_title: "Video",
              channel_title: null,
              channel_url: null,
              duration_seconds: null,
              thumbnail_url: null,
            },
          },
        ],
        ["likes"],
        youtubeLikesSchema,
      ],
      [
        "youtube.watchLater",
        [
          {
            stream: "watch_later",
            data: {
              id: "later-1",
              video_id: "video-1",
              video_url: "https://youtube.com/watch?v=video-1",
              video_title: "Video",
              channel_title: null,
              channel_url: null,
              duration_seconds: null,
              thumbnail_url: null,
            },
          },
        ],
        ["watch_later"],
        youtubeWatchLaterSchema,
      ],
      [
        "youtube.history",
        [
          {
            stream: "watch_history",
            data: {
              id: "history-1",
              position: 0,
              watched_date: "2026-09-23",
              video_id: "video-1",
              video_url: "https://youtube.com/watch?v=video-1",
              video_title: "Video",
              channel_title: "Channel",
              channel_url: null,
              view_count: 42,
              description: "Description",
            },
          },
        ],
        ["watch_history"],
        youtubeHistorySchema,
      ],
    ];

    for (const [scope, records, fetchedStreams, schema] of examples) {
      expect(
        legacyScopeToPdppSelection(scope, { profileKey: "youtube" }),
      ).toEqual({
        ok: true,
        selection: {
          source: "https://registry.pdpp.dev/connectors/youtube",
          streams: fetchedStreams,
        },
      });
      const result = projectPdppRecordsToLegacyPayload(scope, records, {
        fetchedStreams,
        profileKey: "youtube",
      });
      expect(result.ok, `${scope}: ${JSON.stringify(result)}`).toBe(true);
      if (result.ok) validateAgainst(schema, result.payload);
    }
  });

  it("preserves browser history page order and day-only dates", () => {
    const records: PdppRecord[] = Array.from({ length: 55 }, (_, index) => ({
      stream: "watch_history",
      data: {
        id: `history-${index}`,
        position: index,
        watched_date: "2026-09-23",
        video_id: `video-${index}`,
        video_url: `https://youtube.com/watch?v=${index}`,
        video_title: `Video ${index}`,
        channel_title: null,
        channel_url: null,
        view_count: index,
        description: null,
      },
    }));
    records.push({
      stream: "watch_history",
      data: {
        id: "missing-url",
        position: 55,
        watched_date: "2026-09-23",
        video_url: null,
      },
    });

    const result = projectPdppRecordsToLegacyPayload(
      "youtube.history",
      records,
      { fetchedStreams: ["watch_history"] },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope", scope: "youtube.history" },
    });

    const complete = projectPdppRecordsToLegacyPayload(
      "youtube.history",
      records.slice(0, -1),
      { fetchedStreams: ["watch_history"] },
    );
    expect(complete.ok).toBe(true);
    if (complete.ok) {
      validateAgainst(youtubeHistorySchema, complete.payload);
      const history = complete.payload.history as Record<string, unknown>[];
      expect(history).toHaveLength(50);
      expect(history[0]).toMatchObject({
        videoId: "video-0",
        watchedAtText: "2026-09-23",
        views: "0 views",
      });
      expect(history[49]).toMatchObject({ videoId: "video-49" });
      // copy-assertion-ok: this exact timeWindow value is part of the retained legacy payload contract.
      expect(complete.payload.timeWindow).toBe("top 50 most recent items");
    }
  });

  it("fails explicitly when browser history position is absent", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "youtube.history",
      [
        {
          stream: "watch_history",
          data: { id: "h1", video_url: "https://youtube.com/watch?v=1" },
        },
      ],
      { fetchedStreams: ["watch_history"] },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { kind: "invalid_value", scope: "youtube.history" },
    });
  });

  it("skips YouTube rows that cannot satisfy legacy required fields", () => {
    const cases = [
      [
        "youtube.subscriptions",
        "subscriptions",
        {
          id: "s1",
          channel_title: null,
          channel_url: null,
          is_verified: null,
          notifications: null,
        },
      ],
      ["youtube.playlists", "playlists", { id: "p1", url: null }],
      [
        "youtube.playlistItems",
        "playlist_items",
        { id: "i1", playlist_id: "p1", video_url: null, video_title: null },
      ],
      [
        "youtube.likes",
        "likes",
        {
          id: "l1",
          video_url: "https://youtube.com/watch?v=1",
          video_title: null,
        },
      ],
      [
        "youtube.watchLater",
        "watch_later",
        {
          id: "w1",
          video_url: "https://youtube.com/watch?v=1",
          video_title: null,
        },
      ],
    ] as const;
    for (const [scope, stream, data] of cases) {
      const result = projectPdppRecordsToLegacyPayload(
        scope,
        [{ stream, data }],
        { fetchedStreams: [stream] },
      );
      expect(result, scope).toMatchObject({
        ok: false,
        error: { kind: "incomplete_scope", scope },
      });
    }
  });

  it("projects the six requested scopes from fixture records into their retained legacy schemas", () => {
    const cases = [
      ["chatgpt.memories", chatgptMemoriesSchema],
      ["icloud_notes.folders", icloudFoldersSchema],
      ["linkedin.connections", linkedinConnectionsSchema],
      ["oura.activity", ouraActivitySchema],
      ["oura.sleep", ouraSleepSchema],
      ["spotify.savedTracks", spotifySavedTracksSchema],
    ] as const;

    for (const [scope, schema] of cases) {
      const records = requestedScopeFixtures[scope] as PdppRecord[];
      const binding = LEGACY_SCOPE_BINDINGS.get(scope);
      expect(binding, `${scope} binding`).toBeDefined();
      const result = projectPdppRecordsToLegacyPayload(scope, records, {
        fetchedStreams: binding?.pdppStreams ?? [],
      });
      expect(result.ok, `${scope}: ${JSON.stringify(result)}`).toBe(true);
      if (result.ok) validateAgainst(schema, result.payload);
    }

    const folders = projectPdppRecordsToLegacyPayload(
      "icloud_notes.folders",
      requestedScopeFixtures["icloud_notes.folders"] as PdppRecord[],
      { fetchedStreams: ["folders"] },
    );
    expect(folders).toMatchObject({
      ok: true,
      payload: {
        folders: [{ recordName: "folder-1", title: "Work" }],
        total: 1,
      },
    });

    const connections = projectPdppRecordsToLegacyPayload(
      "linkedin.connections",
      requestedScopeFixtures["linkedin.connections"] as PdppRecord[],
      { fetchedStreams: ["connections"] },
    );
    expect(connections).toMatchObject({
      ok: true,
      payload: {
        connections: [{ fullName: "Ada Example", dateConnected: "2026-09-03" }],
      },
    });
  });

  describe("instagram.following", () => {
    it("projects declared following fields and validates against the retained schema", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.following",
        [
          {
            stream: "following",
            data: {
              id: "u-1",
              username: "ava",
              full_name: "Ava Example",
              is_private: true,
              is_verified: false,
              profile_pic_url: null,
            },
          },
          {
            stream: "following",
            data: {
              id: "u-2",
              username: "ben",
              full_name: null,
              is_private: null,
              is_verified: null,
              profile_pic_url: "",
            },
          },
          {
            stream: "following",
            data: { id: "u-3", username: "" },
          },
        ],
        { fetchedStreams: ["following"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(instagramFollowingSchema, result.payload);
        expect(result.payload).toEqual({
          accounts: [
            {
              username: "ava",
              pk: "u-1",
              full_name: "Ava Example",
              is_private: true,
              is_verified: false,
              profile_pic_url: null,
            },
            {
              username: "ben",
              pk: "u-2",
              full_name: "",
              is_private: false,
              is_verified: false,
              profile_pic_url: null,
            },
          ],
          total: 2,
        });
      }
    });
  });

  describe("instagram.ads", () => {
    it("routes declared kinds into the three retained legacy collections", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.ads",
        [
          {
            stream: "ads",
            data: { id: "a1", kind: "advertiser", name: "Acme" },
          },
          {
            stream: "ads",
            data: { id: "t1", kind: "ad_topic", name: "Travel" },
          },
          {
            stream: "ads",
            data: {
              id: "c1",
              kind: "ad_category",
              name: "Sports",
              description: "Interest group",
            },
          },
        ],
        { fetchedStreams: ["ads"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(instagramAdsSchema, result.payload);
        expect(result.payload).toEqual({
          advertisers: [{ name: "Acme" }],
          ad_topics: [{ name: "Travel" }],
          categories: [{ name: "Sports", description: "Interest group" }],
        });
      }
    });
  });

  describe("github.history", () => {
    it("projects authored issue and pull request records, filters assigned-only issues, and validates", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.history",
        [
          { stream: "user", data: { id: "me", login: "ava" } },
          {
            stream: "issues",
            data: {
              id: "i1",
              number: 4,
              title: "Bug",
              body: "details",
              state: "closed",
              user_login: "ava",
              labels: ["bug"],
              repository_full_name: "ava/repo",
              html_url: "https://github.com/ava/repo/issues/4",
              comments: 2,
              reactions_total_count: 3,
              created_at: "2026-01-01T00:00:00Z",
              updated_at: "2026-01-02T00:00:00Z",
              closed_at: "2026-01-03T00:00:00Z",
              is_pull_request: false,
            },
          },
          {
            stream: "issues",
            data: {
              id: "assigned",
              user_login: "other",
              repository_full_name: "ava/repo",
              is_pull_request: false,
            },
          },
          {
            stream: "pull_requests",
            data: {
              id: "p1",
              number: 5,
              title: "Fix",
              state: "open",
              labels: [],
              repository_full_name: "ava/repo",
              html_url: "https://github.com/ava/repo/pull/5",
              comments: 1,
              reactions_total_count: 0,
              created_at: "2026-01-04T00:00:00Z",
              updated_at: "2026-01-05T00:00:00Z",
              closed_at: null,
              merged_at: null,
              draft: true,
            },
          },
        ],
        { fetchedStreams: ["user", "issues", "pull_requests"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubHistorySchema, result.payload);
        expect(result.payload).toMatchObject({
          issues: [
            { id: "i1", type: "issue", repo: "ava/repo", labels: ["bug"] },
          ],
          pullRequests: [
            { id: "p1", type: "pr", repo: "ava/repo", isDraft: true },
          ],
        });
        expect(result.payload.issues).toHaveLength(1);
      }
    });

    it("projects a fetched empty history without a user record, but refuses issues without an author identity", () => {
      const fetchedStreams = ["user", "issues", "pull_requests"];
      const empty = projectPdppRecordsToLegacyPayload("github.history", [], {
        fetchedStreams,
      });
      expect(empty.ok).toBe(true);
      if (empty.ok) validateAgainst(githubHistorySchema, empty.payload);

      const unknownAuthor = projectPdppRecordsToLegacyPayload(
        "github.history",
        [{ stream: "issues", data: { id: "assigned", user_login: "other" } }],
        { fetchedStreams },
      );
      expect(unknownAuthor).toMatchObject({
        ok: false,
        error: { kind: "invalid_value", scope: "github.history" },
      });
    });
  });

  describe("GitHub profile, events, and contributions", () => {
    it("projects profile fields from the declared profile, stats, pins, and organization streams", () => {
      const records: PdppRecord[] = [
        {
          stream: "user",
          data: {
            id: "u1",
            login: "octocat",
            name: "Octo Cat",
            achievements: [{ name: "YOLO", icon_url: null }],
          },
        },
        {
          stream: "user_stats",
          data: {
            id: "u1:2026-09-22",
            observed_on: "2026-09-22",
            followers: 12,
            following: 8,
            public_repos: 4,
          },
        },
        {
          stream: "user_stats",
          data: {
            id: "u1:2026-09-23",
            observed_on: "2026-09-23",
            followers: 13,
            following: 9,
            public_repos: 5,
          },
        },
        {
          stream: "pinned_repositories",
          data: {
            id: "r1",
            full_name: "octocat/hello",
            html_url: "https://github.com/octocat/hello",
            description: "Hi",
            languages: ["TypeScript"],
            stargazers_count: 7,
          },
        },
        {
          stream: "organizations",
          data: {
            id: "o1",
            login: "octo-org",
            description: "Octo org",
            avatar_url: null,
          },
        },
      ];
      const result = projectPdppRecordsToLegacyPayload(
        "github.profile",
        records,
        {
          fetchedStreams:
            LEGACY_SCOPE_BINDINGS.get("github.profile")!.pdppStreams,
        },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubProfileSchema, result.payload);
        expect(result.payload).toMatchObject({
          username: "octocat",
          profileUrl: "https://github.com/octocat",
          fullName: "Octo Cat",
          followers: 13,
          following: 9,
          repositoryCount: 5,
          achievements: [{ name: "YOLO", iconUrl: null }],
          pinnedRepositories: [
            { fullName: "octocat/hello", language: "TypeScript", stars: 7 },
          ],
          organizations: [{ login: "octo-org", avatarUrl: null }],
        });
        expect(
          (result.payload.organizations as unknown[])[0],
        ).not.toHaveProperty("label");
        expect(result.payload).not.toHaveProperty("contributionsLastYear");
      }
    });

    it("projects only fields carried by public event records", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.events",
        [
          {
            stream: "events",
            data: {
              id: "e1",
              type: "PushEvent",
              created_at: "2026-09-23T12:00:00Z",
              repository_full_name: "octocat/hello",
              is_public: true,
            },
          },
        ],
        { fetchedStreams: ["events"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubEventsSchema, result.payload);
        expect(result.payload.events).toEqual([
          {
            id: "e1",
            type: "PushEvent",
            createdAt: "2026-09-23T12:00:00Z",
            repo: "octocat/hello",
            isPublic: true,
          },
        ]);
        expect(result.payload.events).not.toHaveProperty("action");
      }
    });

    it("projects daily contribution counts without claiming incomplete aggregates", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.contributions",
        [
          {
            stream: "contributions",
            data: {
              id: "u1:2026-09-22",
              user_id: "u1",
              date: "2026-09-22",
              contribution_count: 3,
            },
          },
          {
            stream: "contributions",
            data: {
              id: "u1:2026-09-23",
              user_id: "u1",
              date: "2026-09-23",
              contribution_count: 0,
            },
          },
        ],
        { fetchedStreams: ["contributions"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubContributionsSchema, result.payload);
        expect(result.payload.days).toEqual([
          { date: "2026-09-22", count: 3 },
          { date: "2026-09-23", count: 0 },
        ]);
        expect(result.payload).not.toHaveProperty("totalContributionsLastYear");
        expect(result.payload).not.toHaveProperty("monthlyTotals");
      }
    });
  });

  it("selects the declared Claude streams for both retained legacy scopes", () => {
    expect(legacyScopeToPdppSelection("claude.conversations")).toEqual({
      ok: true,
      selection: {
        source: "https://registry.pdpp.dev/connectors/anthropic",
        streams: ["account_profile", "conversations", "messages"],
      },
    });
    expect(legacyScopeToPdppSelection("claude.projects")).toEqual({
      ok: true,
      selection: {
        source: "https://registry.pdpp.dev/connectors/anthropic",
        streams: ["account_profile", "projects", "project_documents"],
      },
    });
  });

  it("selects order history, order items, and nutrition for H-E-B nutrition", () => {
    expect(legacyScopeToPdppSelection("heb.nutrition")).toEqual({
      ok: true,
      selection: {
        source: "https://registry.pdpp.dev/connectors/heb",
        streams: ["nutrition", "orders", "order_items"],
      },
    });
  });

  it("projects Oura activity fields from the current declaration and validates against the legacy schema", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.activity",
      [
        {
          stream: "activity",
          data: {
            id: "activity-1",
            day: "2026-09-01",
            score: 83,
            active_calories: 420,
            total_calories: 2100,
            steps: 8500,
            equivalent_walking_distance: 6200,
            high_activity_time: 900,
            medium_activity_time: 1800,
            low_activity_time: 2700,
            sedentary_time: 3600,
            resting_time: 1800,
            inactivity_alerts: 1,
            contributors: {},
          },
        },
      ],
      { fetchedStreams: ["activity"] },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      validateAgainst(ouraActivitySchema, result.payload);
      expect(result.payload).toMatchObject({
        days: [{ id: "activity-1", day: "2026-09-01", score: 83, steps: 8500 }],
      });
    }
  });

  it("projects Oura readiness fields from the current declaration and validates against the legacy schema", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.readiness",
      [
        {
          stream: "readiness",
          data: {
            id: "readiness-1",
            day: "2026-09-01",
            score: 78,
            temperature_deviation: 0.2,
            temperature_trend_deviation: 0.1,
            contributors: {},
          },
        },
      ],
      { fetchedStreams: ["readiness"] },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      validateAgainst(ouraReadinessSchema, result.payload);
      expect(result.payload).toMatchObject({
        days: [
          {
            id: "readiness-1",
            day: "2026-09-01",
            score: 78,
            temperatureDeviation: 0.2,
          },
        ],
      });
    }
  });

  it("projects Oura sleep scores and periods from the current declaration and validates against the legacy schema", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            id: "sleep-1",
            day: "2026-09-01",
            sleep_score: 82,
            type: "long_sleep",
            contributors: { deep_sleep: 80 },
            bedtime_start: "2026-09-01T00:00:00Z",
            bedtime_end: "2026-09-01T08:00:00Z",
            total_sleep_duration: 27000,
            time_in_bed: 28800,
            deep_sleep_duration: 5000,
            light_sleep_duration: 12000,
            rem_sleep_duration: 10000,
            efficiency: 94,
            latency: 600,
            average_heart_rate: 52,
            average_hrv: 45,
            lowest_heart_rate: 42,
            average_breath: 14.2,
            restless_periods: 2,
          },
        },
      ],
      { fetchedStreams: ["sleep"] },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      validateAgainst(ouraSleepSchema, result.payload);
      expect(result.payload).toMatchObject({
        dailyScores: [{ id: "sleep-1", day: "2026-09-01", score: 82 }],
        sleepPeriods: [{ id: "sleep-1", timeInBed: 28800, averageHrv: 45 }],
      });
    }
  });

  it("keeps one separate Oura Browser daily score when attached to multiple same-day sleep sessions", () => {
    const score = { deep_sleep: 80 };
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            record_type: "sleep_session",
            id: "session-1",
            day: "2026-09-01",
            sleep_score: 82,
            contributors: score,
            type: "long_sleep",
            total_sleep_duration: 27000,
          },
        },
        {
          stream: "sleep",
          data: {
            record_type: "sleep_session",
            id: "session-2",
            day: "2026-09-01",
            sleep_score: 82,
            contributors: score,
            type: "rest",
            total_sleep_duration: 1800,
          },
        },
        {
          stream: "sleep",
          data: {
            record_type: "daily_score",
            id: "daily-1",
            daily_sleep_id: "daily-1",
            daily_sleep_timestamp: "2026-09-01T07:00:00Z",
            day: "2026-09-01",
            sleep_score: 82,
            contributors: score,
          },
        },
      ],
      { fetchedStreams: ["sleep"], profileKey: "oura-browser" },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        dailyScores: [
          {
            id: "daily-1",
            day: "2026-09-01",
            score: 82,
            timestamp: "2026-09-01T07:00:00Z",
            contributors: score,
          },
        ],
        sleepPeriods: [
          expect.objectContaining({ id: "session-1", day: "2026-09-01" }),
          expect.objectContaining({ id: "session-2", day: "2026-09-01" }),
        ],
      },
    });
    if (result.ok) validateAgainst(ouraSleepSchema, result.payload);
  });

  it("projects signed Oura Browser score records separately from sessions, preserving multiple scores on one day", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            record_type: "daily_score",
            id: "daily-2a",
            day: "2026-09-02",
            sleep_score: 77,
            daily_sleep_id: "daily-2a",
            daily_sleep_timestamp: "2026-09-02T07:00:00Z",
          },
        },
        {
          stream: "sleep",
          data: {
            record_type: "daily_score",
            id: "daily-2b",
            day: "2026-09-02",
            sleep_score: 79,
            daily_sleep_id: "daily-2b",
            daily_sleep_timestamp: "2026-09-02T08:00:00Z",
          },
        },
        {
          stream: "sleep",
          data: {
            record_type: "sleep_session",
            id: "session-3",
            day: "2026-09-03",
            sleep_score: 81,
            daily_sleep_id: "daily-3",
            daily_sleep_timestamp: "2026-09-03T07:00:00Z",
            awake_time: 1200,
          },
        },
        {
          stream: "sleep",
          data: {
            record_type: "daily_score",
            id: "daily-3",
            day: "2026-09-03",
            sleep_score: 81,
            daily_sleep_id: "daily-3",
            daily_sleep_timestamp: "2026-09-03T07:00:00Z",
          },
        },
      ],
      { fetchedStreams: ["sleep"], profileKey: "oura-browser" },
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        dailyScores: [
          {
            id: "daily-2a",
            day: "2026-09-02",
            score: 77,
            timestamp: "2026-09-02T07:00:00Z",
          },
          {
            id: "daily-2b",
            day: "2026-09-02",
            score: 79,
            timestamp: "2026-09-02T08:00:00Z",
          },
          {
            id: "daily-3",
            day: "2026-09-03",
            score: 81,
            timestamp: "2026-09-03T07:00:00Z",
          },
        ],
        sleepPeriods: [{ id: "session-3", awakeTime: 1200 }],
      },
    });
    if (result.ok) validateAgainst(ouraSleepSchema, result.payload);
  });

  it("projects an Oura Browser score-only date as a daily score without a sleep period", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "oura.sleep",
      [
        {
          stream: "sleep",
          data: {
            record_type: "daily_score",
            id: "daily-4",
            day: "2026-09-04",
            sleep_score: 73,
            daily_sleep_id: "daily-4",
            daily_sleep_timestamp: "2026-09-04T07:00:00Z",
          },
        },
      ],
      { fetchedStreams: ["sleep"], profileKey: "oura-browser" },
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        dailyScores: [
          {
            id: "daily-4",
            day: "2026-09-04",
            score: 73,
            timestamp: "2026-09-04T07:00:00Z",
          },
        ],
        sleepPeriods: [],
      },
    });
    if (result.ok) validateAgainst(ouraSleepSchema, result.payload);
  });

  it("omits absent optional Oura fields without turning undefined into schema failures", () => {
    const cases = [
      {
        scope: "oura.activity",
        stream: "activity",
        data: { id: "activity-min", day: "2026-09-01", score: null },
        schema: ouraActivitySchema,
      },
      {
        scope: "oura.readiness",
        stream: "readiness",
        data: { id: "readiness-min", day: "2026-09-01", score: null },
        schema: ouraReadinessSchema,
      },
      {
        scope: "oura.sleep",
        stream: "sleep",
        data: { id: "sleep-min", day: "2026-09-01", sleep_score: null },
        schema: ouraSleepSchema,
      },
    ];
    for (const entry of cases) {
      const result = projectPdppRecordsToLegacyPayload(
        entry.scope,
        [{ stream: entry.stream, data: entry.data }],
        { fetchedStreams: [entry.stream] },
      );
      expect(result.ok, `${entry.scope}: ${JSON.stringify(result)}`).toBe(true);
      if (result.ok) validateAgainst(entry.schema, result.payload);
    }
  });

  it("returns a typed error for an unknown scope", () => {
    const result = projectPdppRecordsToLegacyPayload("totally.unheard.of", [], {
      fetchedStreams: [],
    });
    expect(result).toEqual({
      ok: false,
      error: { kind: "unknown_scope", scope: "totally.unheard.of" },
    });
  });

  describe("icloud_notes.notes — provisional manifest", () => {
    it("joins folder names and maps nullable legacy fields into a schema-valid payload", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "icloud_notes.notes",
        [
          {
            stream: "notes",
            data: {
              id: "note-1",
              title: "A note",
              snippet: "Preview",
              folder_id: "folder-1",
              is_pinned: true,
              created_at: "2026-09-01T12:00:00Z",
              modified_at: "2026-09-02T12:00:00Z",
              has_attachments: false,
              text_content: "Body",
            },
          },
          {
            stream: "notes",
            data: {
              id: "note-2",
              title: null,
              snippet: null,
              folder_id: "missing-folder",
              is_pinned: false,
              created_at: null,
              modified_at: null,
              has_attachments: false,
              text_content: null,
            },
          },
          { stream: "folders", data: { id: "folder-1", name: "Ideas" } },
        ],
        { fetchedStreams: ["notes", "folders"] },
      );

      expect(result).toEqual({
        ok: true,
        payload: {
          notes: [
            {
              recordName: "note-1",
              title: "A note",
              snippet: "Preview",
              folder: "Ideas",
              isPinned: true,
              createdDate: "2026-09-01T12:00:00Z",
              modifiedDate: "2026-09-02T12:00:00Z",
              hasAttachments: false,
              textContent: "Body",
            },
            {
              recordName: "note-2",
              title: null,
              snippet: null,
              folder: "missing-folder",
              isPinned: false,
              createdDate: null,
              modifiedDate: null,
              hasAttachments: false,
              textContent: null,
            },
          ],
          total: 2,
          userName: null,
        },
      });
      validateAgainst(icloudNotesSchema, result.ok ? result.payload : result);
    });

    it("rejects records that violate required manifest fields and distinguishes an unfetched stream", () => {
      expect(
        projectPdppRecordsToLegacyPayload(
          "icloud_notes.notes",
          [{ stream: "notes", data: { id: "note-1", is_pinned: false } }],
          { fetchedStreams: ["notes", "folders"] },
        ),
      ).toMatchObject({
        ok: false,
        error: { kind: "invalid_value", scope: "icloud_notes.notes" },
      });
      expect(
        projectPdppRecordsToLegacyPayload("icloud_notes.notes", [], {
          fetchedStreams: ["notes"],
        }),
      ).toEqual({
        ok: false,
        error: {
          kind: "missing_stream",
          scope: "icloud_notes.notes",
          expectedStream: "folders",
        },
      });
    });
  });

  describe("instagram.posts — Meta 0.4.0 projection", () => {
    it("joins post_likes to the matching legacy post by post id", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.posts",
        instagramPostLikesFixture.sourceRecords,
        { fetchedStreams: ["posts", "post_likes"], profileKey: "meta" },
      );

      const expectedPinnedLegacyOutput = {
        posts: instagramPostLikesFixture.pinnedLegacyOutput.posts,
      };
      expect(result).toEqual({ ok: true, payload: expectedPinnedLegacyOutput });
      if (result.ok) {
        expect(
          instagramPostsSchema.schema.properties.posts.items.properties
            .who_liked.items.properties,
        ).toHaveProperty("profile_pic_url");
        validateAgainst(instagramPostsSchema, result.payload);
      }
    });

    it("maps complete and nullable records with the retained collector sentinels", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.posts",
        [
          {
            stream: "posts",
            data: {
              id: "post-with-fields",
              media_url: "https://example.test/post.jpg",
              caption: "A captured caption",
              like_count: 12,
              taken_at: "2026-09-22T12:30:00Z",
            },
          },
          {
            stream: "posts",
            data: {
              id: "post-with-empty-caption",
              media_url: "https://example.test/second.jpg",
              caption: "",
              like_count: 0,
            },
          },
          {
            stream: "posts",
            data: {
              id: "post-with-nullable-fields",
              media_url: null,
              caption: null,
              like_count: null,
            },
          },
        ],
        { fetchedStreams: ["posts", "post_likes"] },
      );

      expect(result).toMatchObject({
        ok: true,
        payload: {
          posts: [
            {
              img_url: "https://example.test/post.jpg",
              caption: "A captured caption",
              num_of_likes: 12,
            },
            {
              img_url: "https://example.test/second.jpg",
              caption: "",
              num_of_likes: 0,
            },
            { img_url: "", caption: "", num_of_likes: 0 },
          ],
        },
      });
      if (result.ok) validateAgainst(instagramPostsSchema, result.payload);
    });

    it("preserves nested liker profile pictures and empty legacy identity values", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.posts",
        [
          {
            stream: "posts",
            data: { id: "p1", media_url: "", caption: "", like_count: 0 },
          },
          {
            stream: "post_likes",
            data: {
              post_id: "p1",
              user_id: "",
              username: "",
              id: "",
              pk: "",
              profile_pic_url: "",
              liker_ordinal: 1,
            },
          },
          {
            stream: "post_likes",
            data: {
              post_id: "p1",
              user_id: "u1",
              username: "ada",
              id: "u1",
              pk: "u1",
              profile_pic_url: "https://cdn.example.test/u.jpg",
              liker_ordinal: 0,
            },
          },
        ],
        { fetchedStreams: ["posts", "post_likes"], profileKey: "meta" },
      );
      expect(result).toEqual({
        ok: true,
        payload: {
          posts: [
            {
              img_url: "",
              caption: "",
              num_of_likes: 0,
              who_liked: [
                {
                  profile_pic_url: "https://cdn.example.test/u.jpg",
                  pk: "u1",
                  username: "ada",
                  id: "u1",
                },
                { profile_pic_url: "", pk: "", username: "", id: "" },
              ],
            },
          ],
        },
      });
      if (result.ok) validateAgainst(instagramPostsSchema, result.payload);
    });

    it("retains a post whose media URL is unavailable", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.posts",
        [
          {
            stream: "posts",
            data: {
              id: "video-without-media-url",
              media_url: null,
              caption: "Video caption",
              like_count: 4,
            },
          },
        ],
        { fetchedStreams: ["posts", "post_likes"] },
      );

      expect(result).toMatchObject({
        ok: true,
        payload: {
          posts: [{ img_url: "", caption: "Video caption", num_of_likes: 4 }],
        },
      });
    });

    it("preserves a genuinely empty source timeline", () => {
      const result = projectPdppRecordsToLegacyPayload("instagram.posts", [], {
        fetchedStreams: ["posts", "post_likes"],
      });

      expect(result).toEqual({ ok: true, payload: { posts: [] } });
    });
  });

  for (const [label, fullName] of [
    ["null", null],
    ["undefined", undefined],
  ] as const) {
    it(`uses the legacy empty-string sentinel for ${label} Instagram full_name`, () => {
      const result = projectPdppRecordsToLegacyPayload(
        "instagram.profile",
        [
          {
            stream: "profile",
            data: {
              id: "profile-1",
              username: "example",
              full_name: fullName,
              bio: null,
              follower_count: null,
              following_count: null,
              is_verified: null,
            },
          },
        ],
        { fetchedStreams: ["profile"] },
      );

      expect(result).toEqual({
        ok: true,
        payload: {
          username: "example",
          full_name: "",
        },
      });
      if (result.ok) validateAgainst(instagramProfileSchema, result.payload);
    });
  }

  it("rejects non-null non-string Instagram full_name values", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "instagram.profile",
      [
        {
          stream: "profile",
          data: {
            id: "profile-1",
            username: "example",
            full_name: 123,
          },
        },
      ],
      { fetchedStreams: ["profile"] },
    );

    expect(result).toMatchObject({
      ok: false,
      error: {
        kind: "invalid_value",
        scope: "instagram.profile",
      },
    });
  });

  it("omits nullable optional profile fields and keeps provided values schema-valid", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "instagram.profile",
      [
        {
          stream: "profile",
          data: {
            id: "profile-1",
            username: "example",
            full_name: "Example User",
            bio: null,
            profile_pic_url: "https://example.test/profile.jpg",
            external_url: null,
            follower_count: null,
            following_count: 12,
            is_private: null,
            is_verified: true,
            is_business: null,
          },
        },
      ],
      { fetchedStreams: ["profile"] },
    );

    expect(result).toEqual({
      ok: true,
      payload: {
        username: "example",
        full_name: "Example User",
        profile_pic_url: "https://example.test/profile.jpg",
        following_count: 12,
        is_verified: true,
      },
    });
    if (result.ok) validateAgainst(instagramProfileSchema, result.payload);
  });

  for (const prototypeKey of [
    "constructor",
    "toString",
    "__proto__",
    "hasOwnProperty",
  ]) {
    it(`projecting prototype-chain key "${prototypeKey}" is a typed error, not a thrown TypeError (B4)`, () => {
      expect(() =>
        projectPdppRecordsToLegacyPayload(prototypeKey, [], {
          fetchedStreams: [],
        }),
      ).not.toThrow();
      const result = projectPdppRecordsToLegacyPayload(prototypeKey, [], {
        fetchedStreams: [],
      });
      expect(result).toEqual({
        ok: false,
        error: { kind: "unknown_scope", scope: prototypeKey },
      });
    });
  }

  it("projects zero repositories for the second of two orders streams that legitimately has zero rows, without treating it as missing (S2: distinct from missing_stream, using amazon's two-stream shape to make the empty case unambiguous)", () => {
    // github.repositories has exactly one stream, so "zero records tagged
    // 'repositories'" is indistinguishable from "never fetched" without an
    // explicit fetchedStreams signal — that ambiguity is exactly why
    // missing_stream exists, and the single-stream zero-row case is proven
    // directly (below, and in the github.starred/chatgpt.memories zero-row
    // tests) now that "fetched" is expressed out of band (N-B1). amazon
    // .orders has two streams, so "orders present, order_items legitimately
    // empty" is also provable: the orders stream's presence satisfies
    // requireStreams, and zero order_items records for a real order is a
    // valid state (no items), not an error.
    const result = projectPdppRecordsToLegacyPayload(
      "amazon.orders",
      [
        { stream: "orders", data: { id: "amz_1" } },
        {
          stream: "order_items",
          data: { id: "unrelated", order_id: "other" },
        },
      ],
      { fetchedStreams: ["orders", "order_items"] },
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const payload = result.payload as {
        orders: { orderId: string; items: unknown[] }[];
      };
      expect(payload.orders[0].items).toHaveLength(0);
    }
  });

  it("returns a typed missing_stream error for a list-shaped scope whose stream was never fetched at all (S2)", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "github.repositories",
      [],
      { fetchedStreams: [] },
    );
    expect(result).toEqual({
      ok: false,
      error: {
        kind: "missing_stream",
        scope: "github.repositories",
        expectedStream: "repositories",
      },
    });
  });

  it("returns a typed missing_stream error for a singleton-shaped scope with no matching record", () => {
    const result = projectPdppRecordsToLegacyPayload("instagram.profile", [], {
      fetchedStreams: [],
    });
    expect(result).toEqual({
      ok: false,
      error: {
        kind: "missing_stream",
        scope: "instagram.profile",
        expectedStream: "profile",
      },
    });
  });

  it("returns a typed missing_stream error for amazon.orders when only one of its two streams was fetched (S2)", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "amazon.orders",
      [{ stream: "orders", data: { id: "amz_1" } }],
      { fetchedStreams: ["orders"] },
    );
    expect(result).toEqual({
      ok: false,
      error: {
        kind: "missing_stream",
        scope: "amazon.orders",
        expectedStream: "order_items",
      },
    });
  });

  it("returns the real legacy empty payload for a fetched single-stream list scope with zero rows, not missing_stream (N-B1)", () => {
    const result = projectPdppRecordsToLegacyPayload("github.starred", [], {
      fetchedStreams: ["starred"],
    });
    expect(result).toEqual({ ok: true, payload: { starred: [] } });
  });

  it("returns the real legacy empty payload for chatgpt.memories with zero rows, not missing_stream (N-B1)", () => {
    const result = projectPdppRecordsToLegacyPayload("chatgpt.memories", [], {
      fetchedStreams: ["memories"],
    });
    expect(result).toEqual({
      ok: true,
      payload: { memories: [], total: 0 },
    });
  });

  it("returns the real legacy empty payload for amazon.orders with zero rows on both fetched streams, not missing_stream (N-B1)", () => {
    const result = projectPdppRecordsToLegacyPayload("amazon.orders", [], {
      fetchedStreams: ["orders", "order_items"],
    });
    expect(result).toEqual({ ok: true, payload: { orders: [], total: 0 } });
  });

  it("returns empty_singleton error for instagram.profile with zero records, not a fabricated profile (F1)", () => {
    const result = projectPdppRecordsToLegacyPayload("instagram.profile", [], {
      fetchedStreams: ["profile"],
    });
    expect(result).toEqual({
      ok: false,
      error: { kind: "empty_singleton", scope: "instagram.profile" },
    });
  });

  describe("instagram.profile — real captured legacy fixtures (B1)", () => {
    // __fixtures__/instagram.profile.{small,empty,large}.json are byte-
    // identical copies of connectors/meta/fixtures/instagram.profile.*.json
    // at data-connectors@20bba85314034594f64a0a97ac029b76521f6785 — the
    // real OLD payload shape, not an invented one. See __fixtures__/
    // PROVENANCE.md.
    for (const [label, oldPayload] of [
      ["small", instagramProfileSmall],
      ["empty", instagramProfileEmpty],
      ["large", instagramProfileLarge],
    ] as const) {
      it(`does NOT reproduce the real "${label}" legacy fixture byte-for-byte — is_private/media_count/is_business/profile_pic_url/external_url have no PDPP source (B1, B2: documented gap, not silently passed)`, () => {
        const pdppRecords: PdppRecord[] = [
          {
            stream: "profile",
            data: {
              id: "fixture-id",
              username: oldPayload.username,
              full_name: oldPayload.full_name,
              bio: oldPayload.bio,
              follower_count: oldPayload.follower_count,
              following_count: oldPayload.following_count,
              is_verified: oldPayload.is_verified,
            },
          },
        ];
        const result = projectPdppRecordsToLegacyPayload(
          "instagram.profile",
          pdppRecords,
          { fetchedStreams: ["profile"] },
        );
        expect(result.ok).toBe(true);
        if (result.ok) {
          validateAgainst(instagramProfileSchema, result.payload);
          // N-M1: name the exact set of keys the real fixture carries that
          // this projection cannot produce, and assert every key the two
          // DO share is equal — not just "the JSON strings differ", which
          // would also pass on key-order alone and record nothing.
          const oldKeys = new Set(Object.keys(oldPayload));
          const newKeys = new Set(Object.keys(result.payload));
          const missingFromProjection = [...oldKeys].filter(
            (k) => !newKeys.has(k),
          );
          expect(new Set(missingFromProjection)).toEqual(
            new Set(
              [
                "is_private",
                "media_count",
                "is_business",
                "profile_pic_url",
                "external_url",
              ].filter((k) => oldKeys.has(k)),
            ),
          );
          const sharedKeys = [...oldKeys].filter((k) => newKeys.has(k));
          for (const key of sharedKeys) {
            expect(
              (result.payload as Record<string, unknown>)[key],
              `shared key "${key}" should be equal between the real fixture and the projection`,
            ).toEqual((oldPayload as Record<string, unknown>)[key]);
          }
        }
      });
    }
  });

  describe("github.repositories", () => {
    const pdppRecords: PdppRecord[] = [
      {
        stream: "repositories",
        data: {
          id: "1",
          name: "unity-surfaces",
          full_name: "vana-org/unity-surfaces",
          owner_login: "vana-org",
          description: "Vana app surfaces",
          private: false,
          fork: false,
          archived: false,
          disabled: false,
          default_branch: "main",
          language: "TypeScript",
          topics: ["vana", "pdpp"],
          stargazers_count: 12,
          forks_count: 2,
          open_issues_count: 5,
          watchers_count: 12,
          size_kb: 4096,
          license_key: "apache-2.0",
          html_url: "https://github.com/vana-org/unity-surfaces",
          homepage: null,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-09-01T00:00:00Z",
          pushed_at: "2026-09-01T00:00:00Z",
        },
      },
    ];

    it("projects a payload that validates against the pinned legacy schema (schema-valid only — no real OLD fixture at the pin)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.repositories",
        pdppRecords,
        { fetchedStreams: ["repositories"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubRepositoriesSchema, result.payload);
      }
    });

    it("emits capitalized visibility text ('Public'/'Private'), matching github-playwright.js's own DOM label, not lowercase (S4/B2 fix)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.repositories",
        pdppRecords,
        { fetchedStreams: ["repositories"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        assertByteForByte(result.payload, {
          repositories: [
            {
              name: "unity-surfaces",
              url: "https://github.com/vana-org/unity-surfaces",
              description: "Vana app surfaces",
              language: "TypeScript",
              stars: 12,
              forks: 2,
              visibility: "Public",
              topics: ["vana", "pdpp"],
              updatedAt: "2026-09-01T00:00:00Z",
            },
          ],
        });
      }
    });
  });

  describe("github.starred", () => {
    it("projects and validates against the pinned legacy schema (schema-valid only)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.starred",
        [
          {
            stream: "starred",
            data: {
              id: "99",
              full_name: "vana-org/vana",
              description: "Vana protocol",
              language: "Rust",
              stargazers_count: 500,
              html_url: "https://github.com/vana-org/vana",
              starred_at: "2026-05-01T00:00:00Z",
            },
          },
        ],
        { fetchedStreams: ["starred"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(githubStarredSchema, result.payload);
      }
    });

    it("omits updatedAt: starred_at has a different meaning than legacy's page-scraped repo-updated time (B2/S4 fix — no longer mislabeled)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "github.starred",
        [
          {
            stream: "starred",
            data: {
              id: "99",
              full_name: "vana-org/vana",
              html_url: "https://github.com/vana-org/vana",
              starred_at: "2026-05-01T00:00:00Z",
            },
          },
        ],
        { fetchedStreams: ["starred"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const starred = (
          result.payload as { starred: { updatedAt: unknown }[] }
        ).starred;
        expect(starred[0].updatedAt).toBeNull();
      }
    });
  });

  describe("chatgpt.memories", () => {
    it("projects and validates against the pinned legacy schema (schema-valid only)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.memories",
        [
          {
            stream: "memories",
            data: {
              id: "mem_1",
              content: "Prefers dark mode",
              created_at: "2026-01-01T00:00:00Z",
              updated_at: null,
            },
          },
        ],
        { fetchedStreams: ["memories"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(chatgptMemoriesSchema, result.payload);
      }
    });

    it("emits type: 'memory', matching legacy's own fallback (chatgpt-playwright.js:645), not omitting the field (B2/S4 fix)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.memories",
        [
          {
            stream: "memories",
            data: {
              id: "mem_1",
              content: "Prefers dark mode",
              created_at: "2026-01-01T00:00:00Z",
              updated_at: "2026-02-01T00:00:00Z",
            },
          },
        ],
        { fetchedStreams: ["memories"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        assertByteForByte(result.payload, {
          memories: [
            {
              id: "mem_1",
              content: "Prefers dark mode",
              created_at: "2026-01-01T00:00:00Z",
              updated_at: "2026-02-01T00:00:00Z",
              type: "memory",
            },
          ],
          total: 1,
        });
      }
    });
  });

  describe("chatgpt.conversations", () => {
    const conversationRecords: PdppRecord[] = [
      {
        stream: "conversations",
        data: {
          id: "conv_1",
          title: "Adapter notes",
          create_time: "2026-09-22T10:00:00Z",
          update_time: "2026-09-22T10:05:00Z",
          current_node: "msg_3",
          message_count_on_current_branch: 3,
        },
      },
      {
        stream: "messages",
        data: {
          id: "msg_2",
          conversation_id: "conv_1",
          parent_id: "msg_1",
          role: "assistant",
          content: "Use the source declaration fields only.",
          content_type: "text",
          model_slug: "gpt-5",
          create_time: "2026-09-22T10:02:00Z",
          on_current_branch: true,
        },
      },
      {
        stream: "messages",
        data: {
          id: "msg_alt",
          conversation_id: "conv_1",
          parent_id: "msg_1",
          role: "assistant",
          content: "Old branch",
          content_type: "text",
          model_slug: "gpt-5",
          create_time: "2026-09-22T10:03:00Z",
          on_current_branch: false,
        },
      },
      {
        stream: "messages",
        data: {
          id: "msg_1",
          conversation_id: "conv_1",
          parent_id: null,
          role: "user",
          content: "What should the adapter read?",
          content_type: "text",
          model_slug: null,
          create_time: "2026-09-22T10:01:00Z",
          on_current_branch: true,
        },
      },
      {
        stream: "messages",
        data: {
          id: "msg_3",
          conversation_id: "conv_1",
          parent_id: "msg_2",
          role: "assistant",
          content: "Map model_slug to model.",
          content_type: "multimodal_text",
          model_slug: "gpt-5-thinking",
          create_time: null,
          on_current_branch: true,
        },
      },
    ];

    it("joins conversations to current-branch messages, orders by parent chain, and validates the legacy schema", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        conversationRecords,
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.payload).toMatchObject({
          conversations: [
            {
              id: "conv_1",
              title: "Adapter notes",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              message_count: 3,
              fetched_at: expect.any(String),
              messages: [
                {
                  id: "msg_1",
                  role: "user",
                  content: "What should the adapter read?",
                  content_type: "text",
                  create_time: "2026-09-22T10:01:00Z",
                  model: null,
                },
                {
                  id: "msg_2",
                  role: "assistant",
                  content: "Use the source declaration fields only.",
                  content_type: "text",
                  create_time: "2026-09-22T10:02:00Z",
                  model: "gpt-5",
                },
                {
                  id: "msg_3",
                  role: "assistant",
                  content: "Map model_slug to model.",
                  content_type: "multimodal_text",
                  create_time: null,
                  model: "gpt-5-thinking",
                },
              ],
            },
          ],
          total: 1,
        });
        validateAgainst(
          { schema: chatgptConversationsSchema.schema },
          result.payload,
        );
      }
    });

    it("retains legacy nullable timestamps and generated fetched_at", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "nullable-times",
              title: null,
              current_node: null,
              message_count_on_current_branch: 0,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.payload).toMatchObject({
          conversations: [
            {
              id: "nullable-times",
              title: "Untitled",
              create_time: null,
              update_time: null,
              message_count: 0,
              fetched_at: expect.any(String),
              messages: [],
            },
          ],
          total: 1,
        });
        validateAgainst(
          { schema: chatgptConversationsSchema.schema },
          result.payload,
        );
      }
    });

    it.each([
      { field: "create_time", value: 123, scenario: "numeric create_time" },
      { field: "update_time", value: {}, scenario: "object update_time" },
    ])("drops and counts a conversation with $scenario", ({ field, value }) => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "malformed-time",
              title: "Malformed timestamp",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              current_node: null,
              message_count_on_current_branch: 0,
              [field]: value,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result).toEqual({
        ok: true,
        payload: { conversations: [], total: 0 },
        diagnostics: [
          {
            kind: "records_dropped",
            scope: "chatgpt.conversations",
            stream: "conversations",
            count: 1,
            reasons: [
              "Conversation timestamps must be strings, null, or absent",
            ],
          },
        ],
      });
    });

    it("keeps only legacy user and assistant text messages and computes message_count from retained messages", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "filtered",
              title: "Filtered",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              current_node: "tool_msg",
              message_count_on_current_branch: 4,
            },
          },
          {
            stream: "messages",
            data: {
              id: "user_msg",
              conversation_id: "filtered",
              parent_id: null,
              role: "user",
              content: "Keep me",
              content_type: "text",
              model_slug: null,
              create_time: "2026-09-22T10:01:00Z",
              on_current_branch: true,
            },
          },
          {
            stream: "messages",
            data: {
              id: "system_msg",
              conversation_id: "filtered",
              parent_id: "user_msg",
              role: "system",
              content: "Ignore role",
              content_type: "text",
              model_slug: null,
              create_time: "2026-09-22T10:02:00Z",
              on_current_branch: true,
            },
          },
          {
            stream: "messages",
            data: {
              id: "code_msg",
              conversation_id: "filtered",
              parent_id: "system_msg",
              role: "assistant",
              content: "Ignore content type",
              content_type: "code",
              model_slug: "gpt-5",
              create_time: "2026-09-22T10:03:00Z",
              on_current_branch: true,
            },
          },
          {
            stream: "messages",
            data: {
              id: "tool_msg",
              conversation_id: "filtered",
              parent_id: "code_msg",
              role: "tool",
              content: "Ignore tool role",
              content_type: "text",
              model_slug: null,
              create_time: "2026-09-22T10:04:00Z",
              on_current_branch: true,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.payload).toMatchObject({
          conversations: [
            {
              id: "filtered",
              message_count: 1,
              messages: [
                {
                  id: "user_msg",
                  role: "user",
                  content: "Keep me",
                },
              ],
            },
          ],
          total: 1,
        });
        validateAgainst(
          { schema: chatgptConversationsSchema.schema },
          result.payload,
        );
      }
    });

    it("returns missing_stream when messages were not fetched", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        conversationRecords.filter(
          (record) => record.stream === "conversations",
        ),
        { fetchedStreams: ["conversations"] },
      );

      expect(result).toEqual({
        ok: false,
        error: {
          kind: "missing_stream",
          scope: "chatgpt.conversations",
          expectedStream: "messages",
        },
      });
    });

    it("drops and counts the conversation when a conversation is missing required branch count", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "missing-timestamp",
              title: "Missing timestamp",
              create_time: null,
              update_time: "2026-09-22T10:05:00Z",
              current_node: "msg_1",
              message_count_on_current_branch: null,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result).toMatchObject({
        ok: true,
        payload: { conversations: [], total: 0 },
        diagnostics: [
          {
            kind: "records_dropped",
            stream: "conversations",
            count: 1,
            reasons: ["Conversation lacks a current-branch message count"],
          },
        ],
      });
    });

    it("drops and counts the conversation when the current-branch message set is incomplete", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "missing-message",
              title: "Missing message",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              current_node: "msg_missing",
              message_count_on_current_branch: 1,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result).toMatchObject({
        ok: true,
        payload: { conversations: [], total: 0 },
        diagnostics: [
          {
            kind: "records_dropped",
            stream: "conversations",
            count: 1,
            reasons: [
              "Current branch message count does not match conversation",
            ],
          },
        ],
      });
    });

    it("drops and counts the conversation when a current-branch message is orphaned from the current_node chain", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "orphaned",
              title: "Orphaned",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              current_node: "msg_2",
              message_count_on_current_branch: 2,
            },
          },
          {
            stream: "messages",
            data: {
              id: "msg_1",
              conversation_id: "orphaned",
              parent_id: null,
              role: "user",
              content: "Orphan",
              content_type: "text",
              on_current_branch: true,
            },
          },
          {
            stream: "messages",
            data: {
              id: "msg_2",
              conversation_id: "orphaned",
              parent_id: "missing-parent",
              role: "assistant",
              content: "Broken chain",
              content_type: "text",
              on_current_branch: true,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result).toMatchObject({
        ok: true,
        payload: { conversations: [], total: 0 },
        diagnostics: [
          {
            kind: "records_dropped",
            stream: "conversations",
            count: 1,
            reasons: ["Current branch message chain is incomplete"],
          },
        ],
      });
    });

    it("serves the other conversations when one is malformed", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          ...conversationRecords,
          {
            stream: "conversations",
            data: {
              id: "conv_broken",
              title: "Broken",
              current_node: "gone",
              message_count_on_current_branch: 2,
            },
          },
          {
            stream: "messages",
            data: {
              id: "msg_stray",
              conversation_id: "conv_not_stored",
              parent_id: null,
              role: "user",
              content: "No conversation row",
              content_type: "text",
              on_current_branch: true,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      const conversations = result.payload.conversations as {
        id: string;
        messages: unknown[];
      }[];
      expect(conversations.map((c) => c.id)).toEqual(["conv_1"]);
      expect(conversations[0].messages).toHaveLength(3);
      expect(result.payload.total).toBe(1);
      expect(result.diagnostics).toEqual([
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "conversations",
          count: 1,
          reasons: ["Current branch message count does not match conversation"],
        },
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "messages",
          count: 1,
          reasons: ["Messages have no matching conversation"],
        },
      ]);
      validateAgainst(
        { schema: chatgptConversationsSchema.schema },
        result.payload,
      );
    });

    it("drops a conversation without an id and non-object rows instead of failing the scope", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          ...conversationRecords,
          {
            stream: "conversations",
            data: { title: "No id", message_count_on_current_branch: 0 },
          },
          {
            stream: "conversations",
            data: null as unknown as Record<string, unknown>,
          },
          {
            stream: "messages",
            data: null as unknown as Record<string, unknown>,
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(
        (result.payload.conversations as { id: string }[]).map((c) => c.id),
      ).toEqual(["conv_1"]);
      expect(result.diagnostics).toEqual([
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "conversations",
          count: 2,
          reasons: [
            "Conversation record is not an object",
            "Conversation lacks an id",
          ],
        },
        {
          kind: "records_dropped",
          scope: "chatgpt.conversations",
          stream: "messages",
          count: 1,
          reasons: ["Message record is not an object"],
        },
      ]);
    });

    it("projects empty threads and reports stream_missing when allowed to run without messages", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        conversationRecords.filter(
          (record) => record.stream === "conversations",
        ),
        {
          fetchedStreams: ["conversations"],
          allowMissingJoinStreams: true,
          now: "2026-10-01T00:00:00.000Z",
        },
      );

      expect(result).toEqual({
        ok: true,
        payload: {
          conversations: [
            {
              id: "conv_1",
              title: "Adapter notes",
              create_time: "2026-09-22T10:00:00Z",
              update_time: "2026-09-22T10:05:00Z",
              message_count: 0,
              messages: [],
              fetched_at: "2026-10-01T00:00:00.000Z",
            },
          ],
          total: 1,
        },
        diagnostics: [
          {
            kind: "stream_missing",
            scope: "chatgpt.conversations",
            stream: "messages",
          },
        ],
      });
    });

    it("projects the same records to the same output given now and key order", () => {
      const options = {
        fetchedStreams: ["conversations", "messages"],
        now: "2026-10-01T00:00:00.000Z",
        orderByPrimaryKey: true,
      };
      const second: PdppRecord = {
        stream: "conversations",
        data: {
          id: "conv_0",
          title: "Earlier",
          current_node: null,
          message_count_on_current_branch: 0,
        },
      };
      const forward = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [...conversationRecords, second],
        options,
      );
      const reversed = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [second, ...conversationRecords].reverse(),
        options,
      );

      expect(JSON.stringify(forward)).toBe(JSON.stringify(reversed));
      // Legacy order: newest update_time first; conv_0 has none, so it is last.
      expect(forward.ok && forward.payload.conversations).toMatchObject([
        { id: "conv_1", fetched_at: "2026-10-01T00:00:00.000Z" },
        { id: "conv_0", fetched_at: "2026-10-01T00:00:00.000Z" },
      ]);
    });

    it("preserves a fetched empty conversations result", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [],
        { fetchedStreams: ["conversations", "messages"] },
      );

      expect(result).toEqual({
        ok: true,
        payload: { conversations: [], total: 0 },
      });
    });
  });

  describe("linkedin.experience / education / skills / languages", () => {
    it("linkedin.experience projects, validates, and reproduces legacy's 'M/YYYY - Present' dates format from start/end dates (B2/S4 fix — schema-valid only, no real OLD fixture)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.experience",
        [
          {
            stream: "experience",
            data: {
              id: "exp_1",
              title: "Staff Engineer",
              company: "Vana",
              start_date: "2024-01-15T00:00:00Z",
              end_date: null,
              location: "Remote",
              description: "Building Unity surfaces",
            },
          },
        ],
        { fetchedStreams: ["experience"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(linkedinExperienceSchema, result.payload);
        assertByteForByte(result.payload, {
          experiences: [
            {
              jobTitle: "Staff Engineer",
              companyName: "Vana",
              dates: "1/2024 - Present",
              location: "Remote",
              description: "Building Unity surfaces",
            },
          ],
        });
      }
    });

    it("linkedin.experience trims a missing start date to 'Present' with no leading space, matching legacy's own extractTimePeriod (N-M2)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.experience",
        [
          {
            stream: "experience",
            data: {
              id: "exp_2",
              title: "Engineer",
              company: "Vana",
              start_date: null,
              end_date: null,
              location: "Remote",
              description: "",
            },
          },
        ],
        { fetchedStreams: ["experience"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const experiences = (
          result.payload as { experiences: { dates: string }[] }
        ).experiences;
        // copy-assertion-ok: legacy's exact extractTimePeriod text shape is the contract this projection must reproduce byte-for-byte, not UI prose
        expect(experiences[0].dates).toBe("- Present");
      }
    });

    it("linkedin.experience trims a missing start with a real end date (N-M2 follow-up)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.experience",
        [
          {
            stream: "experience",
            data: {
              id: "exp_3",
              title: "Engineer",
              company: "Vana",
              start_date: null,
              end_date: "2020-03-31",
              location: "Remote",
              description: "",
            },
          },
        ],
        { fetchedStreams: ["experience"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const experiences = (
          result.payload as { experiences: { dates: string }[] }
        ).experiences;
        // copy-assertion-ok: legacy's exact extractTimePeriod text shape is the contract this projection must reproduce byte-for-byte, not UI prose
        expect(experiences[0].dates).toBe("- 3/2020");
      }
    });

    it("linkedin.education joins degree and field of study in the legacy degree string", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.education",
        [
          {
            stream: "education",
            data: {
              id: "edu_1",
              school: "University of Example",
              degree: "BS",
              field_of_study: "Computer Science",
              start_date: "2017",
              end_date: "2021-05",
              grade: "3.9",
              logo_url: "https://media.example/school.png",
            },
          },
        ],
        { fetchedStreams: ["education"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(linkedinEducationSchema, result.payload);
        // Frozen linkedin-playwright.js joins degreeName and fieldOfStudy with ", ".
        assertByteForByte(result.payload, {
          education: [
            {
              schoolName: "University of Example",
              degree: "BS, Computer Science",
              years: "2017 - 5/2021",
              grade: "3.9",
              logoUrl: "https://media.example/school.png",
            },
          ],
        });
      }
      expect(LEGACY_SCOPE_BINDINGS.get("linkedin.education")?.lossy).toEqual([
        "school, degree, grade, logo_url: null/missing values become '' to satisfy the required legacy string fields",
      ]);
    });

    it("linkedin.languages projects and validates (schema-valid only)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.languages",
        [
          {
            stream: "languages",
            data: { id: "lang_1", name: "English", proficiency: "Native" },
          },
        ],
        { fetchedStreams: ["languages"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(linkedinLanguagesSchema, result.payload);
        assertByteForByte(result.payload, {
          languages: [{ name: "English", proficiency: "Native" }],
        });
      }
    });

    it("linkedin.skills projects and validates (schema-valid only)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "linkedin.skills",
        [
          {
            stream: "skills",
            data: { id: "skill_1", name: "TypeScript", endorsement_count: 15 },
          },
        ],
        { fetchedStreams: ["skills"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(linkedinSkillsSchema, result.payload);
        assertByteForByte(result.payload, {
          skills: [{ name: "TypeScript", endorsements: "15" }],
        });
      }
    });
  });

  it("linkedin.profile projects the 0.3.1 profile stream to the legacy Career Coach shape", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "linkedin.profile",
      [
        {
          stream: "profile",
          data: {
            id: "member_1",
            public_url: "https://www.linkedin.com/in/member/",
            full_name: "Ada Lovelace",
            headline: "Engineer",
            location: "London",
            connection_count: 42,
            profile_picture_url: "https://media.example/ada.jpg",
            summary: "Builds analytical engines.",
          },
        },
      ],
      { fetchedStreams: ["profile"] },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      validateAgainst(linkedinProfileSchema, result.payload);
      assertByteForByte(result.payload, {
        profileUrl: "https://www.linkedin.com/in/member/",
        fullName: "Ada Lovelace",
        headline: "Engineer",
        location: "London",
        connections: "42",
        profilePictureUrl: "https://media.example/ada.jpg",
        about: "Builds analytical engines.",
      });
    }
  });

  it("linkedin.profile reports and exercises required-field fallback loss", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "linkedin.profile",
      [
        {
          stream: "profile",
          data: {
            id: "member_missing_fields",
            connection_count: null,
          },
        },
      ],
      { fetchedStreams: ["profile"] },
    );

    expect(LEGACY_SCOPE_BINDINGS.get("linkedin.profile")?.lossy).toEqual([
      "public_url, full_name, headline, location, profile_picture_url, summary: null/missing values become '' to satisfy the required legacy string fields",
      "connection_count: absent or non-finite/non-number values become '0'; the legacy connector could replace its initial '0' with a fetched connection count, which this projection does not derive",
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      validateAgainst(linkedinProfileSchema, result.payload);
      assertByteForByte(result.payload, {
        profileUrl: "",
        fullName: "",
        headline: "",
        location: "",
        connections: "0",
        profilePictureUrl: "",
        about: "",
      });
    }
  });

  describe("spotify.profile / playlists", () => {
    it("spotify.profile projects structured source images to legacy URL strings", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "spotify.profile",
        [
          {
            stream: "profile",
            data: {
              id: "spotify_user",
              display_name: "Tim",
              followers: 10,
              following: null,
              uri: "spotify:user:spotify_user",
              images: [
                {
                  url: "https://images.example/avatar.jpg",
                  width: 64,
                  height: 64,
                },
                "https://images.example/avatar-small.jpg",
                { width: 32, height: 32 },
              ],
            },
          },
        ],
        { fetchedStreams: ["profile"] },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(spotifyProfileSchema, result.payload);
        assertByteForByte(result.payload, {
          id: "spotify_user",
          display_name: "Tim",
          followers: 10,
          following: 0,
          uri: "spotify:user:spotify_user",
          images: [
            "https://images.example/avatar.jpg",
            "https://images.example/avatar-small.jpg",
          ],
        });
      }
    });

    it("spotify.playlists joins playlist_items into the legacy nested tracks shape", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "spotify.playlists",
        [
          {
            stream: "playlists",
            data: {
              id: "playlist_1",
              name: "Discover Weekly",
              description: "Fresh finds",
              owner_name: "Spotify",
              uri: "spotify:playlist:playlist_1",
              followers: 25,
              images: [
                {
                  url: "https://images.example/playlist.jpg",
                  width: 640,
                  height: 640,
                },
                {
                  url: "https://images.example/playlist-small.jpg",
                  width: 64,
                  height: 64,
                },
              ],
              track_count: 2,
            },
          },
          {
            stream: "playlist_items",
            data: {
              id: "playlist_1:2",
              playlist_id: "playlist_1",
              position: 2,
              added_at: "2026-01-02T00:00:00Z",
              added_by: "friend",
              name: "Second Song",
              artist_names: ["Second Artist"],
              album_name: "Second Album",
              duration_ms: 2000,
              track_id: "local-track-id",
              uri: "spotify:local:local-track-id",
            },
          },
          {
            stream: "playlist_items",
            data: {
              id: "playlist_1:1",
              playlist_id: "playlist_1",
              position: 1,
              added_at: "2026-01-01T00:00:00Z",
              added_by: "friend",
              name: "First Song",
              artist_names: ["First Artist"],
              album_name: "First Album",
              duration_ms: 1000,
              track_id: "11dFghVXANMlKmJXsNCbN1",
            },
          },
        ],
        { fetchedStreams: ["playlists", "playlist_items"] },
      );

      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(spotifyPlaylistsSchema, result.payload);
        assertByteForByte(result.payload, {
          playlists: [
            {
              name: "Discover Weekly",
              description: "Fresh finds",
              owner: "Spotify",
              uri: "spotify:playlist:playlist_1",
              followers: 25,
              images: [
                "https://images.example/playlist.jpg",
                "https://images.example/playlist-small.jpg",
              ],
              tracks_total: 2,
              tracks: [
                {
                  added_at: "2026-01-01T00:00:00Z",
                  added_by: "friend",
                  name: "First Song",
                  artists: [{ name: "First Artist" }],
                  album: "First Album",
                  duration_ms: 1000,
                  uri: "spotify:track:11dFghVXANMlKmJXsNCbN1",
                },
                {
                  added_at: "2026-01-02T00:00:00Z",
                  added_by: "friend",
                  name: "Second Song",
                  artists: [{ name: "Second Artist" }],
                  album: "Second Album",
                  duration_ms: 2000,
                  uri: "spotify:local:local-track-id",
                },
              ],
            },
          ],
          total: 1,
        });
      }
    });

    it("spotify.playlists keeps rejecting noncanonical track IDs when no URI is available", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "spotify.playlists",
        [
          { stream: "playlists", data: { id: "playlist_1" } },
          {
            stream: "playlist_items",
            data: {
              id: "playlist_1:1",
              playlist_id: "playlist_1",
              position: 1,
              track_id: "local-track-id",
            },
          },
        ],
        { fetchedStreams: ["playlists", "playlist_items"] },
      );

      expect(result).toMatchObject({
        ok: false,
        error: { kind: "incomplete_scope", scope: "spotify.playlists" },
      });
    });
  });

  describe("shop.orders", () => {
    it("projects legacy order fields, including the emitted top-level total", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "shop.orders",
        [
          {
            stream: "orders",
            data: {
              id: "order_1",
              order_date: "2026-03-01T00:00:00Z",
              merchant_name: "Acme Co",
              status: "delivered",
              total_cents: 1999,
              currency: "USD",
              item_count: 2,
              order_number: "#123",
              line_item_titles: ["Shoes", "Socks"],
              detail_url: "https://shop.app/orders/order_1",
            },
          },
        ],
        { fetchedStreams: ["orders"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst({ schema: shopOrdersSchema.schema }, result.payload);
        assertByteForByte(result.payload, {
          orders: [
            {
              id: "order_1",
              orderNumber: "order_1",
              placedAt: "2026-03-01T00:00:00Z",
              merchantName: "Acme Co",
              total: 19.99,
              currency: "USD",
              status: "delivered",
              itemCount: 2,
              lineItemTitles: ["Shoes", "Socks"],
              detailUrl: "https://shop.app/orders/order_1",
            },
          ],
          total: 1,
        });
      }
    });

    it("omits placedAt, total, itemCount rather than inventing an epoch date or a fabricated 0 when the PDPP source value is absent (N-S1)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "shop.orders",
        [{ stream: "orders", data: { id: "order_2" } }],
        { fetchedStreams: ["orders"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst({ schema: shopOrdersSchema.schema }, result.payload);
        const order = (
          result.payload as {
            orders: Record<string, unknown>[];
          }
        ).orders[0];
        expect(order).not.toHaveProperty("placedAt");
        expect(order).not.toHaveProperty("total");
        expect(order).not.toHaveProperty("itemCount");
        expect(result.payload).toMatchObject({ total: 1 });
      }
    });

    it("preserves an explicitly empty line_item_titles array", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "shop.orders",
        [{ stream: "orders", data: { id: "order_4", line_item_titles: [] } }],
        { fetchedStreams: ["orders"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst({ schema: shopOrdersSchema.schema }, result.payload);
        expect(
          (
            result.payload as {
              orders: Record<string, unknown>[];
            }
          ).orders[0].lineItemTitles,
        ).toEqual([]);
      }
    });

    it("omits placedAt when order_date is not a valid ISO 8601 date-time (F5)", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "shop.orders",
        [
          {
            stream: "orders",
            data: {
              id: "order_3",
              order_date: "not a date",
              merchant_name: "Acme Co",
              status: "delivered",
              total_cents: 1999,
              currency: "USD",
              item_count: 1,
            },
          },
        ],
        { fetchedStreams: ["orders"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst({ schema: shopOrdersSchema.schema }, result.payload);
        const order = (
          result.payload as {
            orders: Record<string, unknown>[];
          }
        ).orders[0];
        expect(order).not.toHaveProperty("placedAt");
        expect(order).toHaveProperty("total");
        expect(order).toHaveProperty("itemCount");
      }
    });
  });

  describe("amazon.orders — real PDPP-side input (B1)", () => {
    // __fixtures__/amazon.orders.pdpp-input.json is a byte-identical copy
    // of packages/polyfill-connectors/fixtures/amazon/scrubbed/
    // pilot-real-shape/amazon-browser-collector-proof-records.json at the
    // pin: a real, scrubbed PDPP-side input. This is schema-valid-only —
    // there is no captured legacy OLD payload for this exact record to
    // compare against, so no equality claim is made. See PROVENANCE.md.
    it("joins orders + order_items from a real PDPP-side fixture and validates against the pinned legacy schema, reformatting orderDate to legacy's 'Month D, YYYY' text (B2/S4 fix)", () => {
      const records = amazonPdppInput.records as PdppRecord[];
      const result = projectPdppRecordsToLegacyPayload(
        "amazon.orders",
        records,
        { fetchedStreams: ["orders", "order_items"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        validateAgainst(amazonOrdersSchema, result.payload);
        const payload = result.payload as {
          orders: { orderId: string; orderDate: string; items: unknown[] }[];
        };
        expect(payload.orders).toHaveLength(1);
        // copy-assertion-ok: this IS the contract — legacy's exact scraped date-text shape ("MonthName D, YYYY"), not UI prose
        expect(payload.orders[0].orderDate).toBe("April 18, 2026");
        expect(payload.orders[0].items).toHaveLength(2);
      }
    });

    it("excludes order_items belonging to a different order", () => {
      const result = projectPdppRecordsToLegacyPayload(
        "amazon.orders",
        [
          { stream: "orders", data: { id: "amz_1" } },
          { stream: "orders", data: { id: "amz_2" } },
          {
            stream: "order_items",
            data: { id: "i1", order_id: "amz_1", name: "A" },
          },
          {
            stream: "order_items",
            data: { id: "i2", order_id: "amz_2", name: "B" },
          },
        ],
        { fetchedStreams: ["orders", "order_items"] },
      );
      expect(result.ok).toBe(true);
      if (result.ok) {
        const payload = result.payload as {
          orders: { orderId: string; items: unknown[] }[];
        };
        const order1 = payload.orders.find((o) => o.orderId === "amz_1");
        expect(order1?.items).toHaveLength(1);
      }
    });
  });
});
