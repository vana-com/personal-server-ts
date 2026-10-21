/**
 * PS-Lite serves legacy scope bodies projected from stored PDPP records,
 * through every read path an app or builder uses: the data route, the
 * owner-only stored view, and the bounded block reads MCP tools use.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  legacyBindingsForProfile,
  projectPdppRecordsToLegacyPayload,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const conversations = {
  records: [
    {
      id: "conv-1",
      title: "Trip plan",
      create_time: "2026-09-01T10:00:00Z",
      update_time: "2026-09-01T10:05:00Z",
      current_node: "m1",
      message_count_on_current_branch: 1,
    },
  ],
};
const messages = {
  records: [
    {
      id: "m1",
      conversation_id: "conv-1",
      parent_id: null,
      role: "user",
      content: "How do I get to Lyon?",
      content_type: "text",
      model_slug: null,
      create_time: "2026-09-01T10:01:00Z",
      on_current_branch: true,
    },
  ],
};

function youtubeHistoryRecord(videoId: string, position: number) {
  return {
    id: `history-${videoId}`,
    position,
    watched_date: "2026-10-18",
    watched_date_label: "Today",
    video_id: videoId,
    video_url: `https://www.youtube.com/watch?v=${videoId}`,
    video_title: `${videoId} title`,
    channel_title: "Channel",
    view_count: 1,
    views_text: "1 view",
    description: null,
  };
}

function createRuntime(
  options: Partial<Parameters<typeof createPsLiteRuntime>[0]> = {},
) {
  const storage = createMemoryPsLiteStorage();
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    ...options,
    storage,
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth:
      options.auth ??
      createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
    active: true,
  });
  return { runtime, storage };
}

async function post(
  runtime: ReturnType<typeof createRuntime>["runtime"],
  scope: string,
  body: unknown,
) {
  const res = await postRaw(runtime, `/v1/data/${scope}`, body);
  expect(res.status).toBe(201);
  return res;
}

function postRaw(
  runtime: ReturnType<typeof createRuntime>["runtime"],
  path: string,
  body: unknown,
) {
  return runtime.fetch(
    new Request(`https://ps.local${path}`, {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    }),
  );
}

function get(
  runtime: ReturnType<typeof createRuntime>["runtime"],
  path: string,
  token = "owner-token",
) {
  return runtime.fetch(
    new Request(`https://ps.local${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),
  );
}

function parityFixture(scope: string): {
  streams: Record<string, Record<string, unknown>[]>;
  legacyBody: Record<string, unknown>;
  profileKey?: string;
} {
  return JSON.parse(
    readFileSync(
      new URL(
        `../../core/src/legacy-projection/__fixtures__/parity/${scope}.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  ) as ReturnType<typeof parityFixture>;
}

function markedRecords(
  records: Record<string, unknown>[],
  connectorId: string,
): Record<string, unknown>[] {
  return records.map((record) => ({
    ...record,
    $pdpp: { sourceId: `https://registry.pdpp.dev/sources/${connectorId}` },
  }));
}

function fixtureRecords(
  scope: string,
  fixture: ReturnType<typeof parityFixture>,
  records: Record<string, unknown>[],
): Record<string, unknown>[] {
  if (alternateLegacyBindingsForScope(scope).size === 0) return records;
  const binding = fixture.profileKey
    ? legacyBindingsForProfile(fixture.profileKey).get(scope)
    : LEGACY_SCOPE_BINDINGS.get(scope);
  if (!binding) throw new Error(`Missing test binding for ${scope}`);
  return markedRecords(records, binding.pdppSource.split("/").at(-1)!);
}

describe("PS-Lite legacy projection", () => {
  it("rejects unmarked raw records for a multi-profile source and allows the stored view", async () => {
    const { runtime, storage } = createRuntime();
    const raw = { records: [{ id: "repo-1", repositories: [] }] };
    await post(runtime, "github.repositories", raw);
    const at = storage.findEntry({ scope: "github.repositories" })!.collectedAt;

    const served = await get(runtime, "/v1/data/github.repositories");
    expect(served.status).toBe(409);
    expect(await served.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
    const historical = await get(
      runtime,
      `/v1/data/github.repositories?at=${encodeURIComponent(at)}`,
    );
    expect(historical.status).toBe(409);
    expect(await historical.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
    const stored = await get(
      runtime,
      "/v1/data/github.repositories?view=stored",
    );
    expect(stored.status).toBe(200);
    expect(((await stored.json()) as { data: unknown }).data).toEqual(raw);
  });

  it("does not guess the default Oura binding from a row without record_type", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "oura.sleep", {
      records: [{ id: "day-1", day: "2026-09-01", sleep_score: 82 }],
    });

    const res = await get(runtime, "/v1/data/oura.sleep");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
  });

  it("rejects a sibling stream from another connector", async () => {
    const { runtime } = createRuntime();
    const fixture = parityFixture("instagram.posts");
    await post(runtime, "instagram.posts", {
      records: markedRecords(fixture.streams.posts, "meta"),
    });
    await post(runtime, "instagram.post_likes", {
      records: markedRecords(fixture.streams.post_likes, "github"),
    });

    const res = await get(runtime, "/v1/data/instagram.posts");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
  });

  it("uses connector identity even when a PAT row has browser-looking extra fields", async () => {
    const { runtime } = createRuntime();
    const raw = {
      records: [
        {
          id: "repo-1",
          name: "PAT repo",
          html_url: "https://github.com/example/pat-repo",
          repositories: [],
          $pdpp: { sourceId: "https://registry.pdpp.dev/sources/github" },
        },
      ],
    };
    await post(runtime, "github.repositories", raw);

    const served = await get(runtime, "/v1/data/github.repositories");
    expect(served.status).toBe(200);
    expect(
      ((await served.json()) as { data: { repositories: { name: string }[] } })
        .data.repositories,
    ).toMatchObject([{ name: "PAT repo" }]);
  });

  it.each(["oura.sleep", "instagram.posts"])(
    "matches the canonical %s profile projection for raw stream writes",
    async (scope) => {
      const { runtime } = createRuntime();
      const fixture = parityFixture(scope);
      const source = scope.slice(0, scope.indexOf("."));
      const records = Object.entries(fixture.streams).flatMap(
        ([stream, rows]) => rows.map((data) => ({ stream, data })),
      );
      for (const [stream, rows] of Object.entries(fixture.streams)) {
        await post(runtime, `${source}.${stream}`, {
          records: fixtureRecords(scope, fixture, rows),
        });
      }
      const canonical = projectPdppRecordsToLegacyPayload(scope, records, {
        fetchedStreams: Object.keys(fixture.streams),
        profileKey: fixture.profileKey,
      });
      expect(canonical.ok).toBe(true);
      if (!canonical.ok) return;

      const res = await get(runtime, `/v1/data/${scope}`);
      expect(res.status).toBe(200);
      expect(((await res.json()) as { data: unknown }).data).toEqual(
        canonical.payload,
      );
      expect(canonical.payload).toEqual(fixture.legacyBody);
    },
  );

  it("does not project records with conflicting connector identities", async () => {
    const { runtime } = createRuntime();
    const raw = {
      records: [
        {
          id: "browser-day",
          day: "2026-09-01",
          record_type: "daily_score",
          sleep_score: 83,
          $pdpp: {
            sourceId: "https://registry.pdpp.dev/sources/oura-browser",
          },
        },
        {
          id: "other-day",
          day: "2026-09-02",
          sleep_score: 82,
          $pdpp: { sourceId: "https://registry.pdpp.dev/sources/oura" },
        },
      ],
    };
    await post(runtime, "oura.sleep", raw);

    const res = await get(runtime, "/v1/data/oura.sleep");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
  });

  it("rejects an incomplete row even when its connector identity is known", async () => {
    const { runtime } = createRuntime();
    const raw = {
      records: [
        {
          id: "incomplete-browser-row",
          day: "2026-09-01",
          sleep_score: 83,
          $pdpp: {
            sourceId: "https://registry.pdpp.dev/sources/oura-browser",
          },
        },
      ],
    };
    await post(runtime, "oura.sleep", raw);

    const res = await get(runtime, "/v1/data/oura.sleep");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
  });

  it("rejects malformed raw rows without serving them to the app", async () => {
    const { runtime } = createRuntime();
    const raw = { records: [null] };
    await post(runtime, "oura.sleep", raw);

    const res = await get(runtime, "/v1/data/oura.sleep");
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "LEGACY_PROJECTION_UNAVAILABLE" },
    });
  });

  it("serves a GitHub stream write in the legacy repositories shape", async () => {
    const { runtime, storage } = createRuntime();
    const raw = {
      records: markedRecords(
        [
          {
            id: "repo-a",
            name: "sample",
            html_url: "https://github.com/example/sample",
            description: "Example",
            language: "TypeScript",
            stargazers_count: 12,
            forks_count: 2,
            private: true,
            topics: ["tools"],
            updated_at: "2026-09-01T00:00:00Z",
          },
        ],
        "github",
      ),
    };
    await post(runtime, "github.repositories", raw);

    const res = await get(runtime, "/v1/data/github.repositories");

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual({
      repositories: [
        {
          name: "sample",
          url: "https://github.com/example/sample",
          description: "Example",
          language: "TypeScript",
          stars: 12,
          forks: 2,
          visibility: "Private",
          topics: ["tools"],
          updatedAt: "2026-09-01T00:00:00Z",
        },
      ],
    });
    const entry = storage.findEntry({ scope: "github.repositories" })!;
    expect(
      (await storage.readEnvelope("github.repositories", entry.collectedAt))
        .data,
    ).toEqual(raw);
  });

  it.each([
    "instagram.profile",
    "instagram.following",
    "github.profile",
    "github.events",
    "github.starred",
    "linkedin.profile",
    "linkedin.skills",
    "spotify.profile",
    "spotify.playlists",
    "shop.orders",
    "heb.profile",
    "wholefoods.profile",
    "oura.activity",
    "icloud_notes.notes",
    "icloud_notes.folders",
  ])("serves a %s stream write in its legacy shape", async (scope) => {
    const { runtime, storage } = createRuntime();
    const fixture = parityFixture(scope);
    const source = scope.slice(0, scope.indexOf("."));
    for (const [stream, records] of Object.entries(fixture.streams)) {
      await post(runtime, `${source}.${stream}`, {
        records: fixtureRecords(scope, fixture, records),
      });
    }

    const res = await get(runtime, `/v1/data/${scope}`);

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual(
      fixture.legacyBody,
    );
    const entry = storage.findEntry({ scope })!;
    expect((await storage.readEnvelope(scope, entry.collectedAt)).data).toEqual(
      {
        records: fixtureRecords(
          scope,
          fixture,
          fixture.streams[scope.slice(scope.indexOf(".") + 1)],
        ),
      },
    );
  });

  it.each([
    {
      scope: "github.repositories",
      snapshot: {
        id: "browser-repositories",
        repositories: [{ name: "Browser repo" }],
      },
      expected: { repositories: [{ name: "Browser repo" }] },
    },
    {
      scope: "github.starred",
      snapshot: {
        id: "browser-starred",
        starred: [
          {
            fullName: "example/browser-star",
            url: "https://github.com/example/browser-star",
          },
        ],
      },
      expected: { starred: [{ fullName: "example/browser-star" }] },
    },
    {
      scope: "github.history",
      snapshot: {
        id: "browser-history",
        pullRequests: [],
        issues: [],
        fetchedAt: "2026-10-01T00:00:00Z",
      },
      expected: {
        pullRequests: [],
        issues: [],
        fetchedAt: "2026-10-01T00:00:00Z",
      },
    },
  ])(
    "serves a $scope browser snapshot through its legacy binding",
    async ({ scope, snapshot, expected }) => {
      const { runtime, storage } = createRuntime();
      const records = markedRecords([snapshot], "github-browser");
      await post(runtime, scope, { records });

      const res = await get(runtime, `/v1/data/${scope}`);

      expect(res.status).toBe(200);
      expect(((await res.json()) as { data: unknown }).data).toMatchObject(
        expected,
      );
      const entry = storage.findEntry({ scope })!;
      expect(
        (await storage.readEnvelope(scope, entry.collectedAt)).data,
      ).toEqual({ records });
    },
  );

  it("serves Amazon orders from raw orders and order_items streams", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "amazon.order_items", {
      records: [
        {
          id: "item-1",
          order_id: "order-1",
          name: "Book",
          url: "https://example.com/book",
          unit_price: "$12.00",
        },
      ],
    });
    await post(runtime, "amazon.orders", {
      records: [
        {
          id: "order-1",
          order_date: "2026-10-01",
          order_total: "$12.00",
          delivery_status: "Delivered",
        },
      ],
    });

    const res = await get(runtime, "/v1/data/amazon.orders");

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual({
      orders: [
        {
          orderId: "order-1",
          orderDate: "October 1, 2026",
          orderTotal: "$12.00",
          deliveryStatus: "Delivered",
          items: [
            {
              name: "Book",
              url: "https://example.com/book",
              price: "$12.00",
            },
          ],
        },
      ],
      total: 1,
    });
  });

  it.each(["activities", "coverage_diagnostics"])(
    "serves Strava %s in arrival order and the legacy collection",
    async (stream) => {
      const { runtime } = createRuntime();
      const records =
        stream === "activities"
          ? [
              { id: "z", activity_type: "Ride" },
              { id: "a", activity_type: "Run" },
            ]
          : [
              { id: "z", stream: "activities", status: "partial" },
              { id: "a", stream: "activities", status: "complete" },
            ];
      await post(runtime, `strava.${stream}`, { records });

      const res = await get(runtime, `/v1/data/strava.${stream}`);

      expect(res.status).toBe(200);
      expect(((await res.json()) as { data: unknown }).data).toEqual({
        [stream]: records,
      });
    },
  );

  it("uses a single-binding connector marker without exposing it in the legacy body", async () => {
    const { runtime } = createRuntime();
    const activity = { id: "ride-1", activity_type: "Ride" };
    await post(runtime, "strava.activities", {
      records: markedRecords([activity], "strava"),
    });

    const res = await get(runtime, "/v1/data/strava.activities");
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual({
      activities: [activity],
    });
  });

  it("serves the freshest same-name body without mixing legacy and PDPP versions", async () => {
    const { runtime, storage } = createRuntime();
    const scope = "spotify.profile";
    const oldLegacy = { display_name: "Old listener", followers: 1 };
    const raw = { records: parityFixture(scope).streams.profile };
    await post(runtime, scope, oldLegacy);
    const oldAt = storage.findEntry({ scope })!.collectedAt;
    await post(runtime, scope, raw);
    const rawAt = storage.findEntry({ scope })!.collectedAt;

    const projected = await get(runtime, `/v1/data/${scope}`);
    expect(((await projected.json()) as { data: unknown }).data).toEqual(
      parityFixture(scope).legacyBody,
    );
    const old = await get(
      runtime,
      `/v1/data/${scope}?at=${encodeURIComponent(oldAt)}`,
    );
    expect(((await old.json()) as { data: unknown }).data).toEqual(oldLegacy);
    expect(storage.countVersions(scope)).toBe(2);

    const newLegacy = { display_name: "Newest listener", followers: 2 };
    await post(runtime, scope, newLegacy);
    const latest = await get(runtime, `/v1/data/${scope}`);
    expect(((await latest.json()) as { data: unknown }).data).toEqual(
      newLegacy,
    );
    const historicalRaw = await get(
      runtime,
      `/v1/data/${scope}?at=${encodeURIComponent(rawAt)}`,
    );
    expect(((await historicalRaw.json()) as { data: unknown }).data).toEqual(
      parityFixture(scope).legacyBody,
    );
    expect(storage.countVersions(scope)).toBe(3);
  });

  it("serves youtube.history from stored PDPP watch_history records", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "youtube.history", {
      records: [
        {
          id: "history-2",
          position: 1,
          watched_date: "2026-10-17",
          watched_date_label: "Oct 17, 2026",
          video_id: "video-2",
          video_url: "https://www.youtube.com/watch?v=video-2",
          video_title: "Second video",
          channel_title: "Second channel",
          view_count: 42,
          views_text: null,
          description: "Second description",
        },
        {
          id: "history-1",
          position: 0,
          watched_date: "2026-10-18",
          watched_date_label: "Today",
          video_id: "video-1",
          video_url: "https://www.youtube.com/watch?v=video-1",
          video_title: "First video",
          channel_title: "First channel",
          view_count: 1234,
          views_text: "1.2K views",
          description: "First description",
        },
      ],
    });

    const res = await get(runtime, "/v1/data/youtube.history");

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual({
      timeWindow: "top 50 most recent items",
      history: [
        {
          watchedAt: "2026-10-18",
          watchedAtText: "Today",
          videoId: "video-1",
          videoUrl: "https://www.youtube.com/watch?v=video-1",
          videoTitle: "First video",
          channelTitle: "First channel",
          views: "1.2K views",
          description: "First description",
        },
        {
          watchedAt: "2026-10-17",
          watchedAtText: "Oct 17, 2026",
          videoId: "video-2",
          videoUrl: "https://www.youtube.com/watch?v=video-2",
          videoTitle: "Second video",
          channelTitle: "Second channel",
          views: "42 views",
          description: "Second description",
        },
      ],
    });

    const entry = storage.findEntry({ scope: "youtube.history" })!;
    expect(
      (await storage.readEnvelope("youtube.history", entry.collectedAt)).data,
    ).toMatchObject({ records: expect.any(Array) });
  });

  it("uses the requested YouTube alias envelope when canonical and alias versions coexist", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "youtube.watch_history", {
      records: [youtubeHistoryRecord("canonical-video", 0)],
    });
    await post(runtime, "youtube.history", {
      records: [youtubeHistoryRecord("alias-video", 0)],
    });
    const alias = storage.findEntry({ scope: "youtube.history" })!;

    const res = await get(runtime, "/v1/data/youtube.history");

    expect(
      ((await res.json()) as { data: { history: { videoId: string }[] } }).data
        .history,
    ).toMatchObject([{ videoId: "alias-video" }]);
    expect(alias).toBeDefined();
  });

  it("does not reuse a projection across alias version or body-form transitions", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "youtube.watch_history", {
      records: [youtubeHistoryRecord("canonical-video", 0)],
    });
    await post(runtime, "youtube.history", {
      records: [youtubeHistoryRecord("first-video", 0)],
    });
    const first = storage.findEntry({ scope: "youtube.history" })!;
    const firstRead = await get(runtime, "/v1/data/youtube.history");
    const firstData = (await firstRead.json()) as {
      data: { history: { videoId: string }[] };
    };
    expect(firstData.data.history[0]?.videoId).toBe("first-video");

    await post(runtime, "youtube.history", {
      records: [youtubeHistoryRecord("second-video", 0)],
    });
    const second = storage.findEntry({ scope: "youtube.history" })!;
    expect(second.collectedAt).not.toBe(first.collectedAt);
    const secondRead = await get(runtime, "/v1/data/youtube.history");
    const secondData = (await secondRead.json()) as {
      data: { history: { videoId: string }[] };
    };
    expect(secondData.data.history[0]?.videoId).toBe("second-video");

    await post(runtime, "youtube.history", {
      history: [{ videoId: "legacy-video" }],
    });
    const legacyRead = await get(runtime, "/v1/data/youtube.history");
    expect(((await legacyRead.json()) as { data: unknown }).data).toEqual({
      history: [{ videoId: "legacy-video" }],
    });
  });

  it("reports a projection that left rows out", async () => {
    const onLegacyProjectionIssue = vi.fn();
    const { runtime } = createRuntime({ onLegacyProjectionIssue });
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(runtime, "/v1/data/chatgpt.conversations");

    expect(res.status).toBe(200);
    expect(onLegacyProjectionIssue).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "projection_diagnostics",
        scope: "chatgpt.conversations",
        diagnostics: [
          expect.objectContaining({
            kind: "stream_missing",
            stream: "messages",
          }),
        ],
      }),
    );
  });

  it("serves the projected legacy body to the owner and keeps the stored records", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(runtime, "/v1/data/chatgpt.conversations");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown };
    expect(body.data).toMatchObject({
      conversations: [
        {
          id: "conv-1",
          title: "Trip plan",
          message_count: 1,
          messages: [{ id: "m1", role: "user" }],
        },
      ],
      total: 1,
    });

    // Sync is built on the raw port: it still sees the canonical records.
    const entry = storage.findEntry({ scope: "chatgpt.conversations" })!;
    const stored = await storage.readEnvelope(
      "chatgpt.conversations",
      entry.collectedAt,
    );
    expect(stored.data).toEqual(conversations);
  });

  it("returns the stored body to the owner with ?view=stored", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=stored",
    );

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual(
      conversations,
    );
  });

  it("refuses ?view=stored to a grantee and an unknown view to anyone", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.conversations", conversations);

    const grantee = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=stored&grantId=grant-1",
      "builder-token",
    );
    expect(grantee.status).toBe(403);

    const unknown = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=raw",
    );
    expect(unknown.status).toBe(400);
    expect(await unknown.json()).toMatchObject({
      error: { errorCode: "INVALID_VIEW" },
    });
  });

  it("serves a grantee the projected body", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);

    const owner = await get(runtime, "/v1/data/chatgpt.conversations");
    expect(owner.status).toBe(200);
    expect(((await owner.json()) as { data: unknown }).data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 1 }],
      total: 1,
    });

    const res = await get(
      runtime,
      "/v1/data/chatgpt.conversations?grantId=grant-1",
      "builder-token",
    );

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 1 }],
      total: 1,
    });
  });

  it("builds MCP blocks and the manifest from the projected envelope, not the stored sidecar", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    // Ingest wrote a sidecar for the stored {records} body.
    expect(
      await storage.readBlockManifest!("chatgpt.conversations", collectedAt),
    ).not.toBeNull();
    const served = withLegacyProjection(storage);
    const projected = await served.readEnvelope(
      "chatgpt.conversations",
      collectedAt,
    );
    const expected = await buildDataBlocksAsync({
      scope: "chatgpt.conversations",
      collectedAt,
      content: projected,
    });

    expect(
      await served.readBlockManifest!("chatgpt.conversations", collectedAt),
    ).toEqual(expected.manifest);
    expect(
      await served.hasScopeBlocks!("chatgpt.conversations", collectedAt),
    ).toBe(true);

    const read = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 1_000_000 },
    );
    expect(read.blocks).toEqual(expected.blocks);
    expect(read.nextCursor).toBeUndefined();
    expect(JSON.stringify(read.blocks)).toContain("How do I get to Lyon?");
    expect(JSON.stringify(read.blocks)).not.toContain(
      "message_count_on_current_branch",
    );
  });

  it("pages projected blocks with a cursor", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    const served = withLegacyProjection(storage);
    const all = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 1_000_000 },
    );

    const paged: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await served.readScopeBlocks!(
        "chatgpt.conversations",
        collectedAt,
        { maxBytes: 40, ...(cursor ? { cursor } : {}) },
      );
      for (const block of page.blocks) {
        paged.push(
          typeof block.value === "string"
            ? block.value
            : JSON.stringify(block.value),
        );
      }
      cursor = page.nextCursor;
    } while (cursor);

    expect(paged.join("")).toBe(
      all.blocks
        .map((block) =>
          typeof block.value === "string"
            ? block.value
            : JSON.stringify(block.value),
        )
        .join(""),
    );
  });
  it("rejects a block cursor after a sibling stream changes", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    const served = withLegacyProjection(storage);
    const first = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 40 },
    );
    expect(first.nextCursor).toBeDefined();

    await post(runtime, "chatgpt.messages", {
      records: [{ ...messages.records[0], content: "Changed" }],
    });

    await expect(
      served.readScopeBlocks!("chatgpt.conversations", collectedAt, {
        maxBytes: 40,
        cursor: first.nextCursor,
      }),
    ).rejects.toMatchObject({ code: "cursor_invalid" });
  });

  it("binds projected cursors to a newly covered scope and version", async () => {
    const { runtime, storage } = createRuntime();
    const scope = "github.repositories";
    const fixture = parityFixture(scope);
    await post(runtime, scope, {
      records: fixtureRecords(scope, fixture, fixture.streams.repositories),
    });
    await post(runtime, "linkedin.skills", {
      records: parityFixture("linkedin.skills").streams.skills,
    });
    const firstAt = storage.findEntry({ scope })!.collectedAt;
    const linkedinAt = storage.findEntry({
      scope: "linkedin.skills",
    })!.collectedAt;
    const served = withLegacyProjection(storage);
    const first = await served.readScopeBlocks!(scope, firstAt, {
      maxBytes: 40,
    });
    expect(first.nextCursor).toBeDefined();

    await expect(
      served.readScopeBlocks!("linkedin.skills", linkedinAt, {
        maxBytes: 40,
        cursor: first.nextCursor,
      }),
    ).rejects.toMatchObject({ code: "cursor_invalid" });

    await post(runtime, scope, {
      records: fixtureRecords(scope, fixture, [
        { ...fixture.streams.repositories[0], name: "new-repo" },
      ]),
    });
    const secondAt = storage.findEntry({ scope })!.collectedAt;
    await expect(
      served.readScopeBlocks!(scope, secondAt, {
        maxBytes: 40,
        cursor: first.nextCursor,
      }),
    ).rejects.toMatchObject({ code: "cursor_invalid" });
  });

  it("keys a sibling-only projection by its requested legacy version", async () => {
    const { runtime, storage } = createRuntime();
    const scope = "amazon.orders";
    await post(runtime, "amazon.order_items", {
      records: [],
    });
    await post(runtime, scope, { records: [] });
    const firstAt = storage.findEntry({ scope })!.collectedAt;
    await post(runtime, scope, { records: [] });
    const secondAt = storage.findEntry({ scope })!.collectedAt;
    expect(secondAt).not.toBe(firstAt);

    const served = withLegacyProjection(storage);
    const first = await served.readEnvelope(scope, firstAt);
    const second = await served.readEnvelope(scope, secondAt);

    expect(first.collectedAt).toBe(firstAt);
    expect(second.collectedAt).toBe(secondAt);
    expect(second.data).toEqual({ orders: [], total: 0 });
  });
});

describe("POST ?supersede=legacy", () => {
  const legacyBody = { conversations: [], total: 0 };

  it("retains older legacy versions for a newly projected source", async () => {
    const { runtime, storage } = createRuntime();
    const scope = "github.repositories";
    const old = { repositories: [{ name: "old-repo" }] };
    await post(runtime, scope, old);
    const oldAt = storage.findEntry({ scope })!.collectedAt;

    const write = await postRaw(runtime, `/v1/data/${scope}?supersede=legacy`, {
      records: parityFixture(scope).streams.repositories,
    });

    expect(write.status).toBe(201);
    expect(await write.json()).toMatchObject({
      superseded: [],
      supersedeRefused: "Legacy versions are retained for read-time projection",
    });
    expect(storage.countVersions(scope)).toBe(2);
    const oldRead = await get(
      runtime,
      `/v1/data/${scope}?at=${encodeURIComponent(oldAt)}`,
    );
    expect(((await oldRead.json()) as { data: unknown }).data).toEqual(old);
  });

  function versionBodies(
    storage: ReturnType<typeof createRuntime>["storage"],
    scope: string,
  ) {
    return Promise.all(
      storage
        .listVersions(scope, { limit: 50 })
        .map(
          async (entry) =>
            (await storage.readEnvelope(scope, entry.collectedAt)).data,
        ),
    );
  }

  const legacyThread = {
    conversations: [
      {
        id: "conv-1",
        title: "Trip plan",
        message_count: 1,
        messages: [
          { id: "m1", role: "user", content: "How do I get to Lyon?" },
        ],
      },
    ],
    total: 1,
  };

  it("deletes older legacy versions after the PDPP write commits", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", legacyBody);
    await post(runtime, "chatgpt.conversations", legacyBody);
    const legacyVersions = storage
      .listVersions("chatgpt.conversations", { limit: 50 })
      .map((entry) => entry.collectedAt);

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      conversations,
    );

    expect(res.status).toBe(201);
    const body = (await res.json()) as { superseded: string[] };
    expect([...body.superseded].sort()).toEqual([...legacyVersions].sort());
    expect(await versionBodies(storage, "chatgpt.conversations")).toEqual([
      conversations,
    ]);
    const read = await get(runtime, "/v1/data/chatgpt.conversations");
    expect(((await read.json()) as { data: unknown }).data).toMatchObject({
      conversations: [{ id: "conv-1" }],
      total: 1,
    });
  });

  it.each([
    {
      scope: "youtube.profile",
      legacy: { channelId: "channel-1", channelTitle: "Old channel" },
      records: [{ id: "channel-1", title: "New channel" }],
      projected: { channelId: "channel-1" },
    },
    {
      scope: "youtube.history",
      legacy: {
        history: [
          {
            videoId: "video-1",
            videoUrl: "https://youtube.com/watch?v=video-1",
            videoTitle: "Old title",
          },
        ],
      },
      records: [youtubeHistoryRecord("video-1", 0)],
      projected: {
        history: [{ videoId: "video-1", videoTitle: "video-1 title" }],
      },
    },
    {
      scope: "youtube.subscriptions",
      legacy: {
        subscriptions: [
          {
            channelId: "channel-1",
            channelUrl: "https://youtube.com/@channel-1",
            channelTitle: "Old title",
          },
        ],
      },
      records: [
        {
          id: "subscription-1",
          channel_id: "channel-1",
          channel_title: "New title",
          channel_url: "https://youtube.com/@channel-1",
          is_verified: false,
          notifications: false,
        },
      ],
      projected: {
        subscriptions: [{ channelId: "channel-1", channelTitle: "New title" }],
      },
    },
    {
      scope: "youtube.playlists",
      legacy: {
        playlists: [
          {
            playlistId: "playlist-1",
            url: "https://youtube.com/playlist?list=playlist-1",
            title: "Old title",
          },
        ],
      },
      records: [
        {
          id: "playlist-1",
          url: "https://youtube.com/playlist?list=playlist-1",
          title: "New title",
        },
      ],
      projected: {
        playlists: [{ playlistId: "playlist-1", title: "New title" }],
      },
    },
    {
      scope: "youtube.playlistItems",
      legacy: {
        playlists: [
          {
            playlistId: "playlist-1",
            items: [
              {
                videoId: "old-video",
                videoUrl: "https://youtube.com/watch?v=old-video",
                videoTitle: "Old video",
              },
            ],
          },
        ],
      },
      records: [
        {
          id: "playlist-item-1",
          playlist_id: "playlist-1",
          video_id: "new-video",
          video_url: "https://youtube.com/watch?v=new-video",
          video_title: "New video",
        },
      ],
      projected: {
        playlists: [
          { playlistId: "playlist-1", items: [{ videoId: "new-video" }] },
        ],
      },
    },
    {
      scope: "youtube.likes",
      legacy: {
        likedVideos: [
          {
            videoId: "video-1",
            videoUrl: "https://youtube.com/watch?v=video-1",
            videoTitle: "Old title",
          },
        ],
      },
      records: [
        {
          id: "like-1",
          video_id: "video-1",
          video_url: "https://youtube.com/watch?v=video-1",
          video_title: "New title",
        },
      ],
      projected: {
        likedVideos: [{ videoId: "video-1", videoTitle: "New title" }],
      },
    },
    {
      scope: "youtube.watchLater",
      legacy: {
        watchLater: [
          {
            videoId: "video-1",
            videoUrl: "https://youtube.com/watch?v=video-1",
            videoTitle: "Old title",
          },
        ],
      },
      records: [
        {
          id: "watch-later-1",
          video_id: "video-1",
          video_url: "https://youtube.com/watch?v=video-1",
          video_title: "New title",
        },
      ],
      projected: {
        watchLater: [{ videoId: "video-1", videoTitle: "New title" }],
      },
    },
  ])(
    "$scope keeps legacy versions and serves the read-time projection",
    async ({ scope, legacy, records, projected }) => {
      const { runtime, storage } = createRuntime();
      await post(runtime, scope, legacy);
      await post(runtime, scope, legacy);
      const legacyVersions = storage
        .listVersions(scope, { limit: 50 })
        .map((entry) => entry.collectedAt);

      const write = await postRaw(
        runtime,
        `/v1/data/${scope}?supersede=legacy`,
        { records },
      );

      expect(write.status).toBe(201);
      expect(await write.json()).toMatchObject({
        superseded: [],
        supersedeRefused:
          "YouTube legacy versions are retained for read-time projection",
      });
      expect(storage.countVersions(scope)).toBe(legacyVersions.length + 1);

      for (const collectedAt of legacyVersions) {
        const oldRead = await get(
          runtime,
          `/v1/data/${scope}?at=${encodeURIComponent(collectedAt)}`,
        );
        expect(((await oldRead.json()) as { data: unknown }).data).toEqual(
          legacy,
        );
      }

      const latestRead = await get(runtime, `/v1/data/${scope}`);
      expect(
        ((await latestRead.json()) as { data: unknown }).data,
      ).toMatchObject(projected);
    },
  );

  it("keeps older PDPP versions", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", legacyBody);
    await post(runtime, "chatgpt.conversations", { records: [] });

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      conversations,
    );

    expect(res.status).toBe(201);
    expect(await versionBodies(storage, "chatgpt.conversations")).toEqual([
      conversations,
      { records: [] },
    ]);
  });

  it("deletes nothing when the new body cannot serve the legacy view", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.conversations", legacyBody);

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      legacyBody,
    );

    expect(res.status).toBe(201);
    expect(((await res.json()) as { superseded: string[] }).superseded).toEqual(
      [],
    );
    expect(storage.countVersions("chatgpt.conversations")).toBe(2);
  });

  it("keeps the legacy threads when the messages stream is not stored yet", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.conversations", legacyThread);

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      conversations,
    );

    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({
      superseded: [],
      supersedeRefused: "the projection is partial (stream_missing)",
    });
    expect(await versionBodies(storage, "chatgpt.conversations")).toEqual([
      conversations,
      legacyThread,
    ]);
  });

  it("keeps the legacy history when the PDPP write holds fewer conversations", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", { records: [] });
    await post(runtime, "chatgpt.conversations", legacyThread);

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      { records: [] },
    );

    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({
      superseded: [],
      supersedeRefused:
        "the projection has 0 conversations; the newest legacy version has 1",
    });
    expect(storage.countVersions("chatgpt.conversations")).toBe(2);
  });

  it("deletes nothing when the write fails", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.conversations", legacyBody);

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      ["not", "an", "object"],
    );

    expect(res.status).toBe(400);
    expect(storage.countVersions("chatgpt.conversations")).toBe(1);
  });

  it("rejects an unknown supersede value before writing", async () => {
    const { runtime, storage } = createRuntime();

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=all",
      conversations,
    );

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "INVALID_SUPERSEDE" },
    });
    expect(storage.countVersions("chatgpt.conversations")).toBe(0);
  });

  it("refuses supersede on a delegated builder write and hands the proof back", async () => {
    const releaseProof = vi.fn(async () => {});
    const bearer = createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    });
    const { runtime, storage } = createRuntime({
      auth: {
        ...bearer,
        authorizeWrite: async () => ({
          builder: "0x00000000000000000000000000000000000000b1",
          grantId: "grant-w",
          attribution: {} as never,
          releaseProof,
        }),
      },
    });

    const res = await postRaw(
      runtime,
      "/v1/data/chatgpt.conversations?supersede=legacy",
      conversations,
    );

    expect(res.status).toBe(403);
    expect(releaseProof).toHaveBeenCalledOnce();
    expect(storage.countVersions("chatgpt.conversations")).toBe(0);
  });
});
