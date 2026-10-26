import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import claudeProjectionFixture from "./__fixtures__/claude-projection.json";
import storedChatgpt from "./__fixtures__/ps-lite-stored-chatgpt.json";
import {
  isStoredPdppScopeFile,
  projectStoredScopeToLegacyPayload,
  storedScopeJoinScopes,
} from "./index.js";
import chatgptConversationsSchema from "./legacy-schemas/chatgpt.conversations.json";
import chatgptMemoriesSchema from "./legacy-schemas/chatgpt.memories.json";
import claudeConversationsSchema from "./legacy-schemas/claude.conversations.json";
import claudeProjectsSchema from "./legacy-schemas/claude.projects.json";
import githubContributionsSchema from "./legacy-schemas/github.contributions.json";
import githubEventsSchema from "./legacy-schemas/github.events.json";
import githubHistorySchema from "./legacy-schemas/github.history.json";
import githubProfileSchema from "./legacy-schemas/github.profile.json";
import githubRepositoriesSchema from "./legacy-schemas/github.repositories.json";
import githubStarredSchema from "./legacy-schemas/github.starred.json";

const ajv = new Ajv({ allErrors: true, strict: false });

function expectLegacySchema(schemaDoc: { schema: unknown }, payload: unknown) {
  const validate = ajv.compile(schemaDoc.schema as Record<string, unknown>);
  expect(validate(payload), JSON.stringify(validate.errors)).toBe(true);
}

/** Group the tagged claude fixture into the per-stream files PS-Lite stores. */
function storedClaudeFiles(
  tagged: { data: Record<string, unknown>; stream: string }[],
): Record<string, { records: Record<string, unknown>[] }> {
  const files: Record<string, { records: Record<string, unknown>[] }> = {};
  for (const { data, stream } of tagged) {
    files[`claude.${stream}`] ??= { records: [] };
    files[`claude.${stream}`].records.push(data);
  }
  return files;
}

describe("projectStoredScopeToLegacyPayload", () => {
  it("passes a legacy payload through unchanged", () => {
    const legacy = {
      conversations: [
        {
          id: "c1",
          title: "Trip planning",
          create_time: 1_778_400_000.5,
          update_time: 1_778_400_100.5,
          message_count: 1,
          messages: [
            {
              id: "m1",
              role: "user",
              content: "Plan a trip",
              content_type: "text",
              create_time: "2026-05-10T08:00:00.000Z",
              model: null,
            },
          ],
          fetched_at: "2026-05-20T00:00:00.000Z",
        },
      ],
      total: 1,
    };
    expect(isStoredPdppScopeFile(legacy)).toBe(false);
    expect(
      projectStoredScopeToLegacyPayload("chatgpt.conversations", legacy, {
        "chatgpt.messages": storedChatgpt["chatgpt.messages"],
      }),
    ).toBe(legacy);
  });

  it("joins stored chatgpt.messages into stored chatgpt.conversations", () => {
    const payload = projectStoredScopeToLegacyPayload(
      "chatgpt.conversations",
      storedChatgpt["chatgpt.conversations"],
      { "chatgpt.messages": storedChatgpt["chatgpt.messages"] },
    ) as { conversations: Record<string, unknown>[]; total: number };

    expectLegacySchema(chatgptConversationsSchema, payload);
    expect(payload.total).toBe(3);
    expect(payload.conversations[0]).toMatchObject({
      id: "conv-1",
      title: "Mobile fixture 1",
      create_time: "2026-05-28T20:26:40.000Z",
      update_time: "2026-05-28T20:26:40.000Z",
      message_count: 1,
      messages: [
        {
          id: "msg-1-a",
          role: "user",
          content: "fixture message 1",
          content_type: "text",
          create_time: "2026-05-28T20:26:40.000Z",
          model: null,
        },
      ],
    });
  });

  it("keeps chatgpt titles and dates when chatgpt.messages is absent", () => {
    const payload = projectStoredScopeToLegacyPayload(
      "chatgpt.conversations",
      storedChatgpt["chatgpt.conversations"],
    );
    expect(payload).toEqual({
      conversations: [
        {
          id: "conv-1",
          title: "Mobile fixture 1",
          create_time: "2026-05-28T20:26:40.000Z",
          update_time: "2026-05-28T20:26:40.000Z",
        },
        {
          id: "conv-2",
          title: "Mobile fixture 2",
          create_time: "2026-05-28T20:26:39.000Z",
          update_time: "2026-05-28T20:26:39.000Z",
        },
        {
          id: "conv-3",
          title: "Mobile fixture 3",
          create_time: "2026-05-28T20:26:38.000Z",
          update_time: "2026-05-28T20:26:38.000Z",
        },
      ],
      total: 3,
    });
  });

  it("keeps chatgpt titles and dates when stored messages are incomplete", () => {
    const [first] = storedChatgpt["chatgpt.messages"].records;
    const payload = projectStoredScopeToLegacyPayload(
      "chatgpt.conversations",
      storedChatgpt["chatgpt.conversations"],
      { "chatgpt.messages": { records: [first] } },
    ) as { conversations: Record<string, unknown>[] };
    expect(payload.conversations).toHaveLength(3);
    expect(payload.conversations[1]).toEqual({
      id: "conv-2",
      title: "Mobile fixture 2",
      create_time: "2026-05-28T20:26:39.000Z",
      update_time: "2026-05-28T20:26:39.000Z",
    });
  });

  it("projects stored chatgpt.memories to the legacy wrapper", () => {
    const payload = projectStoredScopeToLegacyPayload("chatgpt.memories", {
      records: [
        {
          id: "mem-1",
          content: "Prefers metric units",
          created_at: "2026-05-01T10:00:00.000Z",
          updated_at: null,
        },
      ],
    });
    expectLegacySchema(chatgptMemoriesSchema, payload);
    expect(payload).toEqual({
      memories: [
        {
          id: "mem-1",
          content: "Prefers metric units",
          created_at: "2026-05-01T10:00:00.000Z",
          type: "memory",
        },
      ],
      total: 1,
    });
  });

  it("projects stored claude.* files with their join scopes", () => {
    const conversationFiles = storedClaudeFiles(
      claudeProjectionFixture["claude.conversations"],
    );
    const conversations = projectStoredScopeToLegacyPayload(
      "claude.conversations",
      conversationFiles["claude.conversations"],
      conversationFiles,
    );
    expectLegacySchema(claudeConversationsSchema, conversations);
    expect(conversations).toMatchObject({
      conversations: [
        {
          id: "chat-1",
          title: "Export chat",
          createdAt: "2026-01-01T00:00:00Z",
          messageCount: 2,
        },
      ],
      total: 1,
    });

    const projectFiles = storedClaudeFiles(
      claudeProjectionFixture["claude.projects"],
    );
    const projects = projectStoredScopeToLegacyPayload(
      "claude.projects",
      projectFiles["claude.projects"],
      projectFiles,
    );
    expectLegacySchema(claudeProjectsSchema, projects);
    expect(projects).toMatchObject({
      projects: [{ id: "project-1", title: "Research" }],
    });
  });

  it("keeps claude titles and dates without the account profile", () => {
    const files = storedClaudeFiles(
      claudeProjectionFixture["claude.conversations"],
    );
    expect(
      projectStoredScopeToLegacyPayload(
        "claude.conversations",
        files["claude.conversations"],
      ),
    ).toEqual({
      conversations: [
        {
          id: "chat-1",
          title: "Export chat",
          createdAt: "2026-01-01T00:00:00Z",
          updatedAt: "2026-01-02T00:00:00Z",
        },
      ],
      total: 1,
    });
  });

  it("returns a raw payload unchanged for a scope with no binding", () => {
    const raw = { records: [{ id: "x" }] };
    expect(projectStoredScopeToLegacyPayload("chatgpt.messages", raw)).toBe(
      raw,
    );
    expect(projectStoredScopeToLegacyPayload("unknown.scope", raw)).toBe(raw);
  });
});

describe("storedScopeJoinScopes", () => {
  it("names the sibling scopes a projection joins", () => {
    expect(storedScopeJoinScopes("chatgpt.conversations")).toEqual([
      "chatgpt.messages",
    ]);
    expect(storedScopeJoinScopes("chatgpt.memories")).toEqual([]);
    expect(storedScopeJoinScopes("claude.conversations")).toEqual([
      "claude.account_profile",
      "claude.messages",
    ]);
    expect(storedScopeJoinScopes("chatgpt.messages")).toEqual([]);
  });
});

describe("projectStoredScopeToLegacyPayload with one bad conversation", () => {
  const conversationRow = (id: string, count: number) => ({
    id,
    title: `Chat ${id}`,
    create_time: "2026-05-28T20:26:40.000Z",
    update_time: "2026-05-28T20:26:40.000Z",
    current_node: `msg-${id}`,
    message_count_on_current_branch: count,
  });
  const messageRow = (conversationId: string) => ({
    id: `msg-${conversationId}`,
    conversation_id: conversationId,
    role: "user",
    content_type: "text",
    content: `Hello ${conversationId}`,
    create_time: "2026-05-28T20:26:41.000Z",
    parent_id: "root",
    on_current_branch: true,
  });

  it("keeps messages for good conversations and titles-only for the bad one", () => {
    // `bad` claims two messages but only one is stored, so it is incomplete.
    const payload = projectStoredScopeToLegacyPayload(
      "chatgpt.conversations",
      {
        records: [
          conversationRow("a", 1),
          conversationRow("bad", 2),
          conversationRow("c", 1),
        ],
      },
      {
        "chatgpt.messages": {
          records: [messageRow("a"), messageRow("bad"), messageRow("c")],
        },
      },
    ) as {
      conversations: { id: string; messages?: unknown[] }[];
      total: number;
    };
    expect(payload.total).toBe(3);
    expect(
      payload.conversations.map((c) => [c.id, c.messages?.length ?? "none"]),
    ).toEqual([
      ["a", 1],
      ["bad", "none"],
      ["c", 1],
    ]);
  });

  it("accepts a raw file with extra metadata keys", () => {
    expect(isStoredPdppScopeFile({ records: [], next_cursor: null })).toBe(
      true,
    );
  });
});

// The github-browser connector (0.3.x) stores one snapshot record per stream
// with a runtime `id` key and the legacy fields beside it.
const browserFetchedAt = "2026-09-24T12:00:00.000Z";
const browserSnapshots = {
  "github.profile": {
    id: "octocat:profile",
    username: "octocat",
    fullName: "Octo Cat",
    profileUrl: "https://github.com/octocat",
    followers: 42,
    pinnedRepositories: [
      {
        fullName: "octocat/Hello-World",
        url: "https://github.com/octocat/Hello-World",
      },
    ],
    organizations: [],
    achievements: [],
    contributionsLastYear: 4,
  },
  "github.repositories": {
    id: "octocat:repositories",
    repositories: [
      {
        name: "Hello-World",
        url: "https://github.com/octocat/Hello-World",
        stars: 3,
        forks: 1,
        visibility: "Public",
        topics: [],
        updatedAt: "2026-09-20T00:00:00Z",
      },
    ],
  },
  "github.starred": {
    id: "octocat:starred",
    starred: [
      {
        fullName: "other/repo",
        url: "https://github.com/other/repo",
        stars: 9,
        updatedAt: "2026-09-19T00:00:00Z",
      },
    ],
  },
  "github.events": {
    id: "octocat:events",
    events: [
      {
        id: "evt-1",
        type: "PushEvent",
        createdAt: "2026-09-20T12:34:56Z",
        repo: "octocat/Hello-World",
        isPublic: true,
      },
    ],
    fetchedAt: browserFetchedAt,
    windowDescription:
      "GitHub public events API retention window (up to 300 events).",
  },
  "github.contributions": {
    id: "octocat:contributions",
    totalContributionsLastYear: 5,
    days: [
      { date: "2026-09-22", count: 3, level: 2 },
      { date: "2026-09-23", count: 2, level: 1 },
    ],
    fetchedAt: browserFetchedAt,
  },
  "github.history": {
    id: "octocat:history",
    pullRequests: [
      {
        id: "pr-1",
        type: "pr",
        repo: "other/repo",
        labels: [],
        comments: 0,
        reactionsTotal: 0,
        isDraft: false,
      },
    ],
    issues: [],
    fetchedAt: browserFetchedAt,
  },
} as const;

const browserLegacySchemas = {
  "github.profile": githubProfileSchema,
  "github.repositories": githubRepositoriesSchema,
  "github.starred": githubStarredSchema,
  "github.events": githubEventsSchema,
  "github.contributions": githubContributionsSchema,
  "github.history": githubHistorySchema,
} as const;

describe("projectStoredScopeToLegacyPayload for github-browser scope files", () => {
  it.each(Object.entries(browserSnapshots))(
    "projects the stored %s snapshot to its legacy payload",
    (scope, snapshot) => {
      const { id: _id, ...legacyFields } = snapshot;
      const projected = projectStoredScopeToLegacyPayload(scope, {
        records: [snapshot],
      });
      expectLegacySchema(
        browserLegacySchemas[scope as keyof typeof browserLegacySchemas],
        projected,
      );
      expect(projected).toEqual(
        scope === "github.events"
          ? {
              ...legacyFields,
              // copy-assertion-ok: the binding rewrites the browser wording to the retained legacy windowDescription contract
              windowDescription:
                "Up to 300 most recent public events across all repositories (≈90 days, GitHub API limit)",
            }
          : legacyFields,
      );
    },
  );

  it("keeps the nested snapshot rows the API bindings would drop", () => {
    const events = projectStoredScopeToLegacyPayload("github.events", {
      records: [browserSnapshots["github.events"]],
    }) as { events: unknown[] };
    const contributions = projectStoredScopeToLegacyPayload(
      "github.contributions",
      { records: [browserSnapshots["github.contributions"]] },
    ) as { days: unknown[] };
    expect(events.events).toHaveLength(1);
    expect(contributions.days).toHaveLength(2);
  });

  it("names no join scope for a browser snapshot", () => {
    for (const scope of Object.keys(browserSnapshots)) {
      expect(storedScopeJoinScopes(scope)).toEqual([]);
    }
  });

  it("leaves a browser snapshot the binding rejects raw, not empty", () => {
    const { fetchedAt: _fetchedAt, ...withoutFetchedAt } =
      browserSnapshots["github.events"];
    const raw = { records: [withoutFetchedAt] };
    expect(projectStoredScopeToLegacyPayload("github.events", raw)).toBe(raw);
  });

  it("projects the GitHub API connector's stored files as before", () => {
    const apiEvents = {
      records: [
        {
          id: "e1",
          type: "PushEvent",
          created_at: "2026-09-23T12:00:00Z",
          repository_full_name: "octocat/hello",
          is_public: true,
        },
      ],
    };
    expect(
      projectStoredScopeToLegacyPayload("github.events", apiEvents),
    ).toMatchObject({
      events: [
        {
          id: "e1",
          type: "PushEvent",
          createdAt: "2026-09-23T12:00:00Z",
          repo: "octocat/hello",
          isPublic: true,
        },
      ],
    });

    const apiContributions = projectStoredScopeToLegacyPayload(
      "github.contributions",
      {
        records: [
          {
            id: "u1:2026-09-22",
            user_id: "u1",
            date: "2026-09-22",
            contribution_count: 3,
          },
        ],
      },
    ) as { days: unknown[]; fetchedAt: string };
    expect(apiContributions.days).toEqual([{ date: "2026-09-22", count: 3 }]);

    // The API profile is built from `user` rows, not a `profile` stream, so a
    // raw file under `github.profile` stays raw exactly as before.
    const apiProfile = { records: [{ id: "u1", login: "octocat" }] };
    expect(
      projectStoredScopeToLegacyPayload("github.profile", apiProfile),
    ).toBe(apiProfile);
  });
});
