import { describe, expect, it } from "vitest";
import { ANTHROPIC_LIVE_BINDINGS } from "./bindings.js";
import liveDeclaration from "./declarations/anthropic-live-0.3.6.collection-profile.json";
import {
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";

const options = {
  profileKey: "anthropic-live",
  fetchedStreams: ["account_plan", "conversations", "messages"],
};
const records = [
  {
    stream: "account_plan",
    data: { id: "team-org", account_id: "team-org", plan_display_name: "Team" },
  },
  {
    stream: "conversations",
    data: { id: "chat-1", title: "Existing chat", message_count: 1 },
  },
  {
    stream: "messages",
    data: {
      id: "message-1",
      conversation_id: "chat-1",
      role: "human",
      content: "Keep this existing conversation",
      attachments: [],
    },
  },
];

describe("live Claude conversation compatibility", () => {
  it("delivers the existing conversation and its messages without claiming an official export", () => {
    const result = projectPdppRecordsToLegacyPayload(
      "claude.conversations",
      records,
      options,
    );
    expect(result).toMatchObject({
      ok: true,
      payload: {
        organizationId: "team-org",
        profile: { name: null, plan: "Team" },
        source: "live-session",
        total: 1,
        messageTotal: 1,
        conversations: [
          {
            id: "chat-1",
            href: "/chat/chat-1",
            messages: [
              { id: "message-1", content: "Keep this existing conversation" },
            ],
          },
        ],
      },
    });
    expect(
      projectPdppRecordsToLegacyPayload(
        "claude.conversations",
        records.slice(0, 2),
        options,
      ),
    ).toMatchObject({ ok: false, error: { kind: "incomplete_scope" } });
    expect(
      legacyScopeToPdppSelection("claude.projects", {
        profileKey: "anthropic-live",
      }),
    ).toMatchObject({ ok: false, error: { kind: "unsupported_profile" } });
  });
});

// Record shapes from data-connectors connectors/anthropic_live 0.3.6
// fixtures/scrubbed/pilot-real-shape. `message_count` is null when the run
// did not read the conversation detail (parsers.ts buildConversationRecord).
describe("live Claude message coverage", () => {
  const plan = {
    stream: "account_plan",
    data: {
      id: "account_plan",
      account_id: "00000000-0000-4000-8000-0000000000f1",
      plan_display_name: null,
    },
  };
  const conversation = (message_count: number | null | undefined) => ({
    stream: "conversations",
    data: {
      id: "00000000-0000-4000-8000-0000000000c1",
      title: "Example conversation",
      create_time: "2026-01-15T09:30:00.000000Z",
      update_time: "2026-01-15T09:42:10.000000Z",
      project_id: null,
      model: "claude-sonnet-4-6",
      ...(message_count === undefined ? {} : { message_count }),
      is_starred: false,
    },
  });
  const message = {
    stream: "messages",
    data: {
      id: "00000000-0000-4000-8000-0000000000a1",
      conversation_id: "00000000-0000-4000-8000-0000000000c1",
      role: "human",
      parent_id: "00000000-0000-4000-8000-000000000000",
      content: "Example question",
      model: null,
      model_source: null,
      create_time: "2026-01-15T09:30:00.000000Z",
      update_time: "2026-01-15T09:30:00.000000Z",
      attachments: [],
    },
  };
  const project = (records: { stream: string; data: object }[]) =>
    projectPdppRecordsToLegacyPayload(
      "claude.conversations",
      records as Parameters<typeof projectPdppRecordsToLegacyPayload>[1],
      options,
    );
  const unknownCount = {
    kind: "records_partial",
    stream: "conversations",
    count: 1,
    reasons: ["message_count_unknown"],
  };

  it.each([
    ["null, no messages", null, []],
    ["null, some messages", null, [message]],
    ["absent, no messages", undefined, []],
    ["absent, some messages", undefined, [message]],
  ])(
    "does not certify a conversation whose message count is %s",
    (_label, count, messages) => {
      const result = project([plan, conversation(count), ...messages]);
      expect(result).toMatchObject({
        ok: true,
        diagnostics: [unknownCount],
        payload: {
          total: 1,
          messageTotal: messages.length,
          conversations: [
            { messageCount: null, messages: { length: messages.length } },
          ],
        },
      });
    },
  );

  it.each([
    ["an explicit zero with no messages", 0, []],
    ["a matching positive count", 1, [message]],
  ])("certifies %s", (_label, count, messages) => {
    const result = project([plan, conversation(count), ...messages]);
    expect(result).toMatchObject({
      ok: true,
      payload: {
        messageTotal: count,
        conversations: [{ messageCount: count }],
      },
    });
    expect(result.ok && result.diagnostics).toBeFalsy();
  });

  it.each([
    ["more than fetched", 2],
    ["negative", -1],
    ["fractional", 0.5],
  ])("rejects a message count that is %s", (_label, count) => {
    expect(project([plan, conversation(count), message])).toMatchObject({
      ok: false,
      error: { kind: "incomplete_scope" },
    });
  });
});

describe("live Claude raw-envelope blobs", () => {
  it("treats only a declared blob_ref that projects no field as ancillary", () => {
    const binding = ANTHROPIC_LIVE_BINDINGS.get("claude.conversations");
    expect(binding?.ancillaryBlobStreams).toEqual(["conversations"]);
    for (const name of binding?.ancillaryBlobStreams ?? []) {
      const blobRef = liveDeclaration.streams.find(
        (stream) => stream.name === name,
      )?.schema.properties.blob_ref as Record<string, unknown> | undefined;
      expect(blobRef).toBeDefined();
      expect(blobRef).not.toHaveProperty("x_pdpp_blob_projects_field");
    }
  });
});
