import { describe, expect, it } from "vitest";
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
