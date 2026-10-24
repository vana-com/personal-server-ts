import { describe, expect, it } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyBindingsForProfile,
  projectPdppRecordsToLegacyPayload,
  projectStoredScopeToLegacyPayload,
} from "./index.js";
import type { PdppRecord } from "./types.js";

const bindingSources = [
  ["base map", LEGACY_SCOPE_BINDINGS],
  ["chatgpt profile map", legacyBindingsForProfile("chatgpt")],
] as const;

describe("Personal Server legacy projection boundary", () => {
  it.each(
    bindingSources.flatMap(
      ([source, bindings]) =>
        [
          [
            `${source}: missing count`,
            bindings,
            { id: "partial", current_node: null },
          ],
          [
            `${source}: missing id`,
            bindings,
            { current_node: null, message_count_on_current_branch: 0 },
          ],
        ] as const,
    ),
  )("%s rejects a partial conversation", (_name, bindings, conversation) => {
    const records: PdppRecord[] = [
      { stream: "conversations", data: conversation },
    ];
    const options = { fetchedStreams: ["conversations", "messages"] };
    expect(
      bindings.get("chatgpt.conversations")?.project(records, options),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "invalid_value",
        scope: "chatgpt.conversations",
        reason: "Conversation lacks required branch identity or count",
      },
    });
    expect(
      projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        records,
        options,
      ),
    ).toMatchObject({
      ok: false,
      error: {
        kind: "invalid_value",
        scope: "chatgpt.conversations",
        reason: "Conversation lacks required branch identity or count",
      },
    });
  });

  it("rejects a hidden message without an id before replacing a conversation list", () => {
    expect(
      projectPdppRecordsToLegacyPayload(
        "chatgpt.conversations",
        [
          {
            stream: "conversations",
            data: {
              id: "complete",
              current_node: null,
              message_count_on_current_branch: 0,
            },
          },
          {
            stream: "messages",
            data: {
              conversation_id: "complete",
              role: "system",
              on_current_branch: false,
            },
          },
        ],
        { fetchedStreams: ["conversations", "messages"] },
      ),
    ).toEqual({
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope: "chatgpt.conversations",
        reason: "messages.id is unavailable",
      },
    });
  });

  it.each(["2026-09-23", null])(
    "keeps YouTube watchedAt at source precision: %s",
    (watchedDate) => {
      const result = projectPdppRecordsToLegacyPayload(
        "youtube.history",
        [
          {
            stream: "watch_history",
            data: {
              id: "watch",
              position: 0,
              watched_date: watchedDate,
              video_url: "https://youtube.com/watch?v=watch",
            },
          },
        ],
        { fetchedStreams: ["watch_history"] },
      );
      expect(result).toMatchObject({
        ok: true,
        payload: {
          history: [{ watchedAt: watchedDate, watchedAtText: watchedDate }],
        },
      });
    },
  );

  it("keeps legacy conversation identity when stored message rows are incomplete", () => {
    expect(
      projectStoredScopeToLegacyPayload(
        "chatgpt.conversations",
        {
          records: [
            {
              id: "partial",
              title: "Saved title",
              create_time: "2026-09-23T00:00:00Z",
              update_time: "2026-09-24T00:00:00Z",
              current_node: null,
            },
          ],
        },
        { "chatgpt.messages": { records: [] } },
      ),
    ).toEqual({
      conversations: [
        {
          id: "partial",
          title: "Saved title",
          create_time: "2026-09-23T00:00:00Z",
          update_time: "2026-09-24T00:00:00Z",
        },
      ],
      total: 1,
    });
  });
});
