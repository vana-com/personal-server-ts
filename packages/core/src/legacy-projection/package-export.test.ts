import { describe, expect, it } from "vitest";
import * as viaExport from "@opendatalabs/personal-server-ts-core/legacy-projection";
import * as viaSource from "./index.js";

// Consumers (unity-surfaces app-runtime) import the adapter through the
// package export, which resolves to the built dist. This proves the subpath
// exists and serves the same projection as the source module.
describe("@opendatalabs/personal-server-ts-core/legacy-projection", () => {
  it("exports every runtime name the source module exports", () => {
    expect(Object.keys(viaExport).sort()).toEqual(
      Object.keys(viaSource).sort(),
    );
  });

  it("projects ChatGPT records into the legacy body", () => {
    const result = viaExport.projectPdppRecordsToLegacyPayload(
      "chatgpt.conversations",
      [
        {
          stream: "conversations",
          data: {
            id: "c1",
            title: "t",
            create_time: "2026-01-01T00:00:00.000Z",
            update_time: "2026-01-01T00:00:00.000Z",
            current_node: "m1",
            message_count_on_current_branch: 1,
          },
        },
        {
          stream: "messages",
          data: {
            id: "m1",
            conversation_id: "c1",
            parent_id: null,
            children_ids: [],
            role: "user",
            content: "hi",
            content_type: "text",
            create_time: "2026-01-01T00:00:00.000Z",
            on_current_branch: true,
          },
        },
      ],
      {
        fetchedStreams: ["conversations", "messages"],
        now: "2026-01-02T00:00:00.000Z",
      },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const payload = result.payload as {
      total: number;
      conversations: { messages: unknown[] }[];
    };
    expect(payload.total).toBe(1);
    expect(payload.conversations[0]?.messages).toHaveLength(1);
  });
});
