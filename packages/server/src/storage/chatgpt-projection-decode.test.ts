import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { readCanonicalLegacyScope } from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const schema = {
  type: "object",
  required: ["id", "conversation_id"],
  properties: {
    content: {
      type: ["string", "null"],
      x_pdpp_text_encoding: "pdpp-safe-escape-v1",
    },
    tool_calls: { type: "array", x_pdpp_text_encoding: "pdpp-safe-escape-v1" },
    blob_ref: {
      x_pdpp_blob_projects_field: "content",
      x_pdpp_blob_codec: "json-string-v1",
    },
  },
};
const declarations = createStreamDeclarationRegistry([
  {
    name: "messages",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "create_time",
    requiredFields: ["id", "conversation_id"],
    schema,
  },
]);

describe("canonical ChatGPT declared text over SQLite", () => {
  it.each([false, true])(
    "preserves valid peers and reports malformed encoded rows (malformed=%s)",
    async (malformed) => {
      const store = createSqliteRecordStore(new Database(":memory:"));
      try {
        const selection = {
          instance: "test",
          sourceId: "https://registry.pdpp.dev/sources/chatgpt",
          method: "chatgpt",
        };
        store.registerConnection({ ...selection, label: "test" });
        const messages: Record<string, unknown>[] = [
          {
            id: "valid-m",
            conversation_id: "valid",
            content: "hello\\u0000",
            role: "user",
            content_type: "text",
            tool_calls: [{ ["key\\u0000"]: [{ text: "nested\\u005C" }] }],
          },
          {
            id: "tool-m",
            conversation_id: "tool",
            role: "tool",
            content_type: "code",
            tool_calls: [{ text_ref: "content" }],
          },
          ...(malformed
            ? [
                {
                  id: "bad-m",
                  conversation_id: "bad",
                  content: "bad",
                  role: "user",
                  content_type: "text",
                  tool_calls: [{ text: "\u0000" }],
                },
              ]
            : []),
        ];
        const rows = messages.flatMap((message) => [
          {
            stream: "conversations",
            data: {
              id: message.conversation_id,
              current_node: message.id,
              message_count_on_current_branch: 1,
            },
          },
          {
            stream: "messages",
            data: { ...message, parent_id: null, on_current_branch: true },
          },
        ]);
        expect(
          store.ingestBatch(
            rows.map(({ stream, data }) => ({
              instance: "test",
              stream,
              key: String(data.id),
              data,
              emitted_at: "2026-10-17T00:00:00.000Z",
            })),
            () => "mutable_state",
            () => ["id"],
            { method: "chatgpt", generation: 1 },
          ).rejected,
        ).toEqual([]);
        const result = await readCanonicalLegacyScope({
          store,
          selection,
          scope: "chatgpt.conversations",
          declarations,
          pageSize: 1,
        });
        expect(result.ok).toBe(true);
        if (!result.ok) return;
        expect(result.complete).toBe(!malformed);
        const conversations = result.envelope.data.conversations as {
          id: string;
          messages: { content: string }[];
        }[];
        expect(conversations.map((c) => c.id)).toEqual(["tool", "valid"]);
        expect(conversations[0]!.messages).toEqual([]);
        expect(conversations[1]!.messages[0]!.content).toBe("hello\u0000");
        expect(result.diagnostics.sourceRowCounts).toEqual({
          conversations: malformed ? 3 : 2,
          messages: malformed ? 3 : 2,
        });
        if (malformed) {
          expect(result.diagnostics.omissions).toContainEqual({
            stream: "messages",
            count: 1,
            reasons: ["invalid_encoded_text: tool_calls"],
          });
          expect(result.diagnostics.omissions).toContainEqual({
            stream: "conversations",
            count: 1,
            reasons: [
              "Current branch message count does not match conversation",
            ],
          });
        } else expect(result.diagnostics.omissions).toEqual([]);
        // Projection is read-only: encoded strings and absent optional fields remain stored.
        const stored = store.listRecords("messages", {
          instanceIds: ["test"],
          limit: 10,
        }).data;
        expect(
          stored.find((row) => row.data.id === "valid-m")!.data.content,
        ).toBe("hello\\u0000");
        expect(
          Object.hasOwn(
            stored.find((row) => row.data.id === "tool-m")!.data,
            "content",
          ),
        ).toBe(false);
      } finally {
        store.close();
      }
    },
  );
});
