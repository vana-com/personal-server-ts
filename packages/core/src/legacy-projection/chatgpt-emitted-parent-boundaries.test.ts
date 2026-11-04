import { describe, expect, it } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "./index.js";
import type { PdppRecord } from "./types.js";

const T = "2026-11-03T00:00:00.000Z";
const conversation = (
  id: string,
  tip: string | null,
  count: number | null,
): PdppRecord => ({
  stream: "conversations",
  data: {
    id,
    title: id,
    create_time: T,
    update_time: T,
    current_node: tip,
    message_count_on_current_branch: count,
  },
});
const message = (
  id: string,
  node: string,
  parent: string | null,
  flag = true,
  role = "user",
): PdppRecord => ({
  stream: "messages",
  data: {
    id: `${id}:${node}`,
    conversation_id: id,
    parent_id: parent === null ? null : `${id}:${parent}`,
    on_current_branch: flag,
    role,
    content_type: "text",
    content: node,
    create_time: T,
    model_slug: null,
  },
});
function project(records: PdppRecord[]) {
  const result = LEGACY_SCOPE_BINDINGS.get("chatgpt.conversations")!.project(
    records,
    {
      fetchedStreams: ["conversations", "messages"],
      now: T,
      orderByPrimaryKey: true,
    },
  );
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result;
}

describe("ChatGPT emitted-parent boundary cases", () => {
  it("M02 follows a nearest retained ancestor without requiring a hidden system node", () => {
    const result = project([
      conversation("A", "a1", 2),
      message("A", "a0", "synthetic-root", false),
      // The connector removed a roleless intermediate node before emitting this parent.
      message("A", "a1", "a0", false),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        { id: "A", message_count: 2, messages: [{ id: "a0" }, { id: "a1" }] },
      ],
      total: 1,
    });
    expect(result.chatgptCoverageGaps).toBeUndefined();
    expect(result.chatgptBranchDiagnostics).toBeUndefined();
  });

  it("M03 counts an emitted tool node structurally while omitting it from legacy text", () => {
    const result = project([
      conversation("A", "a1", 3),
      message("A", "a0", "root", false),
      message("A", "tool", "a0", false, "tool"),
      message("A", "a1", "tool", false, "assistant"),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        { message_count: 2, messages: [{ id: "a0" }, { id: "a1" }] },
      ],
      total: 1,
    });
    expect(result.chatgptBranchDiagnostics).toBeUndefined();
    expect(result.chatgptCoverageGaps).toBeUndefined();
  });

  it("M05 follows an edited user sibling and its answer instead of the stored old branch", () => {
    const result = project([
      conversation("A", "new-answer", 3),
      message("A", "shared", "root"),
      message("A", "old-user", "shared"),
      message("A", "old-answer", "old-user", true, "assistant"),
      message("A", "new-user", "shared", false),
      message("A", "new-answer", "new-user", false, "assistant"),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        {
          message_count: 3,
          messages: [
            { id: "shared" },
            { id: "new-user" },
            { id: "new-answer" },
          ],
        },
      ],
      total: 1,
    });
    expect(
      result.retainedChatgptMessages?.map((entry) => entry.message.id),
    ).toEqual(["old-user", "old-answer"]);
    expect(result.chatgptCoverageGaps).toBeUndefined();
  });

  it("M06 retains the first-version parent P rather than substituting the later retained Q", () => {
    const result = project([
      conversation("A", "M", 2),
      message("A", "root", "synthetic-root", false),
      message("A", "P", "root", false),
      // A repeat detail wanted Q, but append-only storage kept M's first parent P.
      message("A", "M", "P"),
      message("A", "Q", "root"),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        {
          message_count: 3,
          messages: [{ id: "root" }, { id: "P" }, { id: "M" }],
        },
      ],
      total: 1,
    });
    expect(result.chatgptBranchDiagnostics).toMatchObject([
      {
        reason: "declared_count_below_walked",
        declaredCount: 2,
        walkedCount: 3,
      },
    ]);
    expect(
      result.retainedChatgptMessages?.map((entry) => entry.message.id),
    ).toEqual(["Q"]);
  });

  it("M06/M10 does not replace an unavailable first-version parent with a flagged sibling", () => {
    const result = project([
      conversation("A", "M", 3),
      message("A", "M", "P"),
      message("A", "Q", "synthetic-root"),
      conversation("H", "healthy", 1),
      message("H", "healthy", "root"),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        { id: "H", message_count: 1, messages: [{ id: "healthy" }] },
      ],
      total: 1,
    });
    expect(result.chatgptCoverageGaps).toMatchObject([
      { declaredCount: 3, walkedCount: 1 },
    ]);
  });

  it("M08 starts from the emitted tip when a hidden provider tip was filtered", () => {
    const result = project([
      // The provider's hidden tip is not an emitted record or a stored lookup key.
      conversation("A", "emitted-tip", 2),
      message("A", "first", "synthetic-root", false),
      message("A", "emitted-tip", "first", false),
    ]);
    expect(result.payload).toMatchObject({
      conversations: [
        {
          message_count: 2,
          messages: [{ id: "first" }, { id: "emitted-tip" }],
        },
      ],
      total: 1,
    });
    expect(result.chatgptCoverageGaps).toBeUndefined();
    expect(result.chatgptBranchDiagnostics).toBeUndefined();
  });

  it("M13 represents an explicitly empty emitted branch without inventing a message", () => {
    const result = project([conversation("A", null, 0)]);
    expect(result.payload).toEqual({
      conversations: [
        {
          id: "A",
          title: "A",
          create_time: T,
          update_time: T,
          message_count: 0,
          messages: [],
          fetched_at: T,
        },
      ],
      total: 1,
    });
    expect(result.chatgptCoverageGaps).toBeUndefined();
    expect(result.diagnostics).toBeUndefined();
  });

  it("M13 never invents a zero count for list-only unknown branch metadata", () => {
    const result = project([conversation("A", "provider-hidden-tip", null)]);
    expect(result.payload).toEqual({ conversations: [], total: 0 });
    expect(result.diagnostics).toMatchObject([
      {
        kind: "records_dropped",
        reasons: ["Conversation lacks a current-branch message count"],
      },
    ]);
  });
});
