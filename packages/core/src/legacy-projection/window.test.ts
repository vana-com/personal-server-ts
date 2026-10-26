import { describe, expect, it } from "vitest";
import {
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import type { PdppRecord } from "./types.js";

const NOW = "2026-10-26T00:00:00.000Z";

function chatgptRecords(): PdppRecord[] {
  // Update times with a tie, a missing time and an unparseable one, so the
  // windows' order depends on both the time and the id.
  const updates = [
    "2026-01-03T00:00:00.000Z",
    "2026-01-05T00:00:00.000Z",
    "2026-01-03T00:00:00.000Z",
    null,
    "not a time",
    "2026-01-04T00:00:00.000Z",
    "2026-01-01T00:00:00.000Z",
  ];
  const records: PdppRecord[] = [];
  updates.forEach((update_time, c) => {
    const id = `c${(7 - c) % 7}`;
    const count = c % 3;
    let parent: string | null = null;
    for (let m = 0; m < count; m++) {
      const node = `n${m}`;
      records.push({
        stream: "messages",
        data: {
          id: `${id}:${node}`,
          conversation_id: id,
          parent_id: parent ? `${id}:${parent}` : null,
          role: m % 2 ? "assistant" : "user",
          content: `message ${m} of ${id}`,
          content_type: "text",
          model_slug: null,
          create_time: "2026-01-01T00:00:00.000Z",
          on_current_branch: true,
        },
      });
      parent = node;
    }
    records.push({
      stream: "conversations",
      data: {
        id,
        title: `conversation ${id}`,
        create_time: "2026-01-01T00:00:00.000Z",
        update_time,
        current_node: parent,
        message_count_on_current_branch: count,
      },
    });
  });
  return records;
}

function claudeRecords(): PdppRecord[] {
  const records: PdppRecord[] = [
    {
      stream: "account_profile",
      data: {
        id: "org-1",
        organization_id: "org-1",
        plan: "Pro",
        full_name: "Ada Example",
        name_source: "browser_menu",
        metadata_status: "valid",
      },
    },
  ];
  // Ids that sort differently as plain text and as JSON text, a conversation
  // with no messages, and one whose count the source does not know.
  const ids = ["chat-b", 'chat-"q', "chat-a", "chat-a-2", "chat-c", "chat-d"];
  ids.forEach((id, c) => {
    const count = c % 4;
    for (let m = 0; m < count; m++) {
      records.push({
        stream: "messages",
        data: {
          id: `${id}:m${m}`,
          conversation_id: id,
          role: m % 2 ? "assistant" : "human",
          parent_id: m ? `${id}:m${m - 1}` : null,
          content: `message ${m} of ${id}`,
          create_time: `2026-01-01T00:0${m}:00Z`,
          update_time: null,
          attachments: [],
        },
      });
    }
    records.push({
      stream: "conversations",
      data: {
        id,
        title: `conversation ${id}`,
        create_time: "2026-01-01T00:00:00Z",
        update_time: "2026-01-02T00:00:00Z",
        project_id: null,
        message_count: c === 5 ? null : count,
        is_starred: c % 2 === 0,
      },
    });
  });
  return records;
}

/**
 * Project `records` whole, and again a window of parents at a time with
 * exactly their own children, and return both for comparison.
 */
function projectWhole(scope: string, records: PdppRecord[], options: object) {
  const window = LEGACY_SCOPE_BINDINGS.get(scope)!.window!;
  const whole = projectPdppRecordsToLegacyPayload(scope, records, options);
  expect(whole.ok).toBe(true);
  if (!whole.ok) throw new Error("whole projection failed");

  const parents = records
    .filter((record) => record.stream === window.parentStream)
    .map((record) => record.data)
    .sort(window.parentOrder);
  const total = parents.length;
  const joined: unknown[] = [];
  const sums: Record<string, number> = {};
  for (const size of [2, 1, 3, 1, 5]) {
    const slice = parents.splice(0, size);
    const ids = new Set(slice.map((parent) => parent.id));
    const part = projectPdppRecordsToLegacyPayload(
      scope,
      [
        ...slice.map((data) => ({ stream: window.parentStream, data })),
        ...records.filter(
          (record) =>
            record.stream !== window.parentStream &&
            (record.stream !== window.childStream ||
              ids.has(record.data[window.childKey])),
        ),
      ],
      options,
    );
    expect(part.ok).toBe(true);
    if (!part.ok) throw new Error("window projection failed");
    const payload = part.payload as Record<string, unknown>;
    joined.push(...(payload[window.arrayKey] as unknown[]));
    for (const key of window.sumKeys) {
      sums[key] = (sums[key] ?? 0) + (payload[key] as number);
    }
  }
  expect(parents).toHaveLength(0);
  expect(joined).toHaveLength(total);
  return { window, whole, joined, sums };
}

describe("windowed legacy projection", () => {
  it("declares windows only over bound streams with a one-field parent key", () => {
    for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
      const window = binding.window;
      if (!window) continue;
      expect(binding.pdppStreams, scope).toContain(window.parentStream);
      expect(binding.pdppStreams, scope).toContain(window.childStream);
      expect(binding.primaryKey[window.parentStream], scope).toHaveLength(1);
    }
  });

  it("joins chatgpt.conversations windows into the whole projection", () => {
    const { window, whole, joined, sums } = projectWhole(
      "chatgpt.conversations",
      chatgptRecords(),
      {
        fetchedStreams: ["conversations", "messages"],
        orderByPrimaryKey: true,
        profileKey: "chatgpt",
        now: NOW,
      },
    );
    expect({ [window.arrayKey]: joined, ...sums }).toEqual(whole.payload);
    expect(Object.keys(whole.payload as object)).toEqual([
      window.arrayKey,
      ...window.sumKeys,
    ]);
  });

  it("joins claude.conversations windows into the whole projection", () => {
    const { window, whole, joined, sums } = projectWhole(
      "claude.conversations",
      claudeRecords(),
      {
        fetchedStreams: ["account_profile", "conversations", "messages"],
        orderByPrimaryKey: true,
        now: NOW,
      },
    );
    // Every other payload key is the same in each window.
    expect({
      ...(whole.payload as object),
      [window.arrayKey]: joined,
      ...sums,
    }).toEqual(whole.payload);
    expect(sums.messageTotal).toBeGreaterThan(0);
  });
});
