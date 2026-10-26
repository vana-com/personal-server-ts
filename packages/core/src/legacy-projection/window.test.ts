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
    const scope = "chatgpt.conversations";
    const window = LEGACY_SCOPE_BINDINGS.get(scope)!.window!;
    const records = chatgptRecords();
    const options = {
      fetchedStreams: ["conversations", "messages"],
      orderByPrimaryKey: true,
      profileKey: "chatgpt",
      now: NOW,
    };
    const whole = projectPdppRecordsToLegacyPayload(scope, records, options);
    expect(whole.ok).toBe(true);
    if (!whole.ok) return;

    const parents = records
      .filter((record) => record.stream === window.parentStream)
      .map((record) => record.data)
      .sort(window.parentOrder);
    const joined: unknown[] = [];
    const sums: Record<string, number> = {};
    for (const size of [2, 1, 3, 1]) {
      const slice = parents.splice(0, size);
      const ids = new Set(slice.map((parent) => parent.id));
      const part = projectPdppRecordsToLegacyPayload(
        scope,
        [
          ...slice.map((data) => ({ stream: window.parentStream, data })),
          ...records.filter(
            (record) =>
              record.stream === window.childStream &&
              ids.has(record.data[window.childKey]),
          ),
        ],
        options,
      );
      expect(part.ok).toBe(true);
      if (!part.ok) return;
      const payload = part.payload as Record<string, unknown>;
      joined.push(...(payload[window.arrayKey] as unknown[]));
      for (const key of window.sumKeys) {
        sums[key] = (sums[key] ?? 0) + (payload[key] as number);
      }
    }
    expect(parents).toHaveLength(0);
    expect(joined).toHaveLength(7);

    expect({ [window.arrayKey]: joined, ...sums }).toEqual(whole.payload);
    expect(Object.keys(whole.payload as object)).toEqual([
      window.arrayKey,
      ...window.sumKeys,
    ]);
  });
});
