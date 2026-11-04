import { describe, it, expect } from "vitest";
import { planIngest, type CurrentContent } from "./ingest-plan.js";
import type { PdppRecordEnvelopeInput } from "./types.js";

const PRIMARY_KEY = ["id"];

function envelope(data: Record<string, unknown>): PdppRecordEnvelopeInput {
  return {
    stream: "messages",
    instance: "source:synthetic",
    key: String(data.id),
    data,
    emitted_at: "2026-11-01T00:00:00.000Z",
  } as unknown as PdppRecordEnvelopeInput;
}

function plan(
  existing: Record<string, unknown> | null,
  incoming: Record<string, unknown>,
) {
  const current = (): CurrentContent | undefined =>
    existing === null ? undefined : { deleted: false, data: existing };
  return planIngest(0, envelope(incoming), "append_only", PRIMARY_KEY, current);
}

const stored = {
  id: "message-1",
  conversation_id: "conversation-1",
  content_type: "text",
  content: null,
  role: "assistant",
};

describe("planIngest append_only null-to-empty fill", () => {
  it("accepts a null field re-emitted as an empty string when all else is equal", () => {
    const result = plan(stored, { ...stored, content: "" });
    expect(result.outcome).toEqual({ index: 0, outcome: "accepted" });
    expect(result.write).toEqual({
      recordKey: "message-1",
      data: { ...stored, content: "" },
    });
  });

  it("keeps a null to non-empty change refused as append_only_conflict", () => {
    const result = plan(stored, { ...stored, content: "x" });
    expect(result.outcome).toEqual({
      index: 0,
      outcome: "unchanged",
      flag: "append_only_conflict",
    });
    expect(result.write).toBeUndefined();
  });

  it("keeps an empty string to null change refused as append_only_conflict", () => {
    const result = plan(
      { ...stored, content: "" },
      { ...stored, content: null },
    );
    expect(result.outcome).toEqual({
      index: 0,
      outcome: "unchanged",
      flag: "append_only_conflict",
    });
    expect(result.write).toBeUndefined();
  });

  it("keeps a null to empty fill refused when another field also changes", () => {
    const result = plan(stored, {
      ...stored,
      content: "",
      role: "user",
    });
    expect(result.outcome).toEqual({
      index: 0,
      outcome: "unchanged",
      flag: "append_only_conflict",
    });
    expect(result.write).toBeUndefined();
  });
});
