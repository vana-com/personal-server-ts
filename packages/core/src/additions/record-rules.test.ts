import { describe, expect, it } from "vitest";

import { MEMORY_RECORD_RULES, memoryRecordRulesFor } from "./record-rules.js";

describe("memoryRecordRulesFor", () => {
  it("returns null for a scope with no entry", () => {
    expect(memoryRecordRulesFor("unknown.scope")).toBeNull();
    expect(memoryRecordRulesFor("test.scope")).toBeNull();
  });

  it("returns an empty list for a scope with no memory records", () => {
    expect(memoryRecordRulesFor("github.profile")).toEqual([]);
    expect(memoryRecordRulesFor("chatgpt.memories")).toEqual([]);
  });

  it("returns the rules for a ruled scope", () => {
    expect(memoryRecordRulesFor("github.repositories")).toBe(
      MEMORY_RECORD_RULES["github.repositories"],
    );
  });
});
