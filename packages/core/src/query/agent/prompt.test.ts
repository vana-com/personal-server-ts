import { describe, expect, it } from "vitest";

import {
  SYSTEM_PROMPT_TEMPLATE,
  SYSTEM_PROMPT_VERSION,
  buildSystemPrompt,
} from "./prompt.js";

describe("system prompt", () => {
  it("is versioned", () => {
    expect(SYSTEM_PROMPT_VERSION).toMatch(/^vana-query-prompt\/\d+$/);
  });

  it("carries every numbered rule from the prompt doc §4", () => {
    // These are the rules that stop specific, measured failure modes. If one
    // is dropped from the template the corresponding trap comes back.
    for (const rule of [
      "Compute, never estimate",
      "Read the profile first",
      "State your definitions and denominators",
      "requires reading everything",
      "Resolve the set before you aggregate it",
      "People appear under many names",
      "Distinguish what was measured from what was said",
      "is expensive",
      "Cite.",
      "Say what you do not know",
    ]) {
      expect(SYSTEM_PROMPT_TEMPLATE).toContain(rule);
    }
  });

  it("interpolates both placeholders and leaves none behind", () => {
    const built = buildSystemPrompt({
      scopes: [{ scope: "oura.sleep", itemCount: 1030, contentKind: "json" }],
    });
    expect(built.prompt).not.toContain("{{SCOPES}}");
    expect(built.prompt).not.toContain("{{PROFILES}}");
    expect(built.prompt).toContain("oura.sleep");
    expect(built.prompt).toContain("1,030 items");
  });

  it("injects the Oura profile in full, including the nap rule", () => {
    // The single highest-leverage sentence in the system: without it the
    // model averages naps into main sleep and is wrong by ~9% silently.
    const built = buildSystemPrompt({ scopes: [{ scope: "oura.sleep" }] });
    expect(built.prompt.toLowerCase()).toContain("long_sleep");
    expect(built.unprofiledScopes).toEqual([]);
  });

  it("reports scopes that have no profile instead of pretending", () => {
    const built = buildSystemPrompt({ scopes: [{ scope: "unknown.source" }] });
    expect(built.unprofiledScopes).toContain("unknown.source");
  });

  it("says so when the caller holds no scopes", () => {
    const built = buildSystemPrompt({ scopes: [] });
    expect(built.prompt).toContain("you hold no granted scopes");
  });

  it("reports summarization when the profile budget forces it", () => {
    const built = buildSystemPrompt({
      scopes: [{ scope: "oura.sleep" }, { scope: "chatgpt.conversations" }],
      profileBudgetChars: 400,
    });
    // Degradation must be visible (plan §4.3), not silent.
    expect(built.summarizedScopes.length).toBeGreaterThan(0);
  });
});
