import { afterEach, describe, expect, it } from "vitest";
import { LEGACY_SCOPE_BINDINGS } from "../legacy-projection/index.js";
import { scopeDeclarationCursor } from "./legacy-scope-view.js";

describe("scopeDeclarationCursor", () => {
  const binding = LEGACY_SCOPE_BINDINGS.get("icloud_notes.notes")!;
  const declared = binding.optionalStreams;
  afterEach(() => {
    binding.optionalStreams = declared;
  });

  it("names the streams a binding serves without", () => {
    expect(declared).toEqual(["profile"]);
    expect(JSON.parse(scopeDeclarationCursor("icloud_notes.notes"))).toEqual([
      expect.objectContaining({ optionalStreams: ["profile"] }),
    ]);
  });

  it("changes when the optional streams change, so a cached view or cursor is not reused", () => {
    const before = scopeDeclarationCursor("icloud_notes.notes");
    binding.optionalStreams = [];
    const none = scopeDeclarationCursor("icloud_notes.notes");
    expect(none).not.toBe(before);
    // Absent and empty are one declaration.
    binding.optionalStreams = undefined;
    expect(scopeDeclarationCursor("icloud_notes.notes")).toBe(none);
  });
});
