import { describe, it, expect } from "vitest";
import { PDPP_VERSION } from "./pdpp-version.js";

describe("PDPP_VERSION", () => {
  it("is the spec-core.md §8 date-shaped version string, not a semver string", () => {
    // spec-core.md's own normative example is `PDPP-Version: 2026-04-06` —
    // a date, not a semver like "0.1.0". Guards against this constant
    // silently drifting back to a semver shape that would again disagree
    // with whatever the AS lane's PDPP_API_VERSION uses.
    expect(PDPP_VERSION).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });
});
