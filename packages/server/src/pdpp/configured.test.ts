import { describe, expect, it } from "vitest";
import { pdppIsConfigured } from "./bootstrap.js";

describe("pdppIsConfigured", () => {
  it("counts a configured service that did not mount", () => {
    expect(pdppIsConfigured({ pdpp: { enabled: true } }, undefined)).toBe(true);
  });
  it("counts a mounted service even when the flag is off", () => {
    expect(pdppIsConfigured({ pdpp: { enabled: false } }, {})).toBe(true);
  });
  it("is false only when PDPP is neither configured nor mounted", () => {
    expect(pdppIsConfigured({ pdpp: { enabled: false } }, undefined)).toBe(
      false,
    );
  });
});
