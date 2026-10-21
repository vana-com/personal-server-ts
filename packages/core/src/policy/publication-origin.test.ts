import { describe, expect, it } from "vitest";
import { nonOwnerPublicationIsPdpp } from "./publication-origin.js";

describe("nonOwnerPublicationIsPdpp", () => {
  it("is legacy only when PDPP is explicitly disabled", () => {
    expect(nonOwnerPublicationIsPdpp(false)).toBe(false);
    expect(nonOwnerPublicationIsPdpp(() => false)).toBe(false);
  });
  it("is PDPP when enabled, unknown, or the check throws", () => {
    expect(nonOwnerPublicationIsPdpp(true)).toBe(true);
    expect(nonOwnerPublicationIsPdpp(undefined)).toBe(true);
    expect(
      nonOwnerPublicationIsPdpp(() => {
        throw new Error("config unavailable");
      }),
    ).toBe(true);
  });
});
