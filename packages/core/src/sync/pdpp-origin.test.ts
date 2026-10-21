import { describe, expect, it } from "vitest";
import { hasPdppOrigin, isPdppProducer } from "./pdpp-import.js";

describe("hasPdppOrigin producer stamps", () => {
  it.each(["pdpp-projector", "pdpp-import-projection", "pdpp-derivative"])(
    "treats the %s stamp as PDPP origin",
    (producer) => {
      expect(isPdppProducer(producer)).toBe(true);
      expect(hasPdppOrigin({ data: { id: 1 }, producer })).toBe(true);
    },
  );

  it("treats an unstamped legacy envelope and an unknown stamp as legacy", () => {
    expect(hasPdppOrigin({ data: { id: 1 } })).toBe(false);
    expect(hasPdppOrigin({ data: { id: 1 }, producer: "pdpp-other" })).toBe(
      false,
    );
    expect(isPdppProducer("pdpp-other")).toBe(false);
    expect(hasPdppOrigin(undefined)).toBe(false);
  });
});
