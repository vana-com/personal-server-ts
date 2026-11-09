import { describe, expect, it } from "vitest";
import { legacyRetireSwitched } from "./switch.js";

describe("the one gate of legacy import and retire", () => {
  it("is off unless the host turned stream-sync writing on", () => {
    expect(legacyRetireSwitched({})).toBe(false);
    expect(legacyRetireSwitched({ streamSync: {} })).toBe(false);
    expect(legacyRetireSwitched({ streamSync: { write: false } })).toBe(false);
    expect(legacyRetireSwitched({ streamSync: { write: true } })).toBe(true);
  });
});
