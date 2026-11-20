import { describe, expect, it } from "vitest";
import {
  InvalidConnectionLifetime,
  formatLifetime,
  holdsLifetime,
  parseLifetime,
} from "./delete-lifetime.js";

const WORK = "a".repeat(16);

describe("the lifetime token", () => {
  it("round-trips, sorted by namespace, and names no row as `v1:`", () => {
    const token = formatLifetime(
      new Map([
        [WORK, 3],
        ["", 1],
      ]),
    );
    expect(token).toBe(`v1:@1,${WORK}@3`);
    expect(parseLifetime(token)).toEqual(
      new Map([
        ["", 1],
        [WORK, 3],
      ]),
    );
    expect(parseLifetime("v1:")).toEqual(new Map());
  });

  it("refuses what the server did not write", () => {
    for (const token of [
      "",
      "v1",
      "v2:@1",
      "v1:@0",
      "v1:@01",
      "v1:@1,@2",
      `v1:${WORK}@3,@1`,
      "v1:abc@1",
      "v1:@1,",
    ])
      expect(() => parseLifetime(token), token).toThrow(
        InvalidConnectionLifetime,
      );
  });
});

describe("holdsLifetime", () => {
  const named = new Map([["", 1]]);
  it("holds while its row is live at the version it names", () => {
    expect(holdsLifetime(named, new Map([["", 1]]), new Map())).toBe(true);
  });
  it("holds once its row is tombstoned at the next version, and not at a later one", () => {
    expect(holdsLifetime(named, new Map(), new Map([["", 2]]))).toBe(true);
    expect(holdsLifetime(named, new Map(), new Map([["", 4]]))).toBe(false);
  });
  it("does not hold for a row live at another version or one it does not name", () => {
    expect(holdsLifetime(named, new Map([["", 3]]), new Map())).toBe(false);
    expect(
      holdsLifetime(
        named,
        new Map([
          ["", 1],
          [WORK, 1],
        ]),
        new Map(),
      ),
    ).toBe(false);
    expect(holdsLifetime(new Map(), new Map([["", 1]]), new Map())).toBe(false);
  });
});
