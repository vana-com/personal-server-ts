import { describe, expect, it } from "vitest";
import {
  InvalidConnectionLifetime,
  formatLifetime,
  holdsLifetime,
  parseLifetime,
} from "./delete-lifetime.js";

const WORK = "a".repeat(16);
const C = "fixture-source";

describe("the lifetime token", () => {
  it("round-trips, sorted by namespace, and names no row as `v1:`", () => {
    const token = formatLifetime(
      C,
      new Map([
        [WORK, 3],
        ["", 1],
      ]),
    );
    expect(token).toBe(`v2:${C}:@1,${WORK}@3`);
    expect(parseLifetime(C, token)).toEqual(
      new Map([
        ["", 1],
        [WORK, 3],
      ]),
    );
    expect(parseLifetime(C, `v2:${C}:`)).toEqual(new Map());
  });

  it("orders encoded entries without changing the caller's map", () => {
    const input = new Map([
      [WORK, 3],
      ["", 1],
    ]);
    const before = [...input];
    expect(formatLifetime(C, input)).toBe(`v2:${C}:@1,${WORK}@3`);
    expect([...input]).toEqual(before);
  });

  it("returns an independent map on each parse", () => {
    const token = formatLifetime(C, new Map([["", 1]]));
    const first = parseLifetime(C, token) as Map<string, number>;
    first.clear();
    expect(parseLifetime(C, token)).toEqual(new Map([["", 1]]));
  });

  it("refuses what the server did not write", () => {
    for (const token of [
      "",
      "v1",
      "v1:@1",
      `v2:${C}`,
      `v2:${C}:@0`,
      `v2:${C}:@01`,
      `v2:${C}:@1,@2`,
      `v2:${C}:${WORK}@3,@1`,
      `v2:${C}:abc@1`,
      `v2:${C}:@1,`,
      `v3:${C}:@1`,
    ])
      expect(() => parseLifetime(C, token), token).toThrow(
        InvalidConnectionLifetime,
      );
  });

  it("names one connector: a token read for another is refused", () => {
    const token = formatLifetime("other-source", new Map([["", 1]]));
    expect(() => parseLifetime(C, token)).toThrow(InvalidConnectionLifetime);
    // A connector id that is a prefix of another's does not match it either.
    expect(() =>
      parseLifetime(C, formatLifetime(`${C}-2`, new Map([["", 1]]))),
    ).toThrow(InvalidConnectionLifetime);
    expect(() =>
      parseLifetime(`${C}-2`, formatLifetime(C, new Map([["", 1]]))),
    ).toThrow(InvalidConnectionLifetime);
  });

  it("round-trips a connector id with separators in it", () => {
    const id = "a:b,c/d@e%f";
    const token = formatLifetime(id, new Map([["", 2]]));
    expect(parseLifetime(id, token)).toEqual(new Map([["", 2]]));
    expect(() => parseLifetime("a", token)).toThrow(InvalidConnectionLifetime);
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
