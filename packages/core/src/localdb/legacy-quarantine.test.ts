import { describe, expect, it } from "vitest";
import {
  quarantineTally,
  receiptOutcomes,
  receiptReason,
} from "./legacy-quarantine.js";

describe("receipt outcomes", () => {
  it("round-trips the blocked count and the quarantine counts", () => {
    const reason = receiptReason({ blocked: 2, quarantined: { a: 1 } });
    expect(receiptOutcomes(reason)).toEqual({
      blocked: 2,
      quarantined: { a: 1 },
    });
    expect(receiptReason({ blocked: 0, quarantined: {} })).toBeNull();
    expect(receiptOutcomes(null)).toEqual({ blocked: 0, quarantined: {} });
  });

  it("reads a receipt written before blocked rows were counted", () => {
    expect(receiptOutcomes('quarantined:{"superseded":3}')).toEqual({
      blocked: 0,
      quarantined: { superseded: 3 },
    });
  });

  it("counts and round-trips reasons a host names like Object.prototype members", () => {
    // A reason is a host's string. As a plain-object key, `__proto__` is
    // dropped and `constructor` finds Object's own function.
    const tally = quarantineTally();
    tally.add("__proto__", 2);
    tally.add("constructor", 3);
    tally.add("constructor");
    tally.add("toString");
    expect(tally.total).toBe(7);
    const entries = (counts: Readonly<Record<string, number>>) =>
      new Map(Object.entries(counts));
    const expected = new Map([
      ["__proto__", 2],
      ["constructor", 4],
      ["toString", 1],
    ]);
    expect(entries(tally.counts())).toEqual(expected);
    const reason = receiptReason({ blocked: 1, quarantined: tally.counts() });
    const back = receiptOutcomes(reason);
    expect(back.blocked).toBe(1);
    expect(entries(back.quarantined)).toEqual(expected);
  });
});
