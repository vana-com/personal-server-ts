import { describe, expect, it } from "vitest";
import { receiptOutcomes, receiptReason } from "./legacy-quarantine.js";

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
});
