import { describe, expect, it } from "vitest";
import { canonicalJson, type JsonObject } from "./json.js";
import { overlay } from "./overlay.js";
import { stampRun, plainRecords } from "./records.js";
import { InvalidObservationTimeError, MissingKeyFieldError } from "./errors.js";
import { stamped } from "./test-support/index.js";

describe("overlay properties beyond the vectors", () => {
  it("gives identical bytes for any input order", () => {
    const base = stamped(
      [
        { id: 3, v: "c" },
        { id: 1, v: "a" },
      ],
      100,
    );
    const run = stamped(
      [
        { id: 2, v: "b" },
        { id: 1, v: "A" },
      ],
      200,
    );
    const first = canonicalJson(overlay(base, run, ["id"]));
    const second = canonicalJson(
      overlay([...base].reverse(), [...run].reverse(), ["id"]),
    );
    expect(second).toBe(first);
  });

  it("does not modify its inputs", () => {
    const base = stamped([{ id: 2 }, { id: 1 }], 100);
    const run = stamped([{ id: 3 }], 200);
    const before = canonicalJson([base, run]);
    overlay(base, run, ["id"]);
    expect(canonicalJson([base, run])).toBe(before);
  });

  it("does not pollute prototypes when records carry __proto__ and constructor", () => {
    const records = JSON.parse(
      '[{"__proto__":{"polluted":true},"constructor":"c","id":1}]',
    ) as JsonObject[];
    const result = overlay([], stamped(records, 1), ["id"]);
    expect(result).toHaveLength(1);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
    expect(Object.getPrototypeOf(result[0]!.record)).toBe(Object.prototype);
  });

  it("fails the whole overlay, never drops a record, on a missing key field", () => {
    const run = stamped([{ id: 1 }, { nope: true }, { id: 3 }], 1);
    expect(() => overlay([], run, ["id"])).toThrow(MissingKeyFieldError);
  });

  it("treats an explicit null key value as present", () => {
    expect(
      plainRecords(overlay([], stamped([{ id: null, v: 1 }], 1), ["id"])),
    ).toEqual([{ id: null, v: 1 }]);
  });

  it("never lets an older observation replace a newer one, in either input order", () => {
    const newer = stamped([{ id: 1, v: "newer" }], 300);
    const older = stamped([{ id: 1, v: "older" }], 100);
    expect(plainRecords(overlay(newer, older, ["id"]))).toEqual([
      { id: 1, v: "newer" },
    ]);
    expect(plainRecords(overlay(older, newer, ["id"]))).toEqual([
      { id: 1, v: "newer" },
    ]);
  });

  it("rejects an observation time that is not a non-negative integer", () => {
    for (const observedAt of [-1, 1.5, Number.NaN, Infinity, "1", null]) {
      expect(() =>
        overlay(
          [],
          [{ record: { id: 1 }, observedAt: observedAt as number }],
          ["id"],
        ),
      ).toThrow(InvalidObservationTimeError);
    }
    expect(() => stampRun({ records: [], observedAt: -1 })).toThrow(
      InvalidObservationTimeError,
    );
  });
});
