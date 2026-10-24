import { describe, expect, it } from "vitest";
import { compareTime, parseTime, timeSortKey } from "./time.js";
import { withinTimeConstraint } from "../ports/pdpp-auth.js";
it("compares offsets and arbitrary fractional precision exactly", () => {
  expect(
    compareTime(
      "2026-01-01T13:00:00+02:00",
      "2026-01-01T12:00:00Z",
      "date-time",
    ),
  ).toBe(-1);
  expect(
    compareTime(
      "2026-01-01T12:00:00.100Z",
      "2026-01-01T12:00:00.1Z",
      "date-time",
    ),
  ).toBe(0);
  expect(
    compareTime(
      "2026-01-01T12:00:00.0001Z",
      "2026-01-01T12:00:00.0002Z",
      "date-time",
    ),
  ).toBe(-1);
});
it("validates calendar, types, offsets and RFC3339 spelling", () => {
  for (const value of [
    "January 1, 2026",
    "2026-02-29",
    "2026-04-31",
    "2026-01-01T00:00:00",
    "2026-01-01T24:00:00Z",
    "2026-01-01T00:00:00+24:00",
  ])
    expect(parseTime(value, "date-time")).toBeNull();
  expect(parseTime("2024-02-29", "date")).not.toBeNull();
  expect(parseTime("2026-01-01T00:00:00Z", "date")).toBeNull();
  expect(
    compareTime(
      "2026-01-01t00:00:00-00:00",
      "2026-01-01T00:00:00z",
      "date-time",
    ),
  ).toBe(0);
});
it("places real leap seconds between seconds and rejects fictional leaps", () => {
  expect(
    compareTime("2016-12-31T23:59:60Z", "2017-01-01T00:00:00Z", "date-time"),
  ).toBe(-1);
  expect(
    compareTime(
      "2017-01-01T00:59:60+01:00",
      "2016-12-31T23:59:60Z",
      "date-time",
    ),
  ).toBe(0);
  expect(parseTime("2026-12-31T23:59:60Z", "date-time")).toBeNull();
});
it("excludes invalid records and uses exact instants for legacy constraints", () => {
  expect(
    withinTimeConstraint("2026-99-99", {
      field: "at",
      since: "2026-01-01",
      until: "2027-01-01",
    }),
  ).toBe(false);
  expect(
    withinTimeConstraint("2026-01-01T13:00:00+02:00", {
      field: "at",
      since: "2026-01-01T12:00:00Z",
    }),
  ).toBe(false);
});
it("fails closed on malformed frozen temporal type", () => {
  expect(
    withinTimeConstraint("2026-01-01T00:00:00Z", {
      field: "at",
      type: "epoch" as "date-time",
      since: "2025-01-01T00:00:00Z",
    }),
  ).toBe(false);
});

it("keeps untyped current date-only bounds compatible with timestamp records", () => {
  expect(
    withinTimeConstraint("2026-01-15T12:00:00+01:00", {
      field: "at",
      since: "2026-01-01",
      until: "2026-02-01",
    }),
  ).toBe(true);
  expect(
    withinTimeConstraint("2026-02-01T00:00:00Z", {
      field: "at",
      since: "2026-01-01",
      until: "2026-02-01",
    }),
  ).toBe(false);
  expect(
    withinTimeConstraint("2026-01-15", {
      field: "at",
      since: "2026-01-01T00:00:00Z",
    }),
  ).toBe(true);
  // Typed candidate dates retain strict type separation.
  expect(
    withinTimeConstraint("2026-01-15T00:00:00Z", {
      field: "at",
      type: "date",
      since: "2026-01-01",
    }),
  ).toBe(false);
});

it("preserves legacy AS bound syntax while candidate bounds and record values stay strict", () => {
  expect(
    withinTimeConstraint("2026-01-15T12:00:00Z", {
      field: "at",
      since: "January 1, 2026",
      until: "February 1, 2026",
    }),
  ).toBe(true);
  expect(
    withinTimeConstraint("2026-01-15T12:00:00Z", {
      field: "at",
      type: "date-time",
      since: "January 1, 2026",
    }),
  ).toBe(false);
  expect(
    withinTimeConstraint("January 15, 2026", {
      field: "at",
      since: "January 1, 2026",
    }),
  ).toBe(false);
});

it("interprets legacy offset-less bounds identically on servers in every time zone", () => {
  const previous = process.env.TZ;
  try {
    for (const zone of ["UTC", "America/Chicago", "Asia/Tokyo"]) {
      process.env.TZ = zone;
      for (const since of ["2026-01-01T00:00:00", "January 1, 2026"])
        expect(
          withinTimeConstraint("2026-01-01T03:00:00Z", { field: "at", since }),
        ).toBe(true);
      expect(
        withinTimeConstraint("2025-12-31T23:00:00Z", {
          field: "at",
          since: "January 1, 2026 GMT+0200",
        }),
      ).toBe(true);
    }
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});

describe("timeSortKey", () => {
  it("orders keys exactly as compareTime orders instants", () => {
    const values = [
      "2026-01-01T00:00:00Z",
      "2026-01-01T00:00:00.1Z",
      "2026-01-01T00:00:00.10Z",
      "2026-01-01T00:00:00.05Z",
      "2026-01-01T00:30:00+01:00",
      "2025-12-31T23:45:00Z",
      "2016-12-31T23:59:60Z",
      "2017-01-01T00:00:00Z",
      "1969-07-20T20:17:40Z",
      "0001-01-01T00:00:00Z",
      "9999-12-31T23:59:59.999999999Z",
    ];
    for (const a of values)
      for (const b of values) {
        const ka = timeSortKey(a);
        const kb = timeSortKey(b);
        expect(Math.sign(ka < kb ? -1 : ka > kb ? 1 : 0)).toBe(
          compareTime(a, b, "date-time"),
        );
      }
  });

  it("sorts an invalid timestamp after every valid one, by its text", () => {
    expect(timeSortKey("yesterday") > timeSortKey("9999-12-31T23:59:59Z")).toBe(
      true,
    );
    expect(timeSortKey("a") < timeSortKey("b")).toBe(true);
  });
});
