import { describe, expect, it } from "vitest";
import { deriveOuraCollectionRequirements } from "./index.js";

describe("Oura earliest required collection day", () => {
  it("uses actual days across all legacy collections and stored PDPP rows", () => {
    expect(
      deriveOuraCollectionRequirements([
        {
          scope: "oura.sleep",
          data: {
            dailyScores: [{ day: "2026-07-22" }],
            sleepPeriods: [{ day: "2026-07-20" }],
          },
        },
        {
          scope: "oura.readiness",
          data: { records: [{ id: "r", day: "2026-07-21" }] },
        },
        { scope: "oura.activity", data: { days: [{ day: "2026-07-23" }] } },
      ]),
    ).toEqual({ ok: true, since: "2026-07-20" });
    expect(deriveOuraCollectionRequirements([])).toEqual({
      ok: true,
      since: null,
    });
    expect(
      deriveOuraCollectionRequirements([
        { scope: "oura.sleep", data: { dailyScores: [], sleepPeriods: [] } },
      ]),
    ).toEqual({ ok: true, since: null });
  });
  it.each([
    undefined,
    null,
    "",
    "2026-02-30",
    "2026-7-1",
    "2026-07-21T00:00:00Z",
    20260721,
  ])("fails closed on an invalid retained entity day %s", (day) => {
    expect(
      deriveOuraCollectionRequirements([
        { scope: "oura.activity", data: { days: [{ day }] } },
      ]),
    ).toMatchObject({
      ok: false,
      reason: "invalid_day",
      scope: "oura.activity",
    });
  });
  it.each([
    null,
    {},
    { days: null },
    { days: {} },
    { records: [{ data: { day: "2026-07-21" } }] },
    { days: [null] },
  ])("refuses malformed history %j", (data) => {
    expect(
      deriveOuraCollectionRequirements([{ scope: "oura.activity", data }]),
    ).toMatchObject({ ok: false });
  });
});
