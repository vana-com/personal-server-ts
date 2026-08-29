import { describe, expect, it } from "vitest";

import {
  AMBIGUOUS_READINGS,
  Q1_READINGS,
  Q14_READINGS,
  Q18_READINGS,
  classifyResolution,
  gradeAgainstReadings,
} from "./readings.js";

/**
 * The resolution-aware rule is only worth anything if it can fail a run. These
 * tests are the anti-cheat: most of them assert a *rejection*.
 */
describe("resolution-aware grading", () => {
  it("passes a declared reading whose number follows from it", () => {
    const out = gradeAgainstReadings(
      Q1_READINGS,
      "Resolved 'the last month' to the last full calendar month, 2025-12-01 to 2025-12-31.",
      6.68,
    );
    expect(out.kind).toBe("pass");
    if (out.kind === "pass") expect(out.reading.id).toBe("calendarDec");
  });

  it("REJECTS a declared reading with another reading's number", () => {
    // The central anti-cheat: name December, return the trailing-31 figure.
    // Under strict grading this would have *passed*, because 6.5775 is what
    // the eval expects. It must not pass here.
    const out = gradeAgainstReadings(
      Q1_READINGS,
      "Resolved to the last full calendar month, December 2025.",
      6.5775,
    );
    expect(out.kind).toBe("inconsistent");
    if (out.kind === "inconsistent") {
      expect(out.reading.id).toBe("calendarDec");
      expect(out.expected).toBe(6.6817);
    }
  });

  it("REJECTS a vague resolution that names no reading", () => {
    const out = gradeAgainstReadings(
      Q1_READINGS,
      "I looked at the relevant sleep records and averaged them.",
      6.68,
    );
    expect(out.kind).toBe("unrecognised");
  });

  it("REJECTS an undeclared resolution however right the number", () => {
    expect(gradeAgainstReadings(Q1_READINGS, undefined, 6.5775).kind).toBe(
      "undeclared",
    );
    expect(gradeAgainstReadings(Q1_READINGS, "   ", 6.5775).kind).toBe(
      "undeclared",
    );
  });

  it("REJECTS a number that matches no reading at all", () => {
    const out = gradeAgainstReadings(
      Q1_READINGS,
      "Trailing 31 days to the last day of data.",
      5.81, // the naive nap-averaged figure
    );
    expect(out.kind).toBe("inconsistent");
  });

  it("distinguishes the five Q1 readings from one another", () => {
    const cases: [string, string][] = [
      ["the last full calendar month, December 2025", "calendarDec"],
      [
        "calendar November 2025, the last complete month of data",
        "calendarNov",
      ],
      ["a trailing 31 days to the final day of data", "trailing31"],
      ["the trailing 30 days", "trailing30"],
      ["the trailing 28 days, four whole weeks", "trailing28"],
    ];
    for (const [text, id] of cases) {
      expect(classifyResolution(text, Q1_READINGS)?.id, text).toBe(id);
    }
  });

  it("treats a yen-only Q14 total as a wrong set, not a reading", () => {
    // 3790.28 is arithmetically correct for JPY rows alone, but it silently
    // drops in-window USD spend. That is an incomplete set.
    const out = gradeAgainstReadings(
      Q14_READINGS,
      "Summed the yen transactions during the trip and converted them.",
      3790.28,
    );
    expect(out.kind).not.toBe("pass");
  });

  it("accepts both Q14 readings, each with its own number", () => {
    expect(
      gradeAgainstReadings(
        Q14_READINGS,
        "Spend during the trip window in all currencies, excluding the flight booked earlier.",
        7728.3,
      ).kind,
    ).toBe("pass");
    expect(
      gradeAgainstReadings(
        Q14_READINGS,
        "Trip-window spend plus the pre-booked Delta flight.",
        9146.9,
      ).kind,
    ).toBe("pass");
  });

  it("accepts both Q18 denominators but not the expenditure proxy", () => {
    expect(
      gradeAgainstReadings(
        Q18_READINGS,
        "All qualifying run days with a nutrition log (n=108).",
        2054.7,
      ).kind,
    ).toBe("pass");
    expect(
      gradeAgainstReadings(
        Q18_READINGS,
        "Only days whose nutrition log is marked complete (n=74).",
        2387.66,
      ).kind,
    ).toBe("pass");
    // Expenditure answers a different question and has no reading.
    expect(
      gradeAgainstReadings(
        Q18_READINGS,
        "Used total_calories from the activity tracker on qualifying run days.",
        2402.81,
      ).kind,
    ).not.toBe("pass");
  });

  it("declares ambiguity sparingly", () => {
    // Over-declaring is how this rule would quietly stop meaning anything.
    expect(Object.keys(AMBIGUOUS_READINGS).sort()).toEqual([
      "Q1",
      "Q14",
      "Q18",
    ]);
  });

  it("keeps exactly one eval reading per ambiguous question", () => {
    for (const [id, readings] of Object.entries(AMBIGUOUS_READINGS)) {
      const evalReadings = readings.filter((r) => r.isEvalReading);
      expect(evalReadings, id).toHaveLength(1);
    }
  });

  it("classifies by the primary reading, not a parenthetical alternative", () => {
    // The prompt asks the model to name the alternative reading; it does so in
    // brackets. Matching those classifies a run by the reading it explicitly
    // set aside, penalising the behaviour the prompt asked for.
    const out = gradeAgainstReadings(
      Q18_READINGS,
      "Averaged total_kcal over the 108 logged days out of 193 qualifying days (with 74 complete days and 85 unlogged days).",
      2054.7,
    );
    expect(out.kind).toBe("pass");
    if (out.kind === "pass") expect(out.reading.id).toBe("allLogged");
  });

  it("still honours a primary reading that IS the complete-logs one", () => {
    const out = gradeAgainstReadings(
      Q18_READINGS,
      "Restricted to days whose log is marked complete, n=74; the wider set of 108 logged days is the alternative.",
      2387.66,
    );
    expect(out.kind).toBe("pass");
    if (out.kind === "pass") expect(out.reading.id).toBe("completeLogged");
  });
});
