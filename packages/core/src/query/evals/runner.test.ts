import { beforeAll, describe, expect, it } from "vitest";
import { MemoryFixtureSink, type FixtureSource } from "./fixtures/sink.js";
import { generateCorpus } from "./fixtures/generate.js";
import { buildCases } from "./cases.js";
import { createReferenceAnswerer } from "./answerers/reference-answerer.js";
import { createNullAnswerer } from "./answerers/null-answerer.js";
import { extractNumber, formatReport, runEval } from "./runner.js";
import { DEFAULT_SEED } from "./fixtures/profiles.js";
import { AMBIGUOUS_READINGS } from "./readings.js";
import type {
  EvalAnswerer,
  EvalCaseResult,
  EvalQueryAnswer,
  EvalQueryRequest,
  QueryEvalCase,
} from "./types.js";

let source: FixtureSource;
let cases: QueryEvalCase[];

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  await generateCorpus(sink, { profile: "small", seed: DEFAULT_SEED });
  source = sink;
  cases = await buildCases(source);
}, 60_000);

describe("buildCases", () => {
  it("encodes all eighteen questions", () => {
    expect(cases.map((c) => c.id)).toEqual(
      Array.from({ length: 18 }, (_, i) => `Q${i + 1}`),
    );
  });

  it("assigns every case a class from the design taxonomy", () => {
    const classes = new Set(cases.map((c) => c.class));
    for (const cls of classes) {
      expect([
        "aggregation",
        "exhaustive",
        "synthesis",
        "inference",
        "relational",
        "introspection",
      ]).toContain(cls);
    }
  });

  it("computes expected values from the corpus rather than hard-coding them", () => {
    const q1 = cases.find((c) => c.id === "Q1")!;
    expect(q1.expect.kind).toBe("numeric");
    if (q1.expect.kind === "numeric") {
      expect(q1.expect.value).toBeGreaterThan(5);
      expect(q1.expect.value).toBeLessThan(9);
      expect(q1.expect.denominator).toBeGreaterThan(0);
    }
  });

  it("marks the absence case as requiring coverage", () => {
    const q8 = cases.find((c) => c.id === "Q8")!;
    expect(q8.expect).toEqual({ kind: "absence", mustReportCoverage: true });
    expect(q8.expectedCoverage?.unreadable).toBe(22);
  });
});

describe("runEval", () => {
  it("passes every gradeable case against the reference answerer", async () => {
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
    });
    const failures = report.results.filter((r) => r.outcome === "fail");
    expect(failures.map((f) => `${f.id}: ${f.reasons.join("; ")}`)).toEqual([]);
    expect(report.totals.pass).toBeGreaterThan(0);
  }, 60_000);

  it("skips judged cases when no judge is supplied", async () => {
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
    });
    const judged = cases
      .filter((c) => c.expect.kind === "judged")
      .map((c) => c.id);
    const skipped = report.results
      .filter((r) => r.outcome === "skipped")
      .map((r) => r.id);
    expect(skipped.sort()).toEqual(judged.sort());
    // A skip is not a model verdict. Nothing was decided, so nothing carries
    // the label — this is the distinction a downstream reconstruction from
    // `expect.kind === "judged"` cannot draw.
    expect(report.results.filter((r) => r.modelGraded)).toEqual([]);
  }, 60_000);

  it("marks — and renders — only the rows a model actually decided", async () => {
    // A stub judge, so this costs nothing and hits no relay. What is under
    // test is the plumbing, not the verdict: `modelGraded` must be set where
    // the verdict is made and must reach the report, so a model's opinion and
    // a computed comparison never render identically.
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
      judge: {
        judge: async () => ({ pass: true, reason: "stub" }),
      },
    });

    const judged = cases
      .filter((c) => c.expect.kind === "judged")
      .map((c) => c.id)
      .sort();
    expect(
      report.results
        .filter((r) => r.modelGraded)
        .map((r) => r.id)
        .sort(),
    ).toEqual(judged);

    const text = formatReport(report);
    for (const line of text.split("\n")) {
      const match = line.match(/^ {2}(?:PASS|FAIL|SKIP) {2}(\S+)/);
      if (!match) continue;
      expect(
        line.includes("[model-graded]"),
        `${match[1]} label mismatch: ${line}`,
      ).toBe(judged.includes(match[1]));
    }
  }, 60_000);

  it("fails every gradeable case against the null answerer", async () => {
    const report = await runEval({
      answerer: createNullAnswerer(),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
    });
    expect(report.totals.pass).toBe(0);
  }, 60_000);

  it("rolls up per class", async () => {
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
    });
    const total = report.rollups.reduce(
      (a, r) => a + r.pass + r.fail + r.skipped,
      0,
    );
    expect(total).toBe(cases.length);
  }, 60_000);

  it("formats a report without throwing", async () => {
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
      only: ["Q1"],
    });
    expect(formatReport(report)).toContain("Q1");
  }, 30_000);
});

describe("extractNumber", () => {
  it("pulls the first number out of prose", () => {
    expect(extractNumber("6.48 hours per night")).toBe(6.48);
    expect(extractNumber("about 1,234 records")).toBe(1234);
    expect(extractNumber("none found")).toBeUndefined();
  });
});

/* ------------------------------------------------------------------ */
/* Dual-rule grading (design §19.10, §19.11)                           */
/* ------------------------------------------------------------------ */

/**
 * A scripted answerer: one canned answer, whatever it is asked.
 *
 * What is under test is the grader, not an answerer, so the answer is stated
 * outright rather than produced. Everything the shared checks need — a
 * citation, scanned scopes, complete coverage — is satisfied, leaving the
 * numeric rules as the only thing that can fail.
 */
function scripted(fields: {
  answer: string;
  value?: number;
  resolution?: string;
}): EvalAnswerer {
  return {
    name: "scripted",
    answer(request: EvalQueryRequest): Promise<EvalQueryAnswer> {
      return Promise.resolve({
        answer: fields.answer,
        ...(fields.value !== undefined ? { value: fields.value } : {}),
        ...(fields.resolution !== undefined
          ? { resolution: fields.resolution }
          : {}),
        citations: [{ scope: request.grantedScopes[0] ?? "oura.sleep" }],
        coverage: {
          scopesScanned: request.grantedScopes,
          recordsScanned: 1000,
          scopesSkipped: [],
          complete: true,
        },
        determinism: "generated",
        cost: { toolCalls: 1, inputTokens: 10, outputTokens: 10, usd: 0 },
      });
    },
  };
}

describe("dual-rule grading", () => {
  let dogfood: QueryEvalCase[];

  beforeAll(async () => {
    // The readings carry corpus-specific *values*, so they mean anything only
    // on the corpus they were enumerated over: `dogfood` at `DEFAULT_SEED`.
    const sink = new MemoryFixtureSink();
    await generateCorpus(sink, { profile: "dogfood", seed: DEFAULT_SEED });
    dogfood = await buildCases(sink);
  }, 120_000);

  const run = async (
    id: string,
    answerer: EvalAnswerer,
  ): Promise<EvalCaseResult> => {
    const report = await runEval({
      answerer,
      cases: dogfood,
      seed: DEFAULT_SEED,
      profile: "dogfood",
      only: [id],
    });
    return report.results[0];
  };

  it("REJECTS reading A declared with reading B's number, demoting a strict pass", async () => {
    // The anti-cheat, end to end. 6.5775 is *the eval's* figure, so the strict
    // rule passes this run; the declaration names December, whose figure is
    // 6.6817. §19.10 said the rule moves results both ways — this is that.
    const result = await run(
      "Q1",
      scripted({
        answer: "You averaged 6.5775h across 28 nights.",
        value: 6.5775,
        resolution:
          "Resolved 'last month' to the calendar month December 2025.",
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.gradedBy).toBe("resolution-aware");
    expect(result.strictPass).toBe(true);
    expect(result.resolutionOutcome?.kind).toBe("inconsistent");
    expect(result.readingId).toBe("calendarDec");
  }, 30_000);

  it("REJECTS an undeclared resolution rather than falling back to the eval's reading", async () => {
    const result = await run(
      "Q1",
      scripted({
        answer: "You averaged 6.5775h across 28 nights.",
        value: 6.5775,
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.strictPass).toBe(true);
    expect(result.resolutionOutcome?.kind).toBe("undeclared");
    expect(result.readingId).toBeUndefined();
  }, 30_000);

  it("checks the denominator against the DECLARED reading, not the eval's", async () => {
    /*
     * §19.11's Pro run, reproduced: trailing-30 declared, 6.62 returned (inside
     * ±0.05), n=27 stated — the honest denominator for the set it chose. The
     * strict rule fails it for not saying 28, the n of a set it never used.
     */
    const result = await run(
      "Q1",
      scripted({
        answer:
          "Averaged 6.62h over the 30 days ending 2026-01-04, across 27 nights " +
          "after excluding naps and 2 null durations.",
        value: 6.62,
        resolution:
          "The trailing 30 days ending on the most recent date in the dataset.",
      }),
    );
    expect(result.outcome).toBe("pass");
    expect(result.readingId).toBe("trailing30");
    // Both verdicts recorded, and they disagree — which is the whole point.
    expect(result.strictPass).toBe(false);
    expect(result.reasons.join(" ")).toContain("[strict]");
    expect(result.reasons.join(" ")).toContain("denominator (28)");
  }, 30_000);

  it("classifies by the primary reading when the alternative is a parenthetical", async () => {
    const result = await run(
      "Q18",
      scripted({
        answer:
          "About 2054.7 kcal on the 108 logged run days (74 of them complete logs).",
        value: 2054.7,
        resolution:
          "Averaged over the 108 logged run days (with 74 complete days set aside).",
      }),
    );
    expect(result.outcome).toBe("pass");
    expect(result.readingId).toBe("allLogged");
  }, 30_000);

  it("grades a question with one honest reading strictly, resolution or not", async () => {
    // Q6 declares a window and still grades strictly: `enum-readings.ts` shows
    // the count is 6 for every trailing window from a week up, so there is no
    // reading for the rule to arbitrate.
    const q6 = dogfood.find((c) => c.id === "Q6")!;
    if (q6.expect.kind !== "numeric") throw new Error("Q6 should be numeric");
    const result = await run(
      "Q6",
      scripted({
        answer: `You spoke to ${q6.expect.value} people across ${String(q6.expect.denominator)} records.`,
        value: q6.expect.value,
        resolution:
          "Resolved 'last month' to the calendar month December 2025.",
      }),
    );
    expect(result.gradedBy).toBe("strict");
    expect(result.resolutionOutcome).toBeNull();
    expect(result.outcome).toBe("pass");
    expect(result.strictPass).toBe(true);
  }, 30_000);

  it("does not apply readings to a corpus they were not enumerated over", async () => {
    // The values are facts about `dogfood`. On `small` the labels would still
    // match and every number would be wrong, which is worse than strict.
    const report = await runEval({
      answerer: createReferenceAnswerer(source),
      cases,
      seed: DEFAULT_SEED,
      profile: "small",
    });
    expect(report.resolutionAware).toEqual([]);
    expect(report.results.every((r) => r.resolutionOutcome === null)).toBe(
      true,
    );
  }, 60_000);

  it("keeps a denominator on every reading of a case that requires one", () => {
    // The runner reports a missing one loudly rather than skipping the check;
    // this invariant is what keeps that branch unreachable.
    for (const [id, readings] of Object.entries(AMBIGUOUS_READINGS)) {
      const testCase = dogfood.find((c) => c.id === id)!;
      if (testCase.expect.kind !== "numeric") continue;
      if (testCase.expect.denominator === undefined) continue;
      for (const reading of readings) {
        expect(reading.denominator, `${id}/${reading.id}`).toBeDefined();
      }
    }
  });

  it("reports both scoreboards and names the rule behind the headline", async () => {
    const report = await runEval({
      answerer: scripted({
        answer: "You averaged 6.5775h across 28 nights.",
        value: 6.5775,
      }),
      cases: dogfood,
      seed: DEFAULT_SEED,
      profile: "dogfood",
      only: ["Q1"],
    });
    const text = formatReport(report);
    expect(text).toContain("strict scoreboard: pass 1");
    expect(text).toContain("resolution-aware on Q1");
    expect(report.totals.pass).toBe(0);
    expect(report.totals.strictPass).toBe(1);
  }, 30_000);
});
