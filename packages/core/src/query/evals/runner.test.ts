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
/**
 * The `dogfood` corpus, generated once for every describe that needs it.
 *
 * `readings.ts` carries corpus-specific *values*, so the resolution-aware
 * rules mean anything only here; the Q5/Q8/Q17 grading rules below are graded
 * against the same planted decoys and unreadable documents the live sweep hit,
 * so they share it rather than paying for a second generation.
 */
let dogfood: QueryEvalCase[];

beforeAll(async () => {
  const sink = new MemoryFixtureSink();
  await generateCorpus(sink, { profile: "small", seed: DEFAULT_SEED });
  source = sink;
  cases = await buildCases(source);

  const dogfoodSink = new MemoryFixtureSink();
  await generateCorpus(dogfoodSink, { profile: "dogfood", seed: DEFAULT_SEED });
  dogfood = await buildCases(dogfoodSink);
}, 180_000);

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
  /** Overrides for the host-authored ledger, where a case grades on it. */
  coverage?: Partial<EvalQueryAnswer["coverage"]>;
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
          ...fields.coverage,
        },
        determinism: "generated",
        cost: { toolCalls: 1, inputTokens: 10, outputTokens: 10, usd: 0 },
      });
    },
  };
}

/** Grade one `dogfood` case against a scripted answer. */
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

describe("dual-rule grading", () => {
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

/* ------------------------------------------------------------------ */
/* Absence grading: the two senses of "complete"                       */
/* ------------------------------------------------------------------ */

/**
 * Q8 went 3/3 → 0/3 when per-question grants made `coverage.complete`
 * satisfiable, and the runs it started failing were the correct ones.
 *
 * The ledger's `complete` means every granted scope was streamed end to end;
 * the absence rule read it as "nothing was unreadable". An unreadable record
 * was reached, not skipped, so both can hold at once. These cases pin the
 * reconciliation and, more to the point, pin the integrity property that
 * survives it: an incomplete scan must say so in the answer text.
 */
describe("absence grading", () => {
  const q8Coverage = (): { recordsScanned: number; unreadable: number } => {
    const q8 = dogfood.find((c) => c.id === "Q8")!;
    const { recordsScanned, unreadable } = q8.expectedCoverage!;
    return { recordsScanned: recordsScanned!, unreadable: unreadable! };
  };

  it("passes a run that streamed every scope AND reported the unreadable records", async () => {
    const { recordsScanned, unreadable } = q8Coverage();
    const result = await run(
      "Q8",
      scripted({
        answer:
          `No conflicting agreement was found across the ${recordsScanned} readable ` +
          `documents; ${unreadable} documents have no text layer and could not be read.`,
        coverage: { recordsScanned, unreadable, complete: true },
      }),
    );
    expect(result.reasons).toEqual([]);
    expect(result.outcome).toBe("pass");
  }, 30_000);

  it("REJECTS a run that reports no unreadable records when there are some", async () => {
    // The negative control on the metadata axis: `complete` is honest here,
    // and the answer is still wrong about what it managed to read.
    const { recordsScanned, unreadable } = q8Coverage();
    const result = await run(
      "Q8",
      scripted({
        answer:
          `No conflicting agreement was found. All ${recordsScanned} documents ` +
          `were read, and ${unreadable} is not a count of anything.`,
        coverage: { recordsScanned, unreadable: 0, complete: true },
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.reasons.join(" ")).toContain("coverage.unreadable is 0");
  }, 30_000);

  it("REJECTS a run that hides the unreadable records from the prose", async () => {
    // The negative control on the integrity axis, and why the removed branch
    // is not missed: honest metadata alone never buys a pass.
    const { recordsScanned, unreadable } = q8Coverage();
    const result = await run(
      "Q8",
      scripted({
        answer: `No conflicting agreement was found across ${recordsScanned} documents.`,
        coverage: { recordsScanned, unreadable, complete: true },
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.reasons.join(" ")).toContain(
      `does not mention the ${unreadable} unreadable records`,
    );
  }, 30_000);
});

/* ------------------------------------------------------------------ */
/* Set grading: naming an entity vs including its data                 */
/* ------------------------------------------------------------------ */

/**
 * Implementation plan §6's open item, decided by the user: surfacing the
 * ambiguity explicitly is acceptable, silently mixing the two people's data is
 * not. These cases are the boundary between the two.
 *
 * The answers are built from each case's own `contains` / `excludes` rather
 * than transcribed from the sweep, so what is under test is the *rule* — an
 * excluded term ruled out, versus the same term asserted — and not one run's
 * wording.
 */
describe("set grading", () => {
  const q17 = (): { contains: string[]; excludes: string[] } => {
    const c = dogfood.find((x) => x.id === "Q17")!;
    if (c.expect.kind !== "set") throw new Error("Q17 should be a set case");
    return { contains: c.expect.contains, excludes: c.expect.excludes ?? [] };
  };

  it("passes an answer that resolves the ambiguity and enumerates both people", async () => {
    // Q5's shape on all three sweep runs: the needle found, the second Sarah
    // noticed, one recommendation reported per person. The decoy is named
    // under a lead-in that declares the ambiguity and governs the list.
    const q5 = dogfood.find((c) => c.id === "Q5")!;
    if (q5.expect.kind !== "set") throw new Error("Q5 should be a set case");
    const [wanted] = q5.expect.contains;
    const [decoy] = q5.expect.excludes!;
    const result = await run(
      "Q5",
      scripted({
        answer:
          "There are two different people named Sarah in your records, and both " +
          "recommended Thai restaurants:\n\n" +
          `1. **Sarah Johnson** (\`sarahj\`) recommended **${wanted}**.\n` +
          `2. **Sarah Nguyen** (\`snguyen\`) recommended **${decoy}**.\n`,
      }),
    );
    expect(result.outcome).toBe("pass");
    expect(result.reasons.join(" ")).toContain("[disambiguated]");
  }, 30_000);

  it("does not mistake a year ending a sentence for the next list marker", async () => {
    /*
     * The sweep's Q5 run 0, whitespace and all — the citation dates put "2023."
     * between the two items. An unbounded ordinal splits that into a block of
     * its own, which is not a list item, which ends the run of items the
     * ambiguity lead-in governs exactly one block before the item holding the
     * decoy. The rule then failed the run it was written to pass.
     */
    const q5 = dogfood.find((c) => c.id === "Q5")!;
    if (q5.expect.kind !== "set") throw new Error("Q5 should be a set case");
    const [wanted] = q5.expect.contains;
    const [decoy] = q5.expect.excludes!;
    const result = await run(
      "Q5",
      scripted({
        answer:
          "There are two different people named Sarah in your records, and both " +
          "recommended Thai restaurants on Slack: " +
          `1. **Sarah Johnson** (\`sarahj\`) recommended **${wanted}** in a ` +
          "direct message on March 30, 2023. " +
          `2. **Sarah Nguyen** (\`snguyen\`) recommended **${decoy}** in a ` +
          "direct message on October 2, 2024.",
      }),
    );
    expect(result.outcome).toBe("pass");
    expect(result.reasons.join(" ")).toContain("[disambiguated]");
  }, 30_000);

  it("passes an answer that names whom it excluded, in a disambiguation clause", async () => {
    // Q17 runs 0 and 2. This corrects design §19.11, which recorded Q17 as
    // conflating the two Sarahs: it was failed for saying whom it left out.
    const { contains, excludes } = q17();
    const result = await run(
      "Q17",
      scripted({
        answer:
          "Summary of Sarah Johnson before your meeting.\n\n" +
          `- **What is known:** ${contains.join(", ")}.\n` +
          `- **Disambiguation:** Distinct from Sarah Nguyen (${excludes.join(", ")}), ` +
          "who is an external partner contact.\n",
      }),
    );
    expect(result.outcome).toBe("pass");
  }, 30_000);

  it("REJECTS an answer missing the subject's facts, however it words the exclusion", async () => {
    /*
     * The negative control, and the sweep's Q17 run 1 exactly: five required
     * anchors missing *and* both of the other Sarah's handles present, under a
     * "Note on disambiguation" that would otherwise excuse them.
     *
     * Exoneration is gated on the answer already carrying every required
     * mention, so a briefing that is thin on the subject and carrying the
     * decoy fails on both axes rather than being talked out of one of them.
     */
    const { contains, excludes } = q17();
    const result = await run(
      "Q17",
      scripted({
        answer:
          "Summary of Sarah Johnson.\n\n" +
          `- **Aliases:** ${contains[0]}\n` +
          "- *Note on disambiguation:* This is distinct from Sarah Nguyen " +
          `(${excludes.join(", ")}).\n`,
      }),
    );
    expect(result.outcome).toBe("fail");
    const reasons = result.reasons.join(" ");
    expect(reasons).toContain("missing required mention");
    expect(reasons).toContain("contains excluded mention");
    expect(reasons).not.toContain("[disambiguated]");
  }, 30_000);

  it("REJECTS the other person's facts asserted about the subject", async () => {
    // The rule is not an amnesty on the excluded list. Every required anchor
    // is present here, so the gate is open — and the decoy's facts are still
    // stated as facts about Sarah Johnson, with nothing setting them aside.
    const { contains, excludes } = q17();
    const result = await run(
      "Q17",
      scripted({
        answer:
          "Summary of Sarah Johnson before your meeting.\n\n" +
          `- **What is known:** ${contains.join(", ")}.\n` +
          `- **Her remit:** she owns ${excludes.join(" and ")} for the partner side.\n`,
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.reasons.join(" ")).toContain("contains excluded mention");
  }, 30_000);

  it("bounds an exclusion lead-in at the first thing that is not a list item", async () => {
    // Q17's answers open with "…distinguishing her from Sarah Nguyen:" and
    // then a heading. Without the bound, one marker in the opening sentence
    // would licence every excluded term in the document.
    const { contains, excludes } = q17();
    const result = await run(
      "Q17",
      scripted({
        answer:
          "Here is everything known about Sarah Johnson, distinguishing her " +
          "from Sarah Nguyen:\n\n" +
          "### Identity\n\n" +
          `- **What is known:** ${contains.join(", ")}.\n` +
          `- **Her remit:** she owns ${excludes.join(" and ")}.\n`,
      }),
    );
    expect(result.outcome).toBe("fail");
    expect(result.reasons.join(" ")).toContain("contains excluded mention");
  }, 30_000);
});
