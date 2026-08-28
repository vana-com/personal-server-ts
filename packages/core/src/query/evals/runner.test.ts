import { beforeAll, describe, expect, it } from "vitest";
import { MemoryFixtureSink, type FixtureSource } from "./fixtures/sink.js";
import { generateCorpus } from "./fixtures/generate.js";
import { buildCases } from "./cases.js";
import { createReferenceAnswerer } from "./answerers/reference-answerer.js";
import { createNullAnswerer } from "./answerers/null-answerer.js";
import { extractNumber, formatReport, runEval } from "./runner.js";
import { DEFAULT_SEED } from "./fixtures/profiles.js";
import type { QueryEvalCase } from "./types.js";

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
