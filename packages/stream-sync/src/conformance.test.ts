/**
 * Trace-replay conformance: the package against TLC traces of the TLA+
 * model. conformance/README.md has the mapping table, the corpus command
 * and the model abstractions this does not check.
 *
 * Every divergence must be a named entry in conformance/known-divergences.json,
 * and every entry there must still occur, so the list can only shrink when
 * the package (or the model) changes to agree.
 */

import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import {
  readCorpus,
  replayCorpus,
  type Divergence,
  type DecisionApi,
} from "../conformance/replay.js";
import * as pkg from "./index.js";

const corpusFile = new URL(
  "../conformance/corpus/corpus.ndjson.gz",
  import.meta.url,
);
const corpus = readCorpus(corpusFile);

interface KnownDivergence {
  readonly id: string;
  /** Each field is a regular expression the whole divergence field must match. */
  readonly match: {
    readonly check: string;
    readonly action?: string;
    readonly model?: string;
    readonly package?: string;
    readonly detail?: string;
  };
  /** Expected only when the corpus model ran with this design constant TRUE. */
  readonly requiresDesign?: string;
  /** "design": the model and the package read the design text differently. */
  readonly wrongSide: "package" | "model" | "design";
  readonly why: string;
  readonly fixedBy: string;
}

const known: readonly KnownDivergence[] = JSON.parse(
  readFileSync(
    new URL("../conformance/known-divergences.json", import.meta.url),
    "utf8",
  ),
).divergences;

function matches(k: KnownDivergence, d: Divergence): boolean {
  return (["check", "action", "model", "package", "detail"] as const).every(
    (field) => {
      const pattern = k.match[field];
      return (
        pattern === undefined ||
        new RegExp(`^(?:${pattern})$`).test(d[field] ?? "")
      );
    },
  );
}

const unknownOf = (divergences: readonly Divergence[]): Divergence[] =>
  divergences.filter((d) => !known.some((k) => matches(k, d)));

type Replay = Awaited<ReturnType<typeof replayCorpus>>;
let base: Replay;

beforeAll(async () => {
  base = await replayCorpus(corpus);
}, 60_000);

describe("conformance corpus", () => {
  it("is large enough and records its model", () => {
    const { meta, stats, traces } = base;
    // A git commit of the model, or a name for an unpushed model; the
    // SHA-256 of StreamSync.tla identifies the model either way.
    expect(meta.model.ref).toMatch(/^[0-9a-z-]{8,40}$/);
    expect(meta.model.streamSyncSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stats.traces).toBeGreaterThanOrEqual(200);
    const points = Object.values(stats.points).reduce((a, b) => a + b, 0);
    expect(points).toBeGreaterThanOrEqual(2000);
    expect(readFileSync(corpusFile).length).toBeLessThan(5 * 1024 * 1024);
    const fixed = new Set(traces.filter((t) => t.states).map((t) => t.id));
    for (const id of ["late-head", "split-run", "stale-generation", "q9-noop"])
      expect(fixed).toContain(id);
  });

  it("reaches every mapped decision", () => {
    for (const check of [
      "isHeadLive",
      "eligible",
      "isReady",
      "runMustBeFull",
      "decide",
      "targetFor",
      "chooseBase",
      "merge+isNoop",
      "afterCommit",
      "checkpointDecision",
    ]) {
      expect(base.stats.points[check] ?? 0, check).toBeGreaterThan(0);
    }
    const design = base.meta.model.design ?? {};
    if (design["StaleGenStops"] === "TRUE") {
      expect(
        base.traces.some((t) => t.steps?.some((s) => s.a === "PlanStale")),
      ).toBe(true);
    }
    if (design["NoOpNeedsFull"] === "TRUE") {
      expect(base.stats.points["afterCommit.noop"] ?? 0).toBeGreaterThan(0);
    }
  });
});

describe("package against the model", () => {
  it("diverges only where conformance/known-divergences.json says", () => {
    expect(unknownOf(base.divergences)).toEqual([]);
  });

  it("has no stale known divergence", () => {
    const design = base.meta.model.design ?? {};
    const stale = known
      .filter(
        (k) =>
          k.requiresDesign === undefined || design[k.requiresDesign] === "TRUE",
      )
      .filter((k) => !base.divergences.some((d) => matches(k, d)))
      .map((k) => k.id);
    expect(stale).toEqual([]);
  });
});

// Mutation controls: a changed decision rule must show up as a divergence
// the known list does not excuse. Each mutant changes one rule for a subset
// of its inputs.
describe("the corpus catches changed rules", () => {
  const mutants: Record<string, Partial<DecisionApi>> = {
    "decide: keep_pending becomes discard": {
      decide: (input) => {
        const d = pkg.decide(input);
        return d.kind === "keep_pending"
          ? {
              kind: "discard",
              recollect: false,
              clearCheckpoints: false,
              restartFull: false,
            }
          : d;
      },
    },
    "decide: reconnect becomes publish": {
      decide: (input) => {
        const d = pkg.decide(input);
        return d.kind === "reconnect"
          ? { kind: "publish", target: d.target }
          : d;
      },
    },
    "chooseBase: always empty": {
      chooseBase: () => ({ kind: "empty" }),
    },
    "targetFor: deleted(v) targets v": {
      targetFor: (start) =>
        start.kind === "deleted" ? start.version : pkg.targetFor(start),
    },
    "isHeadLive: ignores generation": {
      isHeadLive: (control, row) =>
        control.kind === "active" && row === "present",
    },
    "eligible: never legacy": {
      eligible: (input) => {
        const r = pkg.eligible(input);
        return r.kind === "legacy"
          ? { kind: "unavailable", reason: "no_data" }
          : r;
      },
    },
    "afterCommit: complete:false keeps the checkpoint": {
      afterCommit: (...args: Parameters<typeof pkg.afterCommit>) => ({
        ...pkg.afterCommit(...args),
        clearCheckpoint: false,
      }),
    },
    "checkpointDecision: always save": {
      checkpointDecision: (input) => ({
        kind: "save",
        generation: input.target,
      }),
    },
  };

  for (const [name, impl] of Object.entries(mutants)) {
    it(
      name,
      async () => {
        const { divergences } = await replayCorpus(corpus, impl);
        expect(unknownOf(divergences).length).toBeGreaterThan(0);
      },
      60_000,
    );
  }
});
