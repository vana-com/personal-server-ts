/**
 * Query-layer eval harness (implementation plan phase 1).
 *
 * Browser-safe: nothing under here imports a Node built-in. The corpus is
 * generated through a `FixtureSink`, and the in-memory sink is enough for the
 * `small` and `lite` profiles. Writing the ~222MB `full` profile to disk needs
 * a filesystem sink, which lives outside `packages/core`.
 */

export type {
  EvalAnswerer,
  EvalCaseResult,
  EvalClassRollup,
  EvalCoverage,
  EvalOutcome,
  EvalQueryAnswer,
  EvalQueryRequest,
  EvalReport,
  QueryEvalCase,
  QueryEvalClass,
  QueryEvalExpectation,
} from "./types.js";

export type { EvalJudge, JudgeVerdict, RunOptions } from "./runner.js";
export { runEval, formatReport, extractNumber } from "./runner.js";

export { buildCases, Q1_WINDOW_DAYS } from "./cases.js";

export type {
  FixtureFile,
  FixtureSink,
  FixtureSource,
} from "./fixtures/sink.js";
export { MemoryFixtureSink, writeJsonArray } from "./fixtures/sink.js";

export type { CorpusManifest, GenerateOptions } from "./fixtures/generate.js";
export { generateCorpus, generateInto, SCOPES } from "./fixtures/generate.js";

export type {
  FixtureProfile,
  FixtureProfileName,
} from "./fixtures/profiles.js";
export { DEFAULT_SEED, PROFILES } from "./fixtures/profiles.js";

export type { Rng } from "./fixtures/prng.js";
export { createRng, deriveSeed } from "./fixtures/prng.js";

export { CORPUS_DAYS, CORPUS_START_MS } from "./fixtures/time.js";

export * as planted from "./fixtures/planted.js";
export * as reference from "./reference/compute.js";

export { createReferenceAnswerer } from "./answerers/reference-answerer.js";
export { createNullAnswerer } from "./answerers/null-answerer.js";
