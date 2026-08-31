/**
 * Query layer agent loop (implementation plan phase 5).
 *
 * Browser-safe: nothing here imports a Node built-in. The loop drives the
 * existing `InferenceProvider` (fetch-based, E2EE and relay signing included)
 * and a `Sandbox` port, both injected — so the same loop runs on the Node
 * server and in PS-Lite with different implementations behind those two seams.
 */

export type {
  QueryAnswer,
  QueryBudget,
  QueryCitation,
  QueryConfidence,
  QueryCost,
  QueryCoverage,
  QueryRequest,
  QueryStoppedBecause,
} from "./types.js";

/**
 * Exported so the two query services build their "no readable scope" coverage
 * from the same frozen, fail-closed constant the loop falls back to, rather
 * than each restating the zeroed literal. One definition, one place to break.
 */
export { EMPTY_COVERAGE } from "./types.js";

export {
  ANSWER_TAG,
  RESPONSE_CONTRACT_VERSION,
  RUN_TAG,
  findFencedBlocks,
  parseTurn,
  repairMessage,
} from "./contract.js";
export type {
  ContractViolation,
  ParseFailure,
  ParsedAnswer,
  ParsedRun,
  ParsedTurn,
} from "./contract.js";

export {
  SYSTEM_PROMPT_TEMPLATE,
  SYSTEM_PROMPT_VERSION,
  buildSystemPrompt,
} from "./prompt.js";
export type { BuildSystemPromptResult, QueryScopeInfo } from "./prompt.js";

export {
  DEFAULT_OUTPUT_TAIL_BYTES,
  DEFAULT_TRANSCRIPT_BUDGET_BYTES,
  RELAY_MAX_BODY_BYTES,
  byteLength,
  fitTranscript,
  renderRunResult,
  transcriptBytes,
  truncateOutput,
} from "./transcript.js";

export type {
  ExecutedRun,
  QueryScriptResult,
  QueryToolHost,
} from "./tool-host.js";

export { DEFAULT_MAX_TURNS, runQueryLoop } from "./loop.js";
export type { QueryLoopOptions } from "./loop.js";

// `createAgentAnswerer` is deliberately NOT re-exported here. It adapts this
// loop to the eval harness's `EvalAnswerer`, so it has no product consumer —
// only the harness and its own test — and its type-only import of
// `evals/types.ts` was the single reason the published `./query/agent` types
// dragged the whole `evals/` chain into `dist`. It now lives beside the thing
// it serves, at `query/evals/agent-answerer.ts`, which the build excludes.
