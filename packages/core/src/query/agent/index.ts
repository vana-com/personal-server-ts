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

export { createAgentAnswerer } from "./answerer.js";
export type { AgentAnswererOptions } from "./answerer.js";
