/**
 * Capability confinement for the query layer (plan phase 4b).
 *
 * Browser-safe by construction: nothing here imports a Node built-in. All data
 * access arrives through {@link QueryToolDeps}, so the same layer serves the
 * Node server and PS-Lite.
 */
export type {
  ClassifyFn,
  ClassifyOptions,
  ClassifyResult,
  CoverageCounters,
  CoverageMethod,
  IntrospectFn,
  QueryBudget,
  QueryToolContext,
  QueryToolDeps,
  ReadOptions,
  ScopeInfo,
  ScriptBlock,
  ScriptHit,
  ScriptResult,
  SearchOptions,
  StoppedBecause,
} from "./types.js";

export { CoverageLedger } from "./coverage.js";
export {
  QueryToolError,
  ScriptCompleted,
  type QueryToolErrorCode,
} from "./errors.js";
export { createVanaApi, type CreatedApi, type VanaApi } from "./api.js";
export {
  runQueryScript,
  type QueryScriptOutcome,
  type RunQueryScriptOptions,
} from "./runtime.js";
export {
  ConfinementError,
  FORBIDDEN_IDENTIFIERS,
  FORBIDDEN_KEYS,
  runConfinedScript,
  type RunScriptOptions,
} from "./interpreter/index.js";
export {
  DEFAULT_FRAME_BUDGET_BYTES,
  NOTES_TRIMMED,
  RESULT_FRAME_BEGIN,
  RESULT_FRAME_END,
  boundRunDocument,
  decodeResultFrame,
  encodeResultFrame,
  stripResultFrames,
  type DecodeOutcome,
  type RunDocument,
} from "./protocol.js";
