/**
 * PS-Lite's query layer: the browser half of the two-runtime split.
 *
 * `packages/core/src/query/` holds everything that is not runtime-specific —
 * the agent loop, the prompt, the `vana` API, the coverage ledger and the
 * result-frame protocol. This directory holds the parts that could only be
 * written once you know you are in a browser: a QuickJS-WASM sandbox in place
 * of an OS sandbox, and an in-memory grant in place of a scratch directory.
 *
 * See design §19.17 for the measurements that chose QuickJS, and
 * `quickjs-sandbox.ts`'s header for what one containment layer costs against
 * the Node path's two.
 */

export {
  createQuickJsSandbox,
  loadQuickJsModule,
  probeVmGlobals,
  quickJsEnforcement,
  verifyOutcome,
  EGRESS_GLOBALS,
  MAX_STACK_BYTES,
  type QuickJsSandboxOptions,
  type VmGlobalProbe,
} from "./quickjs-sandbox.js";

export {
  createLiteToolHost,
  type LiteExecuteOutcome,
  type LiteGrantedScope,
  type LiteToolHost,
  type LiteToolHostOptions,
} from "./lite-tool-host.js";

export {
  applyGrantCoverage,
  materializeGrantInMemory,
  resolveGrant,
  runLiteQuery,
  unwrapEnvelopeData,
  LITE_QUERY_BUDGET,
  LITE_QUERY_LIMITS,
  VIRTUAL_GRANT_ROOT,
  type LiteMaterializedGrant,
  type LiteMaterializedScope,
  type LiteQueryEvent,
  type LiteQueryEventSink,
  type LiteScopePayload,
  type LiteScopeReader,
  type LiteSkippedScope,
  type LiteUnwrapResult,
  type RunLiteQueryOptions,
} from "./lite-query-service.js";

export { createLiteAskPersonalDataPort } from "./mcp-ask-port.js";
