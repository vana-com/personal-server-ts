export {
  createIndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntimeOptions,
} from "./browser-runtime.js";

export {
  startPersonalServer,
  type StartPersonalServerLiteOptions,
  type StartPersonalServerLiteRelayOptions,
} from "./client.js";
export type {
  PersonalServerHandle,
  PersonalServerClientErrorBody,
  PersonalServerDataVersion,
  PersonalServerHealthRegistration,
  PersonalServerIdentity,
  PersonalServerInfo,
  PersonalServerAuthRequestOptions,
  PersonalServerListDataOptions,
  PersonalServerListDataResult,
  PersonalServerListVersionsOptions,
  PersonalServerListVersionsResult,
  PersonalServerReadDataOptions,
  PersonalServerRegistrationRequest,
  PersonalServerStatus,
  PersonalServerSyncTriggerResult,
  PersonalServerUrls,
} from "@opendatalabs/personal-server-ts-core/client";
export {
  PersonalServerClientError,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  parsePersonalServerJsonResponse,
} from "@opendatalabs/personal-server-ts-core/client";

export {
  handlePsLiteBridgeRequest,
  type PsLiteBridgeRequest,
  type PsLiteBridgeResponse,
} from "./bridge.js";

export {
  createIndexedDbPsLitePersistence,
  createOpfsPsLiteDataFileStore,
  createPersistentPsLiteStorage,
  isOpfsAvailable,
  type IndexedDbPsLitePersistenceOptions,
  type PsLiteDataFileStore,
  type PsLiteFileStorageKind,
  type PsLitePersistedStorageState,
  type PsLitePersistenceAdapter,
  type PsLiteStorageCapabilities,
  type PsLiteStoragePort,
} from "./storage.js";

export {
  createIndexedDbPsLiteAccessLogStore,
  createIndexedDbPsLiteStateStore,
  createIndexedDbPsLiteTokenStore,
  loadOrCreatePsLiteConfig,
  loadOrCreatePsLiteServerIdentity,
  loadPsLiteRelayState,
  savePsLiteConfig,
  savePsLiteRelayState,
  type IndexedDbPsLiteAccessLogStoreOptions,
  type IndexedDbPsLiteStateStoreOptions,
  type IndexedDbPsLiteTokenStoreOptions,
  type PsLiteEncryptedPrivateKey,
  type PsLiteEncryptedServerIdentity,
  type PsLiteRelayState,
  type PsLiteStateKey,
  type PsLiteStateStore,
  type PsLiteUnlockedServerIdentity,
} from "./state.js";

export {
  createPsLitePendingBlobDeletionStore,
  createPsLiteSyncCursor,
  createPsLiteSyncManager,
  type PsLiteSyncOptions,
} from "./sync.js";

export {
  resolvePsLiteOwner,
  type PsLiteOwnerBindingInput,
} from "./owner-binding.js";

export {
  createPsLiteDerivativeCompute,
  createPsLiteQuestionStore,
  psLiteInferenceConfigured,
  type PsLiteDerivativeCompute,
  type PsLiteDerivativeComputeOptions,
} from "./derivatives.js";

export {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
  type BearerTokenPsLiteAuthOptions,
  type PsLiteAuthAdapter,
  type PsLiteReadAuthInput,
  type PsLiteRuntime,
  type PsLiteRuntimeOptions,
  type PsLiteStorageAdapter,
  type PsLiteTokenStore,
  type PsLiteWriteSessionAuthOptions,
  type Web3SignedPsLiteAuthOptions,
} from "./runtime.js";

// Delegated builder writes: hosts that build their own auth adapter (or want
// one store shared across several runtimes) wire these themselves.
export {
  createInMemoryWriteProofReplayStore,
  createInMemoryWriteSessionStore,
  hashWriteSessionToken,
  verifyStoredWriterAttribution,
  WRITE_SIGNATURE_HEADER,
  WRITER_ATTRIBUTION_KEY,
  type WriteProofReplayStore,
  type WriteSessionRecord,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";

export {
  createIndexedDbMcpConnectionStore,
  createIndexedDbMcpOAuthAuthorizationStore,
  type IndexedDbMcpConnectionStoreOptions,
  type IndexedDbMcpOAuthAuthorizationStoreOptions,
} from "./mcp-store.js";

export {
  DiagnosticsRecorder,
  collectDiagnosticsWithTimeout,
  DIAGNOSTICS_VERSION,
  type ActiveOperation,
  type DiagnosticsEvent,
  type DiagnosticsPhase,
  type LastNetworkOperation,
  type PsLiteDiagnosticsSnapshot,
  type RecordEventOptions,
  type ScopeDiagnostics,
  type ScopeReadinessStatus,
  type StorageHealthSummary,
  type SyncDiagnostics,
} from "./diagnostics.js";

export {
  decodeDataFrame,
  encodeDataFrame,
  psLiteRelayControlUrl,
  psLiteRelayPublicUrl,
  RELAY_CLOSE_SESSION_REPLACED,
  startPsLiteRelayClient,
  type PsLiteRelayClient,
  type PsLiteRelayClientOptions,
  type PsLiteRelayCloseEvent,
  type PsLiteRelayStatus,
  type PsLiteRelayTlsFactory,
  type PsLiteRelayTlsPrepareInput,
  type PsLiteRelayTlsStep,
  type PsLiteRelayTlsStream,
  type PsLiteRelayTlsStreamInput,
  type PsLiteRelayWebSocket,
  type PsLiteRelayWebSocketFactory,
} from "./relay.js";

export {
  createLocalStoragePsLiteRelayTlsIdentityStore,
  createRustlsPsLiteRelayTlsFactory,
  psLiteRelayPublicHost,
  psLiteRelayPublicUrl as psLiteRelayTlsPublicUrl,
  type PsLiteRelayTlsIdentity,
  type PsLiteRelayTlsIdentityStore,
  type RustlsPsLiteRelayTlsOptions,
} from "./relay-tls.js";

export {
  assertCompletePsLitePersistenceBundle,
  psLitePersistenceRuntimeOptions,
  type PsLitePersistenceBundle,
  type PsLitePersistenceRuntimeOptions,
} from "./persistence.js";

/**
 * The query layer (design §19.17, plan phase 4a/8).
 *
 * PS-Lite answers `ask_personal_data` by running model-authored code in a
 * QuickJS-WASM VM over a per-request in-memory grant. Re-exported from `./query`
 * so a host can wire the port without reaching into the package's internals.
 */
export {
  applyGrantCoverage as applyLiteGrantCoverage,
  createLiteAskPersonalDataPort,
  createLiteToolHost,
  createQuickJsSandbox,
  loadQuickJsModule,
  materializeGrantInMemory,
  probeVmGlobals,
  quickJsEnforcement,
  resolveGrant as resolveLiteGrant,
  runLiteQuery,
  unwrapEnvelopeData as unwrapLiteEnvelopeData,
  verifyOutcome as verifyLiteSandboxOutcome,
  EGRESS_GLOBALS as LITE_EGRESS_GLOBALS,
  LITE_QUERY_BUDGET,
  LITE_QUERY_LIMITS,
  MAX_STACK_BYTES as LITE_QUICKJS_MAX_STACK_BYTES,
  VIRTUAL_GRANT_ROOT as LITE_VIRTUAL_GRANT_ROOT,
  type LiteExecuteOutcome,
  type LiteGrantedScope,
  type LiteMaterializedGrant,
  type LiteMaterializedScope,
  type LiteQueryEvent,
  type LiteQueryEventSink,
  type LiteScopePayload,
  type LiteScopeReader,
  type LiteSkippedScope,
  type LiteToolHost,
  type QuickJsSandboxOptions,
  type RunLiteQueryOptions,
} from "./query/index.js";
