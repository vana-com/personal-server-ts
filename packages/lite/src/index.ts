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
  type PsLiteBoundedStateStore,
  type PsLiteUnlockedServerIdentity,
} from "./state.js";

export {
  createPsLitePendingBlobDeletionStore,
  createPsLiteSyncCursor,
  createPsLiteSyncManager,
  type PsLiteSyncOptions,
  type PsLiteOwnerSyncSigner,
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

export {
  createLiteCanonicalStore,
  LiteCanonicalRefusal,
  litePendingFingerprint,
  type LiteCommitReceipt,
  type LiteReplicaReadOptions,
  type LiteVisibleRecord,
  type LiteOperationDraft,
} from "./canonical-store.js";
export {
  LITE_CANONICAL_BATCH_BYTES,
  LITE_CANONICAL_MAX_OPERATION_BYTES,
  LITE_CANONICAL_MAX_VALUE_BYTES,
  type LiteCanonicalPersistence,
  type LiteCanonicalTransaction,
  type LiteBlobDescriptor,
  type LiteStorageEntry,
  type LiteStoragePage,
} from "./canonical-persistence.js";
export {
  LITE_MAX_FRAGMENT_BYTES,
  LITE_REPLICA_SQL_BYTES,
  LITE_REPLICATION_LIMITS,
  LiteReplicaTransferError,
  replicationBootConfigProblem,
  type LiteReplicaBytes,
  type LiteReplicaBytesInfo,
  type LiteReplicaNetwork,
  type LiteReplicaObjectTransfers,
  type LiteReplicaTransferCall,
  type LiteReplicaTransferFailure,
  type LiteReplicaPersistence,
  type LiteReplicaSql,
  type LiteReplicaTransaction,
  type LiteReplicationEngine,
  type LiteReplicationTrigger,
  type ReplicationBootConfig,
  type ReplicationLimits,
} from "./replication-ports.js";
export {
  acquireLiteReplicaOwner,
  createLiteReplicaCoordinatorState,
} from "./replication-coordinator-state.js";
export {
  createLiteReplicaEngine,
  type LiteReplicaEngine,
  type LiteReplicaEngineInput,
} from "./replication-engine.js";
export {
  LITE_REPLICA_TRANSFER_DEADLINE_MS,
  createLiteReplicaStorage,
  type LiteReplicaUploadHeaders,
} from "./replication-storage.js";
export {
  createLiteReplication,
  liteTargetChunkBytes,
  liteVanaReplicaObjects,
  type LiteReplication,
  type LiteReplicationInput,
} from "./replication-host.js";
export {
  LITE_REPLICATION_PAUSE_GRACE_MS,
  createLiteReplicationRuntime,
  type LiteReplicationRuntime,
  type LiteReplicationStatus,
} from "./replication-runtime.js";

export {
  importOuraBrowserRecords,
  type OuraBrowserImportInput,
  type OuraBrowserImportOptions,
  type OuraBrowserImportResult,
  type OuraImportReceipt,
} from "./oura-import.js";

export { OURA_LEGACY_TAKEOVER_CONTRACT } from "@opendatalabs/personal-server-ts-core/api";
