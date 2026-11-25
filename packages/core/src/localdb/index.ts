export type { SqlDriver, SqlReader, SqlStatement, SqlValue } from "./driver.js";
export { readerOf } from "./driver.js";
export { localDatabaseName } from "./name.js";
export { LocalDbTooNew, migrate } from "./migrate.js";
export { MIGRATIONS } from "./schema.js";
export {
  applyDelete,
  mergeIncoming,
  replaceDelete,
  TEMP_TABLES,
  withOrigin,
  type WriteOrigin,
} from "./merge.js";
export {
  LocalDbIdentityMismatch,
  openLocalDb,
  type LocalDbIdentity,
  type OpenLocalDbOptions,
} from "./open.js";
export { connectionQueue, type OperationKind } from "./queue.js";
export type { ConnectionQueue, ConnectionRow, LocalSyncDeps } from "./deps.js";
export { bootstrapConnections, syncBeforeBegin } from "./bootstrap.js";
export { checkRunFence, type FencePoint, type FenceTrip } from "./fence.js";
export { createRunIntakeStore, type RunIntakeStore } from "./run-intake.js";
export { createRunEndStore, type RunEndStore } from "./run-end.js";
export {
  decideReplace,
  replaceMayApply,
  type ReplaceInput,
} from "./replace.js";
export { applyConnection } from "./apply.js";
export {
  leavesUnconfirmed,
  type PublishResult,
  type PublicationReceipt,
} from "./publish.js";
export {
  applyLog,
  LogDivergedError,
  applySegmentOperations,
  applySnapshotPart,
} from "./log-apply.js";
export { publishLog } from "./log-publish.js";
export { unwriteRefusedRun } from "./unwrite.js";
export {
  runCycle,
  runPublish,
  syncConnection,
  type CycleReport,
  type CycleScope,
  type FailedStream,
} from "./cycle.js";
export { UpdateRequiredError } from "./update-required.js";
export { purgeConnection } from "./purge.js";
export {
  createConnectionDeleter,
  ConnectionDeleteSuperseded,
  ConnectionStoppedError,
  type ConnectionDeleter,
  type DeleteIntent,
  type PendingDelete,
} from "./delete.js";
export type {
  ConnectionDeleteStatus,
  DeleteBlockReason,
  DeletePart,
} from "./delete-status.js";
export {
  legacyHeadFrom,
  modeFrom,
  modeOfAccount,
  pendingBlobsFrom,
  retireLegacyOf,
  type LegacyDeletePorts,
  type LegacyHead,
  type LegacyOutcome,
} from "./legacy-delete.js";
export {
  createLegacyRetirer,
  LegacyRetireNotAdmitted,
  LegacyRetireUnavailable,
  type LegacyRetirer,
  type LegacyRetireStatus,
} from "./legacy-retire-intent.js";
export {
  eraseDeletedConnectionLogs,
  inventoryVersionLister,
  retainedPiecesIn,
  type LogErasurePorts,
  type ConnectionErasure,
  type ErasureOutcome,
  type ErasureReport,
  type LogErasureDeps,
  type LogObjectEraser,
  type LogVersionLister,
  type RetainedPieces,
  type TombstoneFinality,
} from "./log-erase.js";
export { createBlobStore, type BlobStore } from "./blobs.js";
export {
  createRecordQuery,
  createGrantHistory,
  listCursor,
  type AliasRecordQuery,
  type ChangePage,
  type RecordPage,
  type RecordQuery,
  type StoredRecord,
} from "./query.js";
export {
  createLocalResolver,
  type LocalResolver,
  type LocalAliasTarget,
  type LocalAliasRecord,
  type AliasScopes,
  type AliasTargets,
} from "./resolve.js";
export {
  createLocalListing,
  type ListedScope,
  type LocalListing,
} from "./listing.js";
export { createLocalSync, type LocalSync } from "./sync.js";
export { sweepAliasSpool } from "./alias-projection.js";
export {
  createViewChanges,
  NO_VIEW_CHANGES,
  type ViewChange,
  type ViewChangeListener,
  type ViewChangeRecorder,
  type ViewChanges,
} from "./view-changes.js";
export {
  createLocalHistory,
  type HistoryLineage,
  type HistoryResult,
  type HistoryVersionItem,
  type HistoryVersionsPage,
  type LocalHistory,
} from "./history.js";
export {
  createLocalRequirements,
  type LocalRequirements,
  type RequirementsAnswer,
  type SinceFieldSource,
} from "./requirements.js";

export {
  createLinkedRecordQuery,
  type ConnectionLink,
} from "./connection-link.js";
// PS-3 interface-only ports (F.2-F.5). Existing exports are unchanged.
export type * from "./legacy-import-types.js";
export * from "./import-ledger.js";
export * from "./legacy-import.js";
export * from "./legacy-quarantine.js";
export * from "./legacy-fold.js";
export * from "./legacy-seed-producer.js";
export * from "./legacy-scope-store.js";
export * from "./import-readback.js";
export * from "./legacy-retire.js";

export * from "./import-fingerprint.js";

export * from "./seed.js";

// Trusted composition ports; no connector/request flag grants producer access.
export { createSystemStreamStore } from "./system-streams.js";
export {
  systemStreamIdentity,
  type SystemStreamDescriptor,
} from "./system-stream-descriptor.js";
