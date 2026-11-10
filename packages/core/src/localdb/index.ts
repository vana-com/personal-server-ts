export type { SqlDriver, SqlStatement, SqlValue } from "./driver.js";
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
export { applyConnection, applyStream, type ApplyResult } from "./apply.js";
export { publishConnection, type PublishResult } from "./publish.js";
export { encodePrefixes, type EncodedPart } from "./encode.js";
export { unwriteRefusedRun } from "./unwrite.js";
export { runCycle, syncConnection, type CycleReport } from "./cycle.js";
export { purgeConnection } from "./purge.js";
export {
  createConnectionDeleter,
  ConnectionDeleteSuperseded,
  ConnectorNotVerifiedError,
  ConnectionStoppedError,
  type ConnectionDeleter,
  type DeleteIntent,
  type PendingDelete,
} from "./delete.js";
export { createBlobStore, type BlobStore } from "./blobs.js";
export {
  createRecordQuery,
  createGrantHistory,
  type ChangePage,
  type RecordPage,
  type RecordQuery,
  type StoredRecord,
} from "./query.js";
export {
  createOlderVersions,
  type OlderVersionCounts,
  type OlderVersions,
  type VersionInfo,
} from "./older-versions.js";
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
export * from "./import-readback.js";
export * from "./legacy-retire.js";

export * from "./import-fingerprint.js";
