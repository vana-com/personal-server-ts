/**
 * The shared account-storage-mode module.
 *
 * `mode-machine.ts` is the policy: the one place that decides the mode, with
 * no clock, disk or network. `authority.ts` holds the records, the lock that
 * the commit seal and the latch write share, and the durable store, which it
 * owns alone: a second runtime on the same store is refused. Every host
 * and the Personal Server read the mode through the authority.
 *
 * The shared test vectors are `vectors.json` in this folder. They are
 * host-neutral JSON; a Desktop, phone or Web adapter runs the same file.
 */
export {
  OFF_TTL_MS,
  createModeRecord,
  fromDurable,
  normalizeOwner,
  reduceAccountMode,
  toDurable,
  tombstoneRecord,
  validModeOwner,
  type AccountModeRecord,
  type DurableModeRecord,
  type ModeClock,
  type ModeDecision,
  type ModeEvent,
  type ModeReduction,
  type ModeState,
} from "./mode-machine.js";
export {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  assertMonotoneWrite,
  sameDurableRecord,
  type ModeRecordStore,
  type ModeStoreLease,
} from "./record-store.js";
export {
  DEFAULT_SAVE_TIMEOUT_MS,
  MAX_FETCH_SKEW_MS,
  DEFAULT_OWNER_RETRY_MS,
  createModeAuthority,
  createModeAuthorityWithImporter,
  defaultAuthorityClock,
  type AuthorityClock,
  type CommitResult,
  type ImportSeedCapability,
  type ModeAuthority,
  type ModeAuthorityOptions,
  type ModeEvidenceInput,
  type RefuseDecision,
  type StreamCommitResult,
} from "./authority.js";
export {
  createMemoryModeRecordStore,
  type MemoryModeRecordStore,
} from "./memory-record-store.js";
export { accountStorageModeOf, decisionToModeValue } from "./port.js";
export {
  parseEvidenceBody,
  decisionBody,
  type EvidenceBody,
  type DecisionBody,
} from "./evidence-wire.js";
export {
  legacyFlagEvidence,
  type LegacyStreamSyncFlag,
} from "./flag-evidence.js";
