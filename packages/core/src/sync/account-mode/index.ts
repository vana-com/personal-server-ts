/**
 * The shared account-storage-mode module.
 *
 * Two layers. `mode-machine.ts` is the pure policy: it decides from one owner's
 * record, one event and a sampled clock, and reads nothing else. The authority
 * (`authority.ts`) holds every owner's record, the one lock that the commit
 * seal and the latch write share, and the durable store. `reduce-adapter.ts`
 * joins them. Every host and the Personal Server read the mode through the
 * authority.
 */
export {
  OFF_TTL_MS,
  createModeRecord,
  reduceAccountMode,
  validModeOwner,
  type AccountModeRecord,
  type ModeClock as PureModeClock,
  type ModeDecision as PureModeDecision,
  type ModeEvent as PureModeEvent,
  type ModeReduction,
} from "./mode-machine.js";
export {
  MemoryAccountModeRecordStore,
  reduceStoredAccountMode,
  type AccountModeRecordStore,
} from "./record-store.js";
export {
  reduce,
  type ModeDecision,
  type ModeEvent,
  type ModeRecordStore,
  type ModeState,
  type OwnerModeRecord,
  type ReduceClock,
} from "./reduce-adapter.js";
export {
  createModeAuthority,
  defaultAuthorityClock,
  type AuthorityClock,
  type CommitResult,
  type ModeAuthority,
  type ModeAuthorityOptions,
  type ModeEvidenceInput,
  type RefuseDecision,
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
