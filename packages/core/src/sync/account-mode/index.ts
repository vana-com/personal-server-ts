/**
 * The account-mode module: one small record per owner (see `record.ts`) held by
 * one authority (see `authority.ts`) that every host and gate reads.
 */
export {
  SWITCHED_REFUSAL,
  UNKNOWN_DECISION,
  applyAnswer,
  createMemoryModeRecordStore,
  normalizeOwner,
  parseRecord,
  type AccountModeRecord,
  type ModeAnswer,
  type ModeDecision,
  type ModeRecordStore,
  type RefuseDecision,
} from "./record.js";
export {
  createModeAuthority,
  type CommitResult,
  type ModeAuthority,
  type ModeAuthorityOptions,
  type ModeEvidenceInput,
} from "./authority.js";
export { accountStorageModeOf, decisionToModeValue } from "./port.js";
export {
  decisionBody,
  parseEvidenceBody,
  type DecisionBody,
  type EvidenceBody,
} from "./evidence-wire.js";
export {
  createImportWaker,
  type ImportRunner,
  type ImportWaker,
  type ImportWakerOptions,
} from "./import-waker.js";
