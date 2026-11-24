export {
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  grantRegistrationDomain,
  grantRevocationDomain,
  isDataPortabilityGatewayConfig,
  verifyGrantRegistration,
  type DataPortabilityGatewayConfig,
  type GrantRegistrationMessage,
  type GrantRevocationMessage,
  type VerifyGrantRegistrationInput,
  type VerifyGrantRegistrationResult,
} from "@opendatalabs/vana-sdk/browser";

// Canary 87b4310 flattened the grant shape — `parseGrantRegistrationPayload`
// and `DataPortabilityGrantPayload` are gone with the JSON blob they
// described. Grants now live entirely on top-level fields of
// `GatewayGrantResponse` (scopes, grantVersion, expiresAt, paymentStatus,
// status, fee). Re-export the response shape so callers don't need to reach
// into vana-sdk's gateway subpath directly.
export type {
  GatewayGrantResponse,
  GatewayGrantStatus,
  GatewayGrantFee,
  GrantListItem,
} from "@opendatalabs/vana-sdk/browser";

// §6 — the PDPP↔chain grant binding. Keyed by existing chain permission
// identity; adds no field to any signed struct.
export {
  createFingerprintedPdppGrantBinding,
  createPdppGrantBinding,
  grantVersionStillAuthorizes,
  isValidGrantVersion,
  samePermission,
  verifyPdppGrantBinding,
  type ChainPermissionRef,
  type CreateBindingInput,
  type CreateFingerprintedBindingInput,
  type PdppGrantBinding,
  type ResolvedBuilder,
  type VerifyBindingInput,
} from "./pdpp-binding.js";
export {
  assertWritableGrantVersion,
  bindingsAgree,
  createInMemoryPdppGrantBindingStore,
  permissionKey,
  type PdppGrantBindingStore,
} from "./pdpp-binding-store.js";
// One salted fingerprint per PDPP grant, the entry it takes in the on-chain
// permission slot. Nothing calls it yet.
export {
  GRANT_FINGERPRINT_DOMAIN,
  GRANT_FINGERPRINT_PREFIX,
  canonicalDataScopes,
  grantFingerprint,
  grantMatchesFingerprint,
  isGrantFingerprint,
  isGrantSalt,
  newGrantSalt,
} from "./grant-fingerprint.js";
