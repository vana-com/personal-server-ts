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
