/**
 * PDPP Core v0.1.0 Authorization Server.
 *
 * Public seam for the PDPP AS: selection validation, axis resolution, consent
 * review, grant issuance, grant-bound tokens, introspection, and revocation.
 * The Resource Server consumes `PdppTokenService.resolveToken` (co-located) or
 * `introspect` (separated) and enforces only from that result.
 */

export {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION,
  PDPP_GRANT_VERSION_V02,
  PDPP_API_VERSION,
  AI_TRAINING_PURPOSE,
  isV02Grant,
} from "./types.js";
export type {
  AccessMode,
  ClientClaims,
  ClientDisplay,
  DeclarationSnapshot,
  DeclaredPreset,
  DeclaredStream,
  DeclaredView,
  Grant,
  GrantStatus,
  InactiveReason,
  PdppAuthorizationDetail,
  PdppAuthorizationEntry,
  PdppAuthorizationResultV02,
  PdppIntrospectionResponse,
  PdppTokenContext,
  PdppTokenKind,
  RequestedSelection,
  RequestedStream,
  Retention,
  SelectionRequest,
  SourceKind,
  StreamGrant,
  StreamMinimum,
  StreamRequest,
  TimeConstraint,
  TimeRange,
} from "./types.js";

export { validateSelectionRequest } from "./selection.js";
export type {
  SelectionFailure,
  SelectionFailureCode,
  SelectionValidation,
} from "./selection.js";

export { resolveSelection } from "./resolve.js";
export type {
  InstanceInventory,
  ResolutionFailure,
  ResolutionFailureCode,
  ResolutionResult,
} from "./resolve.js";

export {
  buildConsentReview,
  computeReviewDigest,
  isRegisteredPurposeCode,
  normalizeClientClaims,
} from "./review.js";
export type {
  BuildReviewInput,
  ConsentReviewModel,
  ExistingGrant,
  RequesterIdentity,
  ReviewStream,
} from "./review.js";

export { issueGrant } from "./issuance.js";
export type {
  ConsentEvidence,
  IssuanceFailure,
  IssuanceFailureCode,
  IssuanceResult,
  IssueGrantInput,
} from "./issuance.js";

export {
  AUTHORIZATION_CODE_TTL_SECONDS,
  DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
  mayIssueRefreshToken,
  PdppTokenService,
  toAuthorizationDetail,
} from "./tokens.js";
export type {
  TokenFailure,
  TokenFailureCode,
  TokenIssuanceResult,
  TokenResult,
  PdppTokenServiceOptions,
} from "./tokens.js";

export {
  approveAuthorization,
  AuthorizationSessionStore,
  denyAuthorization,
  fetchReview,
  REVIEW_SESSION_TTL_SECONDS,
} from "./approval.js";
export type {
  ApprovalFailure,
  ApprovalFailureCode,
  ApprovalResult,
  AuthorizationSession,
  InstanceChoice,
  ReviewFetchResult,
  SessionState,
} from "./approval.js";

export {
  REDIRECT_FAILURES_ARE_NEVER_REDIRECTED,
  validateRedirectUri,
} from "./redirect.js";
export type {
  RedirectFailure,
  RedirectFailureCode,
  RegisteredRedirectPolicy,
} from "./redirect.js";

export {
  computeS256Challenge,
  PKCE_METHOD_S256,
  validateCodeChallenge,
  verifyCodeVerifier,
} from "./pkce.js";
export type { PkceFailure, PkceFailureCode } from "./pkce.js";

export {
  hashToken,
  newOpaqueToken,
  openPdppAuthStore,
  PdppAuthStore,
  PDPP_AUTH_STATE_VERSION,
  UnsupportedAuthStateError,
} from "./store.js";
export type {
  AccessTokenRecord,
  AuthCodeRecord,
  StoredGrant,
} from "./store.js";

export {
  checkDeclarationUrl,
  computeDeclarationDigest,
  declaredSourceId,
  DECLARATION_FETCH_TIMEOUT_MS,
  MAX_DECLARATION_BYTES,
  MAX_REDIRECTS,
  parseDeclaration,
  retrieveDeclaration,
} from "./declaration.js";
export type {
  DeclarationFailure,
  DeclarationFailureCode,
  DeclarationFetcher,
  DeclarationResult,
  DeclarationTrustPolicy,
} from "./declaration.js";

export {
  MAX_CLIENT_DOCUMENT_BYTES,
  resolveUrlHostedClientIdentity,
} from "./client-identity.js";
export type {
  ClientDocumentFetcher,
  ClientIdentityFailure,
  ClientIdentityFailureCode,
  ClientIdentityResult,
} from "./client-identity.js";

export {
  mayRenderRemoteLogo,
  resolveRequesterIdentity,
  verifyClientIdDocument,
} from "./client-metadata.js";
export type {
  ClientIdMetadataDocument,
  RegisteredClientMetadata,
  ResolveRequesterInput,
} from "./client-metadata.js";
