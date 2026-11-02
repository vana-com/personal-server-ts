export {
  authenticateRequest,
  cacheRequestBodyBytes,
  mapSdkAuthError,
  type AuthenticatedRequest,
  type AuthenticateRequestInput,
  type AuthMechanism,
  type RequestAuth,
  type SessionTokenVerifierPort,
} from "./request.js";

export { web3SignedProofId, boundedProofExpiry } from "./proof-id.js";
export {
  isWeb3SignedLifetimeError,
  MAX_WEB3SIGNED_LIFETIME_SEC,
  TokenLifetimeError,
} from "./request.js";
