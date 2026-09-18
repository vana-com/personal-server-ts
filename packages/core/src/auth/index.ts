export {
  authenticateRequest,
  mapSdkAuthError,
  type AuthenticatedRequest,
  type AuthenticateRequestInput,
  type AuthMechanism,
  type RequestAuth,
  type SessionTokenVerifierPort,
} from "./request.js";

export { web3SignedProofId, boundedProofExpiry } from "./proof-id.js";
