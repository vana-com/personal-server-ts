import type {
  LocalPdppAuthorizationService,
  PdppTokenContext,
} from "./pdpp-auth.js";

/**
 * Deterministic fixture PdppAuthorizationService for this lane's own route
 * tests. NOT a real AS integration — maps fixed token strings to fixed
 * PdppTokenContext values. When the AS lane's real implementation exists,
 * this is what gets swapped, not the PdppAuthorizationService interface.
 */
export function createFixtureAuthorizationService(
  tokens: Record<string, PdppTokenContext>,
): LocalPdppAuthorizationService {
  const resolveTokenNow = (accessToken: string): PdppTokenContext =>
    tokens[accessToken] ?? {
      active: false,
      tokenKind: "client",
      subjectId: "",
    };
  return {
    locality: "local",
    resolveTokenNow,
    async resolveToken(accessToken: string): Promise<PdppTokenContext> {
      return resolveTokenNow(accessToken);
    },
  };
}
