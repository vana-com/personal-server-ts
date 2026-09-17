/**
 * Vendored from Context Gateway branch `pdpp/context-client-0917` (PR #284),
 * file `apps/api/src/lib/pdpp-authorization-strategy.ts`.
 *
 * ONLY the bearer-token strategy is carried across. The upstream file also
 * exports `webSignedAuthorizationStrategy`, which imports
 * `@/lib/personal-server-data-read` — a Context Gateway internal that pulls in
 * that repo's wallet custody. Vendoring it would mean vendoring half of
 * Context Gateway to test the half that matters here, so it is deliberately
 * omitted rather than stubbed: a stub would be a fixture pretending to be the
 * real strategy, which is exactly what this journey exists to avoid.
 *
 * The bearer strategy below is byte-identical to upstream, and it is the
 * spec-conformant path (§8 "Authentication": client operations use
 * `Authorization: Bearer <access_token>`). The token it carries here is
 * minted by the real AS, not fabricated.
 */

/**
 * Produces the `Authorization` header value for one PDPP §8 request.
 * `uri` is always the request pathname only (never including the query
 * string — both PS's Web3Signed verifier and this client's callers must
 * agree on that), so a strategy that needs to bind the header to the
 * request (Web3Signed) gets exactly what it needs to do so correctly.
 */
export type PdppAuthorizationStrategy = (params: {
  origin: string;
  method: string;
  uri: string;
}) => Promise<string>;

/**
 * Spec-conformant strategy: send the client access token issued by PS's
 * PDPP AS as `Authorization: Bearer <access_token>`.
 */
export function bearerTokenAuthorizationStrategy(
  accessToken: string,
): PdppAuthorizationStrategy {
  return async () => `Bearer ${accessToken}`;
}

/**
 * Not vendored — see the file header. Present only so that importing code
 * which references it by name fails loudly rather than silently binding to
 * something that looks like the real Web3Signed strategy.
 */
export function webSignedAuthorizationStrategy(): never {
  throw new Error(
    "webSignedAuthorizationStrategy is not vendored into this fixture; " +
      "this journey exercises the spec-conformant bearer path only",
  );
}
