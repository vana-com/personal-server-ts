import type { Context, MiddlewareHandler } from "hono";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";

/**
 * The bearer-error adapter for every PDPP bearer-protected route: records,
 * blobs, and the owner-bearer management routes of the AS and RS.
 *
 * Routes decide WHY a bearer fails (as typed `PdppError` codes); this module
 * alone decides how that failure goes on the wire for the deployment's
 * protocol profile:
 *
 *   - `current`: unchanged. An inactive grant is 403 `grant_revoked` or
 *     `grant_expired`; every 401 carries the RFC 6750 challenge.
 *   - `candidate-0.1.0`: a missing or unusable bearer is 401 `invalid_token`
 *     with the challenge. Known grant revocation and expiry remain typed 403s.
 */
export type PdppProtocolProfile = ServerConfig["pdpp"]["protocolProfile"];

/**
 * The RFC 9728 protected-resource metadata URL for THIS request's origin.
 *
 * RFC 9728 §5.1 requires `resource_metadata` to be a URI the client can
 * dereference. Deriving it from the request keeps it correct behind a tunnel
 * or proxy, where a hardcoded origin would point somewhere unreachable.
 */
export function resourceMetadataUrlFor(c: Context): string {
  return new URL(
    "/.well-known/oauth-protected-resource",
    new URL(c.req.url).origin,
  ).toString();
}

export function bearerChallenge(c: Context): string {
  return `Bearer error="invalid_token", resource_metadata="${resourceMetadataUrlFor(c)}"`;
}

/**
 * Render missing, unknown, or invalid bearers as OAuth invalid_token in the
 * candidate profile. Typed grant lifecycle errors retain their 403 code.
 */
function wireError(err: PdppError, profile: PdppProtocolProfile): PdppError {
  if (profile === "candidate-0.1.0" && err.code === "authentication_error") {
    return new PdppError("invalid_token", err.message);
  }
  return err;
}

/** Why a chain permission refused an otherwise active PDPP grant. */
export type PdppChainDenialCause = "expired" | "revoked" | "invalid";

/**
 * The typed error for a non-retryable chain refusal. Expiry is never reported
 * as revocation. A permission that is unbound, mismatched or unparseable is
 * `grant_invalid` under the candidate profile; `current` keeps its historical
 * `grant_revoked` for that case.
 */
export function chainDenialError(
  cause: PdppChainDenialCause,
  reason: string,
  profile: PdppProtocolProfile = "current",
): PdppError {
  if (cause === "expired") return new PdppError("grant_expired", reason);
  if (cause === "invalid" && profile === "candidate-0.1.0") {
    return new PdppError("grant_invalid", reason);
  }
  return new PdppError("grant_revoked", reason);
}

/** A PDPP §8 error body for a bearer-protected resource-server route. */
export function bearerErrorResponse(
  c: Context,
  err: PdppError,
  reqId: string,
  profile: PdppProtocolProfile = "current",
  options: {
    headers?: Record<string, string>;
  } = {},
) {
  const wire = wireError(err, profile);
  return c.json(wire.toJSON(reqId), wire.status as never, {
    "Request-Id": reqId,
    "PDPP-Version": PDPP_VERSION,
    ...(wire.status === 429 && { "Retry-After": "1" }),
    // Every 401 carries the challenge, whichever branch produced it: a
    // client holding a stale token is exactly who needs the pointer back to
    // the metadata document in order to re-authorize.
    ...(wire.status === 401 && { "WWW-Authenticate": bearerChallenge(c) }),
    ...options.headers,
  });
}

/**
 * An OAuth-shaped (`{error, error_description}`) 401 for an AS route that a
 * missing or inactive bearer failed. Under `current` the body and headers are
 * exactly what the route sent before; under the candidate profile the error is
 * `invalid_token` and the challenge is attached.
 */
export function oauthBearerErrorResponse(
  c: Context,
  error: string,
  description: string,
  profile: PdppProtocolProfile = "current",
  extraHeaders?: Record<string, string>,
) {
  const candidate = profile === "candidate-0.1.0";
  return c.json(
    {
      error: candidate ? "invalid_token" : error,
      error_description: description,
    },
    401,
    {
      ...extraHeaders,
      ...(candidate && { "WWW-Authenticate": bearerChallenge(c) }),
    },
  );
}

/**
 * Candidate-profile challenge for owner-bearer extension routes whose 401
 * bodies keep their own contract. Under `current` it is a no-op.
 */
export function bearerChallengeMiddleware(
  profile: PdppProtocolProfile = "current",
): MiddlewareHandler {
  return async (c, next) => {
    await next();
    if (profile === "candidate-0.1.0" && c.res.status === 401) {
      c.header("WWW-Authenticate", bearerChallenge(c));
    }
  };
}
