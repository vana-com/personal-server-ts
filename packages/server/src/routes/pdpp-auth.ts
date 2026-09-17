/**
 * PDPP Core v0.1.0 Authorization Server HTTP surface.
 *
 * Six endpoints under `/pdpp/v1`:
 *
 *   POST /authorize                      — accept an RFC 9396 selection request
 *   GET  /authorize/:session_id/review   — the owner's consent review model
 *   POST /authorize/:session_id/approve  — authenticated owner approval
 *   POST /authorize/:session_id/deny     — authenticated owner denial
 *   POST /token                          — code redemption + refresh rotation
 *   POST /introspect                     — RFC 7662 introspection
 *   POST /revoke                         — owner-initiated grant revocation
 *
 * This is deliberately a NEW surface rather than an extension of
 * `oauth-token.ts`. That endpoint serves the control-plane and CLI device
 * flows against the legacy `TokenStore`; PDPP tokens are grant-bound and live
 * in their own store with their own lifecycle. Mixing them would mean one
 * endpoint with two token authorities, which §8 explicitly warns against
 * ("do not query or create a second grant authority"). Existing clients of
 * `/oauth/token` are untouched.
 *
 * Every response carries `Cache-Control: no-store` and `Pragma: no-cache`
 * (RFC 6749 §5.1 for token responses; delivery scope §1 requires it on every
 * token response specifically).
 */

import { Hono, type Context } from "hono";
import type { Logger } from "pino";
import type {
  AuthorizationSessionStore,
  PdppTokenService,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  approveAuthorization,
  denyAuthorization,
  fetchReview,
  PDPP_API_VERSION,
  resolveRequesterIdentity,
  validateSelectionRequest,
  type DeclarationSnapshot,
  type InstanceInventory,
  type PdppAuthStore,
  type SelectionRequest,
} from "@opendatalabs/personal-server-ts-core/pdpp";

/** No-store on everything: tokens, codes, and review models are all sensitive. */
const NO_STORE = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
} as const;

export interface PdppAuthRouteDeps {
  logger: Logger;
  store: PdppAuthStore;
  tokens: PdppTokenService;
  sessions: AuthorizationSessionStore;
  /**
   * Resolve the retained declaration snapshot for a source. The AS resolves
   * only against this snapshot — never a live re-fetch at approval time.
   */
  resolveDeclaration(sourceId: string): DeclarationSnapshot | null;
  /** The owner's connected instances, read fresh at review and approval. */
  inventoryFor(subjectId: string, sourceId: string): InstanceInventory;
  /**
   * The authenticated owner for an incoming authorization request. Returns
   * null when no owner session is present.
   */
  currentSubjectId(c: Context): string | null;
  /** AS-policy grant expiry, when the deployment sets one. */
  grantExpiryFor?(request: SelectionRequest): string | undefined;
}

function errorResponse(
  c: Context,
  status: 400 | 401 | 403 | 404 | 409 | 500,
  error: string,
  description: string,
) {
  return c.json({ error, error_description: description }, status, NO_STORE);
}

/** Bearer token from the Authorization header, if present. */
function bearer(c: Context): string | undefined {
  const header = c.req.header("authorization");
  if (!header?.toLowerCase().startsWith("bearer ")) return undefined;
  const token = header.slice(7).trim();
  return token.length > 0 ? token : undefined;
}

/**
 * Negotiate `PDPP-Version` (§7 version layering, §9 AS item 17).
 *
 * An absent header selects the current stable version. An unsupported one is
 * a 400 `unsupported_version` — not a silent downgrade, because a client that
 * asked for a version it needs must not be handed a different contract.
 */
function negotiateVersion(
  c: Context,
): { ok: true } | { ok: false; requested: string } {
  const requested = c.req.header("pdpp-version");
  if (!requested) return { ok: true };
  if (requested !== PDPP_API_VERSION) return { ok: false, requested };
  return { ok: true };
}

export function pdppAuthRoutes(deps: PdppAuthRouteDeps): Hono {
  const app = new Hono();

  // The selected version echoes back on every response (§9 AS item 17).
  app.use("*", async (c, next) => {
    const version = negotiateVersion(c);
    if (!version.ok) {
      return errorResponse(
        c,
        400,
        "unsupported_version",
        `PDPP-Version '${version.requested}' is not supported; this server implements ${PDPP_API_VERSION}`,
      );
    }
    await next();
    c.header("PDPP-Version", PDPP_API_VERSION);
  });

  /**
   * Accept an RFC 9396 selection request and open an authorization session.
   *
   * Requires an authenticated owner: the session is bound to that subject at
   * creation, which is what makes the later approval check meaningful. A
   * session created for an unauthenticated caller would have no subject to
   * bind an approval against.
   */
  app.post("/authorize", async (c) => {
    const subjectId = deps.currentSubjectId(c);
    if (!subjectId) {
      return errorResponse(
        c,
        401,
        "unauthorized",
        "an authenticated owner session is required to start an authorization",
      );
    }

    let body: {
      authorization_details?: SelectionRequest[];
      client_id?: string;
      redirect_uri?: string;
      state?: string;
      client_display?: { name: string };
    };
    try {
      body = await c.req.json();
    } catch {
      return errorResponse(c, 400, "invalid_request", "body must be JSON");
    }

    const details = body.authorization_details;
    if (!Array.isArray(details) || details.length !== 1) {
      // v0.1 issues one grant per authorization. A package of several details
      // would need package-level access-mode rules (§9 AS item 20) that Core
      // does not yet pin down, so we reject rather than guess.
      return errorResponse(
        c,
        400,
        "invalid_authorization_details",
        "exactly one authorization_details entry is supported",
      );
    }
    if (!body.client_id || !body.redirect_uri) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "client_id and redirect_uri are required",
      );
    }

    const request = details[0];
    const snapshot = deps.resolveDeclaration(request.source?.id ?? "");
    if (!snapshot) {
      return errorResponse(
        c,
        400,
        "invalid_authorization_details",
        "no retained declaration snapshot for the requested source",
      );
    }

    const validation = validateSelectionRequest(request, snapshot);
    if (!validation.ok) {
      // §9 AS item 5: the binding maps a Source validation failure to RFC 9396
      // `invalid_authorization_details`. Other shape failures map to
      // `invalid_request`.
      const oauthError =
        validation.failure.code === "invalid_request"
          ? "invalid_request"
          : "invalid_authorization_details";
      return errorResponse(c, 400, oauthError, validation.failure.message);
    }

    const session = deps.sessions.create({
      subjectId,
      request,
      snapshot,
      requester: resolveRequesterIdentity({
        client_id: body.client_id,
        inline: body.client_display,
      }),
      redirectUri: body.redirect_uri,
      stateParam: body.state,
      grantExpiresAt: deps.grantExpiryFor?.(request),
    });

    deps.logger.info(
      { session_id: session.session_id, client_id: body.client_id },
      "PDPP authorization session opened",
    );

    return c.json(
      { session_id: session.session_id, expires_at: session.expires_at },
      201,
      NO_STORE,
    );
  });

  /** The consent review model, for the authenticated owner only. */
  app.get("/authorize/:session_id/review", (c) => {
    const sessionId = c.req.param("session_id");
    const session = deps.sessions.get(sessionId);

    const result = fetchReview({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
      inventory: deps.inventoryFor(
        session?.subject_id ?? "",
        session?.snapshot.source_id ?? "",
      ),
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        result.failure.code,
        result.failure.message,
      );
    }
    return c.json(result.result, 200, NO_STORE);
  });

  /**
   * Approve. Requires an authenticated owner token AND the review digest the
   * owner was shown — see `approval.ts` for why affiliation is not enough.
   */
  app.post("/authorize/:session_id/approve", async (c) => {
    const sessionId = c.req.param("session_id");
    const session = deps.sessions.get(sessionId);

    let body: {
      review_digest?: string;
      explicit_ai_training_consent?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return errorResponse(c, 400, "invalid_request", "body must be JSON");
    }

    const result = approveAuthorization({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
      reviewDigest: body.review_digest ?? "",
      inventory: deps.inventoryFor(
        session?.subject_id ?? "",
        session?.snapshot.source_id ?? "",
      ),
      explicitAiTrainingConsent: body.explicit_ai_training_consent,
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        result.failure.code,
        result.failure.message,
      );
    }

    // Persist the grant and its consent evidence, then mint a single-use
    // authorization code for the redirect.
    deps.store.insertGrant({
      grant: result.grant,
      subjectId: result.grant.subject.id,
      reviewDigest: result.consentEvidence.review_digest,
      consentEvidence: result.consentEvidence,
    });

    const code = `pdpp_code_${crypto.randomUUID().replace(/-/g, "")}`;
    deps.store.insertAuthCode(code, {
      grantId: result.grant.grant_id,
      clientId: result.grant.client.client_id,
      redirectUri: session!.redirect_uri,
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    const redirect = new URL(session!.redirect_uri);
    redirect.searchParams.set("code", code);
    if (session!.state_param) {
      redirect.searchParams.set("state", session!.state_param);
    }

    deps.logger.info(
      { grant_id: result.grant.grant_id },
      "PDPP grant issued after authenticated owner approval",
    );

    return c.json(
      { redirect_uri: redirect.toString(), grant_id: result.grant.grant_id },
      200,
      NO_STORE,
    );
  });

  /** Deny. Terminal; no grant and no consent evidence beyond the denial. */
  app.post("/authorize/:session_id/deny", (c) => {
    const sessionId = c.req.param("session_id");
    const session = deps.sessions.get(sessionId);

    const result = denyAuthorization({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        result.failure.code,
        result.failure.message,
      );
    }

    const redirect = new URL(session!.redirect_uri);
    redirect.searchParams.set("error", "access_denied");
    if (session!.state_param) {
      redirect.searchParams.set("state", session!.state_param);
    }
    return c.json({ redirect_uri: redirect.toString() }, 200, NO_STORE);
  });

  /**
   * Token endpoint: authorization-code redemption and refresh rotation.
   *
   * Form-encoded per RFC 6749 §4.1.3 / §6, so a standard OAuth client library
   * works against it unmodified.
   */
  app.post("/token", async (c) => {
    const contentType = c.req.header("content-type") ?? "";
    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "Content-Type must be application/x-www-form-urlencoded",
      );
    }

    const body = await c.req.parseBody();
    const grantType = asString(body.grant_type);

    if (grantType === "authorization_code") {
      const code = asString(body.code);
      const clientId = asString(body.client_id);
      const redirectUri = asString(body.redirect_uri);
      if (!code || !clientId || !redirectUri) {
        return errorResponse(
          c,
          400,
          "invalid_request",
          "code, client_id, and redirect_uri are required",
        );
      }
      const result = deps.tokens.redeemAuthorizationCode({
        code,
        clientId,
        redirectUri,
      });
      if (!result.ok) {
        return errorResponse(
          c,
          400,
          result.failure.code,
          result.failure.message,
        );
      }
      return c.json(result.issued, 200, NO_STORE);
    }

    if (grantType === "refresh_token") {
      const refreshToken = asString(body.refresh_token);
      if (!refreshToken) {
        return errorResponse(
          c,
          400,
          "invalid_request",
          "refresh_token is required",
        );
      }
      const result = deps.tokens.refresh({ refreshToken });
      if (!result.ok) {
        return errorResponse(
          c,
          400,
          result.failure.code,
          result.failure.message,
        );
      }
      return c.json(result.issued, 200, NO_STORE);
    }

    return errorResponse(
      c,
      400,
      "unsupported_grant_type",
      `grant_type '${grantType ?? ""}' is not supported by the PDPP token endpoint`,
    );
  });

  /**
   * RFC 7662 introspection.
   *
   * For a co-located deployment the RS uses `resolveToken` directly; this
   * endpoint exists for a separated AS/RS, where §8 requires the RS to
   * authenticate. Authentication is the caller's owner token: only a party
   * already trusted with owner scope may introspect.
   */
  app.post("/introspect", async (c) => {
    const callerToken = bearer(c);
    if (!callerToken) {
      return errorResponse(
        c,
        401,
        "invalid_client",
        "the resource server must authenticate to introspect",
      );
    }
    const caller = deps.tokens.resolveToken(callerToken);
    if (!caller.active || caller.tokenKind !== "owner") {
      return errorResponse(
        c,
        401,
        "invalid_client",
        "introspection requires an authenticated resource server",
      );
    }

    const body = await c.req.parseBody();
    const token = asString(body.token);
    if (!token) {
      // RFC 7662: a missing token is a request error, not an inactive answer.
      return errorResponse(c, 400, "invalid_request", "token is required");
    }

    return c.json(deps.tokens.introspect(token), 200, NO_STORE);
  });

  /**
   * Revoke a grant. Owner-authenticated, and scoped to the owner's own grants
   * — a valid owner token is not authority over another subject's grant.
   */
  app.post("/revoke", async (c) => {
    const ownerToken = bearer(c);
    if (!ownerToken) {
      return errorResponse(
        c,
        401,
        "unauthorized",
        "an owner token is required",
      );
    }
    const caller = deps.tokens.resolveToken(ownerToken);
    if (!caller.active || caller.tokenKind !== "owner" || !caller.subjectId) {
      return errorResponse(
        c,
        401,
        "unauthorized",
        "an active owner token is required",
      );
    }

    const body = await c.req.parseBody();
    const grantId = asString(body.grant_id);
    if (!grantId) {
      return errorResponse(c, 400, "invalid_request", "grant_id is required");
    }

    const stored = deps.store.getGrant(grantId);
    // Not-found for another owner's grant as well, so a caller cannot probe
    // which grant ids exist outside their own subject.
    if (!stored || stored.subjectId !== caller.subjectId) {
      return errorResponse(c, 404, "not_found", "grant not found");
    }

    const revoked = deps.tokens.revokeGrant(grantId);
    deps.logger.info({ grant_id: grantId, revoked }, "PDPP grant revocation");

    // Idempotent: a second revoke is still "it is revoked".
    return c.json({ grant_id: grantId, status: "revoked" }, 200, NO_STORE);
  });

  return app;
}

function approvalStatus(code: string): 400 | 401 | 403 | 404 | 409 {
  switch (code) {
    case "unauthorized":
      return 401;
    case "session_not_found":
      return 404;
    case "stale_review":
      return 409;
    default:
      return 400;
  }
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}
