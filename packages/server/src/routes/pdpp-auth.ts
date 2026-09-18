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
 *
 * Two things that cost integrators a debug cycle, so stated plainly:
 *
 *   - **Content types differ by endpoint.** `/authorize`, `/approve` and
 *     `/deny` take JSON. `/token`, `/introspect` and `/revoke` take
 *     `application/x-www-form-urlencoded`, because they follow the RFC 6749 /
 *     7662 / 7009 wire conventions a standard OAuth client library already
 *     speaks. Sending JSON to the form endpoints parses to an empty body and
 *     reads as a missing parameter.
 *   - **The review digest is nested.** `GET /authorize/:id/review` returns
 *     `{ session_id, review, expires_at }`, so the digest is at
 *     `review.review_digest`, not at the top level. The envelope also carries
 *     `instance_choice_required` instead of `review` when the owner still has
 *     an instance to pick.
 */

import { Hono, type Context } from "hono";
import type { Logger } from "pino";
import type {
  ClientIdentityResult,
  ClientIdMetadataDocument,
} from "@opendatalabs/personal-server-ts-core/pdpp";
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
  validateCodeChallenge,
  validateRedirectUri,
  validateSelectionRequest,
  type DeclarationSnapshot,
  type InstanceInventory,
  type PdppAuthStore,
  type RegisteredRedirectPolicy,
  type SelectionRequest,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";
import type { TokenStore } from "../token-store.js";

/** No-store on everything: tokens, codes, and review models are all sensitive. */
const NO_STORE = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
} as const;

/** Owner tokens are short-lived: they authorize consent decisions. */
export const OWNER_TOKEN_TTL_SECONDS = 15 * 60;

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
  /**
   * Resolve the PDPP subject for a request that already passed the PS owner
   * proof (`web3-auth` + `owner-check`). Used only by
   * `POST /owner/token`. Defaults to `currentSubjectId` when a deployment
   * uses one notion of owner identity for both.
   */
  ownerSubjectId?(c: Context): string | null;
  /**
   * Owner-proof wiring. When supplied, `POST /owner/token` is guarded by the
   * PS's existing `web3-auth` + `owner-check` middleware — the same wallet
   * signature chain every other owner route uses — and the verified signer
   * becomes the PDPP subject. Absent, the route falls back to
   * `ownerSubjectId`/`currentSubjectId`, which is how the unit tests drive it.
   */
  ownerAuth?: {
    serverOrigin: string | (() => string);
    serverOwner?: `0x${string}`;
    devToken?: string;
    accessToken?: string;
    tokenStore?: TokenStore;
  };
  /**
   * Registered metadata for a client, used to validate `redirect_uri` by
   * exact match (RFC 6749 §3.1.2.2). Returning null means the client is
   * unregistered, and an unregistered client cannot receive an authorization
   * code — the AS fails closed rather than trusting the requested target.
   */
  registeredClient?(clientId: string): RegisteredRedirectPolicy | null;
  /**
   * Resolve a URL-hosted client identity (§6) when a client is not locally
   * registered. Optional: leaving it unset preserves registration-only
   * behavior exactly, and performs no outbound fetch.
   */
  resolveClientIdentity?(clientId: string): Promise<ClientIdentityResult>;
  /** AS-policy grant expiry, when the deployment sets one. */
  grantExpiryFor?(request: SelectionRequest): string | undefined;
  /**
   * Require PKCE on the authorization code flow. Defaults to true and should
   * stay true: PDPP clients are public clients, so without a verifier an
   * intercepted code is redeemable by whoever intercepted it.
   */
  requirePkce?: boolean;
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

  // The owner-proof chain, when a deployment wires one. `web3-auth` verifies
  // the Web3Signed wallet signature and populates `c.get("auth")`;
  // `owner-check` compares the recovered signer against the configured server
  // owner. Scoped to the token-exchange path only — the rest of the surface
  // authenticates with the PDPP owner token that exchange produces.
  if (deps.ownerAuth) {
    app.use(
      "/owner/token",
      createWeb3AuthMiddleware({
        serverOrigin: deps.ownerAuth.serverOrigin,
        devToken: deps.ownerAuth.devToken,
        accessToken: deps.ownerAuth.accessToken,
        tokenStore: deps.ownerAuth.tokenStore,
        serverOwner: deps.ownerAuth.serverOwner,
      }),
    );
    app.use(
      "/owner/token",
      createOwnerCheckMiddleware(deps.ownerAuth.serverOwner),
    );
  }

  /**
   * Exchange an already-verified owner proof for a PDPP owner token.
   *
   * This endpoint mints no authority of its own. The caller must already have
   * satisfied the PS's existing owner proof — the `web3-auth` middleware
   * verifies a Web3Signed wallet signature and `owner-check` compares the
   * recovered signer against the configured server owner. This route only
   * converts that proof into the short-lived, grant-system credential the
   * consent decision endpoints require.
   *
   * The indirection is deliberate and is the whole point of the design in
   * `approval.ts`: a consent broker (Account/Web) never mints an owner token
   * and never asserts owner identity. It holds a credential the PS issued to
   * a verified wallet signer, so compromising the broker yields a token that
   * expires, not the authority to approve anything for any subject.
   *
   * Mount this behind the same middleware chain as other owner routes:
   *
   *   app.use("/pdpp/v1/owner/token", createWeb3AuthMiddleware(...));
   *   app.use("/pdpp/v1/owner/token", createOwnerCheckMiddleware(serverOwner));
   *
   * `ownerSubjectId` resolves the verified signer to the PDPP subject; a
   * deployment that maps wallets to subjects differently supplies its own.
   */
  app.post("/owner/token", (c) => {
    // With `ownerAuth` wired, the middleware above has already verified a
    // wallet signature and confirmed the signer is the server owner, so
    // `c.get("auth").signer` is a proven identity rather than a claim.
    const verifiedSigner = (c.get("auth") as { signer?: string } | undefined)
      ?.signer;
    const subjectId =
      deps.ownerSubjectId?.(c) ??
      (deps.ownerAuth && verifiedSigner ? verifiedSigner : null) ??
      deps.currentSubjectId(c);
    if (!subjectId) {
      // Reaching here means the owner middleware did not run or did not
      // populate a verified signer. Fail closed rather than inventing a
      // subject — an owner token for an unidentified subject is exactly the
      // credential this design exists to prevent.
      return errorResponse(
        c,
        401,
        "unauthorized",
        "a verified owner proof is required to obtain a PDPP owner token",
      );
    }

    const issued = deps.tokens.issueOwnerToken({
      subjectId,
      ttlSeconds: OWNER_TOKEN_TTL_SECONDS,
    });
    deps.logger.info(
      { subject_id: subjectId },
      "PDPP owner token issued to a verified owner",
    );
    return c.json(issued, 200, NO_STORE);
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
      code_challenge?: string;
      code_challenge_method?: string;
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

    // The authorization code travels in this redirect, so an unvalidated
    // target is code exfiltration, not just an open redirect. PKCE does not
    // help: an attacker who chose the redirect also chose the challenge and
    // holds the verifier. RFC 6749 §4.1.2.1 forbids reporting this failure BY
    // redirecting, so it is returned directly to the caller.
    // Local registration has highest precedence and costs no network call.
    // Only when a client is NOT registered does §6 require us to try its
    // URL-hosted identity: rejecting solely for absence of preregistration is
    // the one reason the spec names as insufficient.
    let redirectPolicy = deps.registeredClient?.(body.client_id) ?? null;
    // The document that earned redirect admission, carried forward so the
    // consent surface shows the identity the verified domain asserted rather
    // than whatever the client put in `client_display`. §6 ranks validated
    // binding metadata above inline metadata; admitting on the document and
    // then displaying the inline name would break that.
    let validatedClientDocument: ClientIdMetadataDocument | undefined;
    if (!redirectPolicy && deps.resolveClientIdentity) {
      const resolved = await deps.resolveClientIdentity(body.client_id);
      if (resolved.ok) {
        redirectPolicy = resolved.policy;
        validatedClientDocument = resolved.document;
      } else {
        // The refusal names the actual reason -- untrusted URL, unreachable,
        // mismatched document -- rather than "not registered", so an operator
        // can tell a policy denial from a broken client.
        deps.logger.warn(
          { client_id: body.client_id, reason: resolved.failure.code },
          "PDPP authorization refused: URL-hosted client identity rejected",
        );
      }
    }

    const redirectFailure = validateRedirectUri(
      body.redirect_uri,
      redirectPolicy,
    );
    if (redirectFailure) {
      deps.logger.warn(
        {
          client_id: body.client_id,
          redirect_uri: body.redirect_uri,
          reason: redirectFailure.code,
        },
        "PDPP authorization refused: redirect_uri failed validation",
      );
      return errorResponse(c, 400, "invalid_request", redirectFailure.message);
    }

    // PKCE is validated before consent, not at redemption: a client whose flow
    // is unusable should learn that before a human is asked to decide anything.
    const pkceFailure = validateCodeChallenge(
      body.code_challenge,
      body.code_challenge_method,
      { required: deps.requirePkce ?? true },
    );
    if (pkceFailure) {
      return errorResponse(c, 400, "invalid_request", pkceFailure.message);
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
        document: validatedClientDocument,
        inline: body.client_display,
      }),
      redirectUri: body.redirect_uri,
      stateParam: body.state,
      codeChallenge: body.code_challenge,
      codeChallengeMethod: body.code_challenge_method,
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

  /**
   * The consent review model, for the authenticated owner only.
   *
   * When a stream has several eligible instances and the request named none,
   * the response carries `instance_choice_required` instead of a review: the
   * owner picks, then re-fetches with `?instance[<stream>]=<handle>` repeated
   * per handle. §6 forbids inferring fan-in from omission, so this is a
   * consent step rather than a failure.
   */
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
      instanceChoices: parseInstanceChoices(c),
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
      instance_choices?: Record<string, string[]>;
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
      instanceChoices: body.instance_choices,
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
      // Carried from the authorization request, so redemption can prove the
      // redeemer is the client that asked (RFC 7636 §4.4).
      codeChallenge: session!.code_challenge ?? null,
      codeChallengeMethod: session!.code_challenge_method ?? null,
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
        codeVerifier: asString(body.code_verifier) ?? undefined,
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
   * **The co-located deployment is the supported baseline**, and there the RS
   * calls `resolveToken` directly — this endpoint is not on that path.
   *
   * **Known gap for the separated deployment (§9 AS item 18).** The only
   * credential accepted here is a PDPP *owner* token: 15-minute TTL, mintable
   * only from a wallet owner-proof. A standalone Resource Server cannot hold
   * one, so the deployment topology this endpoint exists to serve cannot
   * actually authenticate to it. Closing that needs a distinct RS client
   * identity (client credentials, mTLS, or a registered RS principal) that is
   * not owner scope, which is a deployment-model decision this build does not
   * make.
   *
   * Stated plainly rather than papered over: this AS does **not** claim
   * conformance for separated AS/RS introspection. It is conformant for the
   * co-located equivalent §8 explicitly permits ("A co-located AS and RS MAY
   * resolve the same context through a local equivalent").
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

/**
 * Read owner instance picks from repeated `instance[<stream>]=<handle>` query
 * parameters, so a choice survives a plain GET re-fetch without the UI having
 * to hold server state.
 */
function parseInstanceChoices(
  c: Context,
): Record<string, string[]> | undefined {
  const choices: Record<string, string[]> = {};
  const url = new URL(c.req.url);
  for (const [key, value] of url.searchParams.entries()) {
    const match = /^instance\[(.+)\]$/.exec(key);
    if (!match || value.length === 0) continue;
    (choices[match[1]] ??= []).push(value);
  }
  return Object.keys(choices).length > 0 ? choices : undefined;
}
