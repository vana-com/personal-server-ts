/**
 * PDPP Core v0.1.0 Authorization Server HTTP surface.
 *
 * The endpoints under `/pdpp/v1`:
 *
 *   POST /authorize                      — accept an RFC 9396 selection request
 *   GET  /authorize/:session_id/review   — the owner's consent review model
 *   POST /authorize/:session_id/approve  — authenticated owner approval
 *   POST /authorize/:session_id/deny     — authenticated owner denial
 *   POST /token                          — code redemption + refresh rotation
 *   POST /introspect                     — RFC 7662 introspection
 *   POST /token/revoke                   — RFC 7009 client token revocation
 *                                          (the advertised `revocation_endpoint`)
 *   POST /grant-lifecycle                — the grant lifecycle operation
 *                                          (advertised `pdpp_grant_lifecycle_endpoint`)
 *   GET  /grants                         — the owner's grants, with status and
 *                                          held-data lifecycle
 *   POST /revoke                         — owner-initiated grant revocation
 *                                          (owner token + grant_id + disposition;
 *                                          not advertised)
 *   GET  /owner/grants/affected          — the affected set of an owner ending
 *   POST /owner/grants/end               — owner revoke / disconnect / narrowing
 *   POST /owner/grants/erasure           — owner erasure request or advance election
 *   GET  /owner/decommission             — AS decommission view (AS item 46)
 *   POST /owner/decommission/confirm     — record dispositions, confirm (wallet proof)
 *   POST /owner/lifecycle/disable-tokens — disable tokens for lifecycle use
 *   GET  /owner/lifecycle/history        — history currency and pending actions
 *   POST /owner/lifecycle/reestablish    — re-establish a non-current history
 *                                          (wallet proof when wired)
 *
 * Operator policy (AS item 38): the operator does not use owner data held in
 * this Authorization Server role for AI training, except under a training
 * grant issued to it as a client. See docs/pdpp-operator-policy.md.
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
import { readNamedQueryValues } from "./pdpp-auth-query-keys.js";
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
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_DATA_ACCESS_TYPE_CANDIDATE,
  usesLockedRules,
  isSupportedPersistedGrant,
  resolveRequesterIdentity,
  validateCodeChallenge,
  validateRedirectUri,
  validateSelectionRequest,
  validatePublicDetail,
  parseUiLocales,
  SUPPORTED_PROCESSING_PERMISSIONS,
  validateCandidateOwnerChoices,
  GrantLifecycleService,
  HISTORY_RETRY_AFTER_SECONDS,
  PDPP_GRANT_LIFECYCLE_TYPE,
  PENDING_HISTORY_STATEMENT,
  type OwnerActionResult,
  type OwnerEndingAction,
  type ApprovalFailure,
  type DeclarationSnapshot,
  type GrantStatus,
  type InstanceInventory,
  type OwnerChoices,
  type OwnerConditions,
  type PdppAuthStore,
  type RecipientTerms,
  type RegisteredRedirectPolicy,
  type SelectionRequest,
  type StoredGrant,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { createWeb3AuthMiddleware } from "../middleware/web3-auth.js";
import { createOwnerCheckMiddleware } from "../middleware/owner-check.js";
import { createBodyLimit, DEFAULT_MAX_SIZE } from "../middleware/body-limit.js";
import type { TokenStore } from "../token-store.js";
import { canonicalSourceIdCandidate } from "../pdpp/source-id-compat.js";

/** No-store on everything: tokens, codes, and review models are all sensitive. */
const NO_STORE = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
} as const;

/** Owner tokens are short-lived: they authorize consent decisions. */
export const OWNER_TOKEN_TTL_SECONDS = 15 * 60;

export interface PdppAuthRouteDeps {
  /** Candidate protocol behavior is opt-in per deployment. */
  protocolProfile?: "current" | "candidate-0.1.0";
  logger: Logger;
  store: PdppAuthStore;
  tokens: PdppTokenService;
  sessions: AuthorizationSessionStore;
  /**
   * Resolve the retained declaration snapshot for a source. The AS resolves
   * only against this snapshot — never a live re-fetch at approval time.
   */
  resolveDeclaration(sourceId: string): DeclarationSnapshot | null;
  /** Resolve an owner-token source from the independent connection registry. */
  resolveConnectionSourceId?(sourceId: string): string | undefined;
  /** The owner's connected instances, read fresh at review and approval. */
  inventoryFor(subjectId: string, sourceId: string): InstanceInventory;
  connectionState?(instanceId: string): {
    sourceId: string | null;
    deleted: boolean;
  };
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
  /**
   * AS-policy grant expiry, when the deployment sets one.
   *
   * `clientId` is the second argument (not folded into `request`) because it
   * is authorization-request context, not part of the RFC 9396 selection
   * request itself — Core's `SelectionRequest` stays binding-neutral and
   * carries no client identity. `request` remains first for compatibility
   * with any existing caller that only closed over it.
   */
  grantExpiryFor?(
    request: SelectionRequest,
    clientId: string,
  ): string | undefined;
  /**
   * Require PKCE on the authorization code flow. Defaults to true and should
   * stay true: PDPP clients are public clients, so without a verifier an
   * intercepted code is redeemable by whoever intercepted it.
   */
  requirePkce?: boolean;
  /**
   * Standing terms this client has authorized, when the deployment tracks
   * them.
   *
   * Absent means the AS knows of no standing terms, which is the safe default
   * rather than a gap: with no terms, only conditions the client's own request
   * already covers can become commitments, and anything else refuses. v0.2 is
   * explicit that a capability advertisement is not acceptance, so an AS that
   * cannot evidence acceptance must not assume it.
   */
  standingTermsFor?(clientId: string): RecipientTerms | null;
  /**
   * This authorization server's issuer identifier, used to build the absolute
   * endpoint URLs in its metadata document. Absent omits the document
   * entirely rather than publishing relative or guessed URLs — a client that
   * cannot resolve the endpoints is worse off than one that finds no document
   * and falls back to configuration.
   */
  issuer?: string | (() => string);
  /**
   * The held-data lifecycle service (AS items 39-47). Defaults to one over
   * `store`, using the token service's clock.
   */
  lifecycle?: GrantLifecycleService;
}

function unavailable(
  c: Context,
  description: string,
  retryAfter = HISTORY_RETRY_AFTER_SECONDS,
) {
  return c.json(
    { error: "temporarily_unavailable", error_description: description },
    503,
    { ...NO_STORE, "Retry-After": String(retryAfter) },
  );
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

function resolveScopedOwnerToken(
  deps: PdppAuthRouteDeps,
  ownerToken: string | undefined,
  subjectId?: string,
  sourceId?: string,
):
  | { ok: true; subjectId: string; sourceId?: string; instanceIds?: string[] }
  | { ok: false; failure: ApprovalFailure } {
  if (!ownerToken) {
    return {
      ok: false,
      failure: {
        code: "unauthorized",
        message: "a scoped owner token is required",
      },
    };
  }

  const context = deps.tokens.resolveToken(ownerToken);
  if (!context.active || context.tokenKind !== "owner" || !context.subjectId) {
    return {
      ok: false,
      failure: {
        code: "unauthorized",
        message: "an active scoped owner token is required",
      },
    };
  }
  if (subjectId && context.subjectId !== subjectId) {
    return {
      ok: false,
      failure: {
        code: "session_not_found",
        message: "authorization session not found",
      },
    };
  }
  if (context.sourceId && sourceId && context.sourceId !== sourceId) {
    return {
      ok: false,
      failure: {
        code: "access_denied",
        message: "owner token is not scoped to the requested source",
      },
    };
  }
  return {
    ok: true,
    subjectId: context.subjectId,
    ...(context.sourceId && { sourceId: context.sourceId }),
    ...(context.instanceIds && { instanceIds: context.instanceIds }),
  };
}

const OUTSIDE_INSTANCE_CEILING =
  "owner token is not scoped to the requested instance";

/**
 * The owner's consent inventory, narrowed to the instance ceiling of the token
 * that is deciding. An absent ceiling is source-wide; a present one is the whole
 * universe, so an empty list covers no instance rather than the whole source.
 */
function ceilingInventory(
  inventory: InstanceInventory,
  ceiling: string[] | undefined,
): InstanceInventory {
  if (!ceiling) return inventory;
  return {
    eligibleFor: (streamName) =>
      inventory.eligibleFor(streamName).filter((id) => ceiling.includes(id)),
  };
}

/**
 * Every instance handle a request names, explicitly or through an owner choice.
 *
 * The request is untrusted until validation runs, so any shape is tolerated
 * here. Validation then answers a malformed `streams` with a 400.
 */
function namedInstanceHandles(
  request: SelectionRequest,
  choices?: Record<string, string[]>,
): string[] {
  const streams = Array.isArray(request.streams) ? request.streams : [];
  return [
    ...streams.flatMap((stream) => stream?.instance_ids ?? []),
    ...Object.values(choices ?? {}).flat(),
  ];
}

/** Whether any named handle falls outside the ceiling. No ceiling, nothing does. */
function namesOutsideCeiling(
  ceiling: string[] | undefined,
  handles: string[],
): boolean {
  return ceiling !== undefined && handles.some((id) => !ceiling.includes(id));
}

/** Whether every granted stream stays inside the ceiling. No ceiling, all do. */
function streamsWithinCeiling(
  streams: ReadonlyArray<{ instance_ids: string[] }>,
  ceiling: string[] | undefined,
): boolean {
  return (
    !ceiling ||
    streams.every((stream) =>
      stream.instance_ids.every((id) => ceiling.includes(id)),
    )
  );
}

function scopedOwnerCoversSnapshot(
  deps: PdppAuthRouteDeps,
  subjectId: string,
  snapshot: DeclarationSnapshot,
  ceiling: string[] | undefined,
): boolean {
  const inventory = ceilingInventory(
    deps.inventoryFor(subjectId, snapshot.source_id),
    ceiling,
  );
  return snapshot.streams.some(
    (stream) => inventory.eligibleFor(stream.name).length > 0,
  );
}

function grantContainedByOwnerScope(
  subjectId: string,
  stored: StoredGrant,
  ownerSourceId?: string,
  ownerInstanceIds?: string[],
): boolean {
  return (
    stored.subjectId === subjectId &&
    (!ownerSourceId || stored.grant.source.id === ownerSourceId) &&
    (!ownerInstanceIds ||
      stored.grant.streams.every((stream) =>
        stream.instance_ids.every((instance) =>
          ownerInstanceIds.includes(instance),
        ),
      ))
  );
}

function scopedOwnerFailureResponse(c: Context, failure: ApprovalFailure) {
  return errorResponse(
    c,
    failure.code === "access_denied" ? 403 : approvalStatus(failure.code),
    approvalOAuthError(failure.code),
    failure.message,
  );
}

/**
 * The PDPP AS metadata document, as a handler both of its locations share.
 *
 * Exported because the two URLs it is served at live in different routers: the
 * path-first one inside `/pdpp/v1`, and the RFC 8414 §3 one
 * (`/.well-known/oauth-authorization-server/pdpp/v1`) at the app root, outside
 * this prefix. One handler rather than two so the documents can never drift --
 * a client discovering through either must find the same authority.
 *
 * `issuer` is accepted as a thunk for deployments that resolve their own origin
 * late (a bound port unknown at construction). It is resolved per request so
 * the document never advertises a stale origin.
 */
export function pdppAsMetadataHandler(
  issuerSource: PdppAuthRouteDeps["issuer"],
  protocolProfile: PdppAuthRouteDeps["protocolProfile"] = "current",
): (c: Context) => Response {
  return (c: Context) => {
    const issuer =
      typeof issuerSource === "function" ? issuerSource() : issuerSource;
    if (!issuer) {
      return errorResponse(
        c,
        404,
        "not_found",
        "this deployment does not publish PDPP authorization-server metadata",
      );
    }
    const base = `${issuer.replace(/\/$/, "")}/pdpp/v1`;
    return c.json(
      {
        issuer,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        introspection_endpoint: `${base}/introspect`,
        // AS item 25 / spec-core L2781: an AS that supports RFC 7009
        // revocation MUST advertise `revocation_endpoint`. It points at the
        // RFC 7009 route, never at the owner-token grant revocation route.
        revocation_endpoint: `${base}/token/revoke`,
        // AS item 39 / spec-core L1692: the grant lifecycle operation.
        pdpp_grant_lifecycle_endpoint: `${base}/grant-lifecycle`,
        // AS item 33 / L1802: data access and lifecycle recovery.
        authorization_details_types_supported: [
          PDPP_DATA_ACCESS_TYPE,
          PDPP_GRANT_LIFECYCLE_TYPE,
          PDPP_DATA_ACCESS_TYPE_V02,
          ...(protocolProfile === "candidate-0.1.0"
            ? [PDPP_DATA_ACCESS_TYPE_CANDIDATE]
            : []),
        ],
        // AS item 14 / spec-core L1126: only permissions whose complete
        // defining contract the AS implements. None (case O7).
        pdpp_processing_permissions_supported: [
          ...SUPPORTED_PROCESSING_PERMISSIONS,
        ],
        grant_types_supported: ["authorization_code", "refresh_token"],
        response_types_supported: ["code"],
        // PKCE is required on this flow, not merely supported: PDPP clients
        // are public clients, so an intercepted code without a verifier is
        // redeemable by whoever intercepted it.
        code_challenge_methods_supported: ["S256"],
      },
      200,
      NO_STORE,
    );
  };
}

export function pdppAuthRoutes(deps: PdppAuthRouteDeps): Hono {
  const app = new Hono();
  const lifecycle =
    deps.lifecycle ??
    new GrantLifecycleService(deps.store, {
      ...(deps.tokens.clock && { clock: deps.tokens.clock }),
    });
  const now = () => lifecycle.clock();

  // No PDPP-Version negotiation here: "It does not negotiate OAuth
  // authorization, token, revocation, introspection, or grant lifecycle
  // endpoints" (spec-core §8 "API versioning"; §9 AS item 17 is "Not used").
  // A PDPP-Version field on an AS request is ignored, and AS responses carry
  // none.

  // The owner-proof chain, when a deployment wires one. `web3-auth` verifies
  // the Web3Signed wallet signature and populates `c.get("auth")`;
  // `owner-check` compares the recovered signer against the configured server
  // owner. Scoped to the token-exchange path only — the rest of the surface
  // authenticates with the PDPP owner token that exchange produces.
  if (deps.ownerAuth) {
    app.use("/owner/token", createBodyLimit(DEFAULT_MAX_SIZE));
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
    // Whole-server owner actions (decommission, history re-establishment)
    // end grants across every source, so a source-scoped owner token held by
    // a consent broker must not reach them: they take the wallet proof.
    for (const path of [
      "/owner/decommission/confirm",
      "/owner/lifecycle/reestablish",
    ]) {
      app.use(path, createBodyLimit(DEFAULT_MAX_SIZE));
      app.use(
        path,
        createWeb3AuthMiddleware({
          serverOrigin: deps.ownerAuth.serverOrigin,
          devToken: deps.ownerAuth.devToken,
          accessToken: deps.ownerAuth.accessToken,
          tokenStore: deps.ownerAuth.tokenStore,
          serverOwner: deps.ownerAuth.serverOwner,
        }),
      );
      app.use(path, createOwnerCheckMiddleware(deps.ownerAuth.serverOwner));
    }
  }

  /**
   * OAuth authorization-server metadata for the PDPP AS.
   *
   * v0.2 §8 requires an AS supporting the revision to advertise
   * `https://pdpp.dev/data-access/0.2` in
   * `authorization_details_types_supported`, and requires a client to
   * establish support before requesting the type. Without this document a
   * conformant client must not request v0.2 at all, so the implementation
   * would be unreachable to exactly the clients that follow the spec.
   *
   * Both types are advertised: both are implemented, each resolves under its
   * own revision, and dropping v0.1 would strand existing clients.
   *
   * This sits under `/pdpp/v1/` rather than at the origin root because the
   * root document already describes the MCP OAuth authorization server — a
   * different authority over different tokens. §8 warns against a second grant
   * authority; merging the documents would present the two as one.
   *
   * The SAME document is also served at the RFC 8414 §3 location
   * (`/.well-known/oauth-authorization-server/pdpp/v1` — well-known first, the
   * issuer's path appended), mounted by the app because it lies outside this
   * router's prefix. Publishing only the path-first form above left the
   * document undiscoverable to any client that follows RFC 8414, which is the
   * only discovery rule the spec gives. The RFC location keeps the `/pdpp/v1`
   * suffix, so it does not collide with the bare URL the MCP AS owns and the
   * separation this comment describes is preserved.
   */
  app.get(
    "/.well-known/oauth-authorization-server",
    pdppAsMetadataHandler(deps.issuer, deps.protocolProfile),
  );

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
  app.post("/owner/token", async (c) => {
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

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "owner token exchange requires JSON body {source_id}",
      );
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "owner token exchange requires JSON body {source_id}",
      );
    }
    const tokenRequest = body as Record<string, unknown>;
    const sourceId = tokenRequest.source_id;
    if (
      typeof sourceId !== "string" ||
      Object.keys(tokenRequest).some(
        (key) => key !== "source_id" && key !== "instance_id",
      ) ||
      (tokenRequest.instance_id !== undefined &&
        (typeof tokenRequest.instance_id !== "string" ||
          tokenRequest.instance_id.length === 0))
    ) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "owner token exchange accepts source_id and an optional instance_id",
      );
    }
    const canonicalCandidate = canonicalSourceIdCandidate(sourceId);
    const declaration =
      deps.resolveDeclaration(sourceId) ??
      (canonicalCandidate ? deps.resolveDeclaration(canonicalCandidate) : null);
    const connectionSourceId =
      deps.resolveConnectionSourceId?.(sourceId) ??
      (canonicalCandidate
        ? deps.resolveConnectionSourceId?.(canonicalCandidate)
        : undefined);
    const resolvedSourceId = declaration?.source_id ?? connectionSourceId;
    if (!resolvedSourceId) {
      return errorResponse(
        c,
        404,
        "not_found",
        "source is not enabled on this server",
      );
    }
    const issued = deps.tokens.issueOwnerToken({
      subjectId,
      sourceId: resolvedSourceId,
      ...(typeof tokenRequest.instance_id === "string" && {
        instanceIds: [tokenRequest.instance_id],
      }),
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
      /** OIDC `ui_locales` (spec-core L1073): a hint, never a rejection. */
      ui_locales?: string;
    };
    try {
      body = await c.req.json();
    } catch {
      return errorResponse(c, 400, "invalid_request", "body must be JSON");
    }
    if (body === null || typeof body !== "object" || Array.isArray(body)) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "body must be a JSON object",
      );
    }

    const details = body.authorization_details;
    // L1802 / case D3: a recovery request contains no other detail.
    if (
      Array.isArray(details) &&
      details.length > 1 &&
      details.some(
        (d) =>
          d &&
          typeof d === "object" &&
          (d as { type?: unknown }).type === PDPP_GRANT_LIFECYCLE_TYPE,
      )
    ) {
      return errorResponse(
        c,
        400,
        "invalid_authorization_details",
        "a lifecycle recovery request contains no other authorization detail",
      );
    }
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
      } else if (resolved.failure.code === "client_not_admitted") {
        // AS item 50 / spec-core L1027: a denial under local policy is not a
        // rejection of the identity form, so it gets its own error.
        deps.logger.warn(
          { client_id: body.client_id },
          "PDPP authorization refused: client not admitted by local policy",
        );
        return errorResponse(
          c,
          400,
          "unauthorized_client",
          resolved.failure.message,
        );
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

    // ── Lifecycle recovery (spec-core L1802-L1808, AS item 47) ──────────
    if (
      request &&
      typeof request === "object" &&
      (request as { type?: unknown }).type === PDPP_GRANT_LIFECYCLE_TYPE
    ) {
      const parsed = GrantLifecycleService.parseRecoveryDetail(request);
      if (!parsed.ok) {
        return errorResponse(
          c,
          400,
          "invalid_authorization_details",
          parsed.message,
        );
      }
      const owner = resolveScopedOwnerToken(deps, bearer(c), subjectId);
      if (!owner.ok) return scopedOwnerFailureResponse(c, owner.failure);
      const opened = lifecycle.openRecoverySession({
        subjectId,
        clientId: body.client_id,
        grantIds: parsed.grantIds,
        redirectUri: body.redirect_uri,
        ...(body.state && { stateParam: body.state }),
        ...(body.code_challenge && { codeChallenge: body.code_challenge }),
        ...(body.code_challenge_method && {
          codeChallengeMethod: body.code_challenge_method,
        }),
        inScope: (stored) =>
          grantContainedByOwnerScope(
            subjectId,
            stored,
            owner.sourceId,
            owner.instanceIds,
          ),
      });
      if (!opened.ok) {
        // L1804: reject without revealing which grant failed.
        return errorResponse(
          c,
          400,
          "invalid_authorization_details",
          opened.message,
        );
      }
      return c.json(
        { session_id: opened.session_id, expires_at: opened.expires_at },
        201,
        NO_STORE,
      );
    }

    // ── Owner-independent checks (spec-core L1218, AS item 52) ──────────
    // Public structure and this build's fixed capabilities only. Every
    // failure here is public invalidity: `invalid_authorization_details`
    // (AS items 2, 5, 14, 33).
    const publicValidation = validatePublicDetail(request, {
      candidateEnabled: deps.protocolProfile === "candidate-0.1.0",
    });
    if (!publicValidation.ok) {
      return errorResponse(
        c,
        400,
        "invalid_authorization_details",
        publicValidation.failure.message,
      );
    }

    // The owner token deciding this flow must be scoped to the requested
    // source. This checks the broker's credential, not owner data.
    const owner = resolveScopedOwnerToken(
      deps,
      bearer(c),
      subjectId,
      request.source.id,
    );
    if (!owner.ok) {
      return scopedOwnerFailureResponse(c, owner.failure);
    }

    // ── Owner-dependent checks, deferred (spec-core L1220-L1222) ─────────
    // Declaration acceptance is per-owner on a Personal Server, and so are
    // instance handles and their eligibility. None of these may change what
    // this endpoint returns: a failure opens the session exactly as success
    // does, and is explained only inside authenticated review, ending for
    // the client in the same `access_denied` an owner decline produces
    // (L1230, L1238; AS items 2, 53, 57). Every check runs on every request,
    // so the work done does not depend on which one fails (L1238, AS 54).
    const retained = deps.resolveDeclaration(request.source.id);
    const snapshot: DeclarationSnapshot = retained ?? {
      source_id: request.source.id,
      source_kind: "connector",
      version: "",
      digest: "",
      streams: [],
    };
    const outsideCeiling = namesOutsideCeiling(
      owner.instanceIds,
      namedInstanceHandles(request),
    );
    const covered = scopedOwnerCoversSnapshot(
      deps,
      subjectId,
      snapshot,
      owner.instanceIds,
    );
    const declarationValidation = validateSelectionRequest(request, snapshot);
    const ineligibleReason = !retained
      ? "this server holds no accepted declaration for the requested source"
      : outsideCeiling
        ? OUTSIDE_INSTANCE_CEILING
        : !covered
          ? "owner token is not scoped to the requested source"
          : !declarationValidation.ok
            ? declarationValidation.failure.message
            : undefined;

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
      grantExpiresAt: deps.grantExpiryFor?.(request, body.client_id),
      // AS item 34: unparseable tags are ignored, never rejected (L1073).
      languagePriority: parseUiLocales(body.ui_locales),
      ...(ineligibleReason !== undefined && {
        ineligible: { message: ineligibleReason },
      }),
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
    if (lifecycle.hasRecoverySession(sessionId)) {
      const owner = resolveScopedOwnerToken(
        deps,
        bearer(c),
        lifecycle.recoverySessionSubject(sessionId),
      );
      if (!owner.ok) return scopedOwnerFailureResponse(c, owner.failure);
      const review = lifecycle.recoveryReview(sessionId, owner.subjectId);
      if (!review.ok)
        return errorResponse(
          c,
          404,
          "session_not_found",
          "authorization session not found",
        );
      return c.json(
        {
          session_id: sessionId,
          recovery: review.review,
          expires_at: review.expires_at,
        },
        200,
        NO_STORE,
      );
    }
    const session = deps.sessions.get(sessionId);
    const owner = resolveScopedOwnerToken(
      deps,
      bearer(c),
      session?.subject_id,
      session?.snapshot.source_id,
    );
    if (!owner.ok) {
      return scopedOwnerFailureResponse(c, owner.failure);
    }
    if (
      session &&
      !session.ineligible &&
      !scopedOwnerCoversSnapshot(
        deps,
        session.subject_id,
        session.snapshot,
        owner.instanceIds,
      )
    ) {
      return errorResponse(
        c,
        403,
        "access_denied",
        "owner token is not scoped to the requested source",
      );
    }

    // spec-core L1228: an owner-dependent failure recorded at /authorize is
    // explained to the authenticated owner here, and nowhere else.
    const ineligible = ineligibleResponse(c, session);
    if (ineligible) return ineligible;

    // Refuse any handle outside the token's ceiling before a review is built, so
    // an out-of-token instance is never resolved, counted, or shown.
    const instanceChoices = parseInstanceChoices(c);
    if (
      session &&
      namesOutsideCeiling(
        owner.instanceIds,
        namedInstanceHandles(session.request, instanceChoices),
      )
    ) {
      return errorResponse(c, 403, "access_denied", OUTSIDE_INSTANCE_CEILING);
    }

    const candidate = usesLockedRules(session?.request.type);
    const ownerChoices = parseOwnerChoices(c, candidate);
    if (ownerChoices === "invalid")
      return errorResponse(
        c,
        400,
        "invalid_owner_choices",
        "approval query values must be true",
      );
    if (candidate) {
      const invalid = validateCandidateOwnerChoices(
        session!.request,
        session!.snapshot,
        ownerChoices,
      );
      if (invalid)
        return errorResponse(c, 400, "invalid_owner_choices", invalid);
    }

    const result = fetchReview({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
      inventory: ceilingInventory(
        deps.inventoryFor(
          session?.subject_id ?? "",
          session?.snapshot.source_id ?? "",
        ),
        owner.instanceIds,
      ),
      instanceChoices,
      ownerChoices,
      ownerConditions: parseOwnerConditions(c),
      standingTerms:
        deps.standingTermsFor?.(session?.requester.client_id ?? "") ??
        undefined,
      store: deps.store,
      existingGrantInstanceIds: session
        ? Array.from(
            new Set(
              session.snapshot.streams.flatMap((stream) =>
                ceilingInventory(
                  deps.inventoryFor(
                    session.subject_id,
                    session.snapshot.source_id,
                  ),
                  owner.instanceIds,
                ).eligibleFor(stream.name),
              ),
            ),
          )
        : [],
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        approvalOAuthError(result.failure.code),
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
    if (lifecycle.hasRecoverySession(sessionId)) {
      const owner = resolveScopedOwnerToken(
        deps,
        bearer(c),
        lifecycle.recoverySessionSubject(sessionId),
      );
      if (!owner.ok) return scopedOwnerFailureResponse(c, owner.failure);
      let recoveryBody: { review_digest?: unknown };
      try {
        recoveryBody = await c.req.json();
      } catch {
        return errorResponse(c, 400, "invalid_request", "body must be JSON");
      }
      const approved = lifecycle.approveRecovery({
        sessionId,
        subjectId: owner.subjectId,
        reviewDigest:
          typeof recoveryBody?.review_digest === "string"
            ? recoveryBody.review_digest
            : "",
      });
      if (!approved.ok) {
        if (approved.code === "temporarily_unavailable")
          return unavailable(
            c,
            "the authorization history cannot be established as current",
          );
        return errorResponse(
          c,
          approved.code === "stale_review" ? 409 : 404,
          approved.code,
          approved.code === "stale_review"
            ? "the review digest does not match the recovery review"
            : "authorization session not found",
        );
      }
      return c.json({ redirect_uri: approved.redirect_uri }, 200, NO_STORE);
    }
    const session = deps.sessions.get(sessionId);
    const owner = resolveScopedOwnerToken(
      deps,
      bearer(c),
      session?.subject_id,
      session?.snapshot.source_id,
    );
    if (!owner.ok) {
      return scopedOwnerFailureResponse(c, owner.failure);
    }
    if (
      session &&
      !session.ineligible &&
      !scopedOwnerCoversSnapshot(
        deps,
        session.subject_id,
        session.snapshot,
        owner.instanceIds,
      )
    ) {
      return errorResponse(
        c,
        403,
        "access_denied",
        "owner token is not scoped to the requested source",
      );
    }

    const ineligible = ineligibleResponse(c, session);
    if (ineligible) return ineligible;

    let body: {
      review_digest?: string;
      explicit_ai_training_consent?: boolean;
      instance_choices?: Record<string, string[]>;
      /** v0.2 narrowing, in the same shape the review was fetched with. */
      owner_choices?: OwnerChoices;
      /** v0.2 conditions on purpose/retention, as reviewed. */
      owner_conditions?: OwnerConditions;
    };
    try {
      body = await c.req.json();
    } catch {
      return errorResponse(c, 400, "invalid_request", "body must be JSON");
    }

    // The request may have been prepared with a wider token. Its explicit
    // handles and the choices named now must all sit inside this token's ceiling.
    if (
      session &&
      namesOutsideCeiling(
        owner.instanceIds,
        namedInstanceHandles(session.request, body.instance_choices),
      )
    ) {
      return errorResponse(c, 403, "access_denied", OUTSIDE_INSTANCE_CEILING);
    }

    if (session && usesLockedRules(session.request.type)) {
      const invalid = validateCandidateOwnerChoices(
        session.request,
        session.snapshot,
        body.owner_choices,
      );
      if (invalid)
        return errorResponse(c, 400, "invalid_owner_choices", invalid);
    }

    const result = approveAuthorization({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
      reviewDigest: body.review_digest ?? "",
      inventory: ceilingInventory(
        deps.inventoryFor(
          session?.subject_id ?? "",
          session?.snapshot.source_id ?? "",
        ),
        owner.instanceIds,
      ),
      instanceChoices: body.instance_choices,
      ownerChoices: body.owner_choices,
      ownerConditions: body.owner_conditions,
      standingTerms:
        deps.standingTermsFor?.(session?.requester.client_id ?? "") ??
        undefined,
      explicitAiTrainingConsent: body.explicit_ai_training_consent,
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        approvalOAuthError(result.failure.code),
        result.failure.message,
      );
    }

    // Recheck what was actually issued against this token's ceiling before any
    // write. Resolution already used the narrowed inventory; this makes the
    // boundary hold even if a resolution path ever widened it.
    if (!streamsWithinCeiling(result.grant.streams, owner.instanceIds)) {
      return errorResponse(c, 403, "access_denied", OUTSIDE_INSTANCE_CEILING);
    }

    // AS item 44 / L1825: no new grant from a history that is not current.
    if (!deps.store.history.isCurrent()) {
      return unavailable(
        c,
        "the authorization history cannot be established as current",
      );
    }

    // Persist the grant and its authorization code as one durable unit
    // before marking this session complete. Only
    // once this succeeds does the session move to "approved" — if the write
    // fails, the session stays "pending" so the same reviewed approval can
    // be retried rather than being stranded as already-decided with nothing
    // durable behind it.
    const code = `pdpp_code_${crypto.randomUUID().replace(/-/g, "")}`;
    deps.store.insertGrantWithAuthCode({
      grant: result.grant,
      subjectId: result.grant.subject.id,
      reviewDigest: result.consentEvidence.review_digest,
      consentEvidence: result.consentEvidence,
      code,
      authCode: {
        grantId: result.grant.grant_id,
        clientId: result.grant.client.client_id,
        redirectUri: session!.redirect_uri,
        // Carried from the authorization request, so redemption can prove the
        // redeemer is the client that asked (RFC 7636 §4.4).
        codeChallenge: session!.code_challenge ?? null,
        codeChallengeMethod: session!.code_challenge_method ?? null,
        expiresAt: new Date(now().getTime() + 60_000).toISOString(),
      },
    });

    deps.sessions.setStatus(session!.session_id, "approved");

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
  app.post("/authorize/:session_id/deny", async (c) => {
    const sessionId = c.req.param("session_id");
    if (lifecycle.hasRecoverySession(sessionId)) {
      const owner = resolveScopedOwnerToken(
        deps,
        bearer(c),
        lifecycle.recoverySessionSubject(sessionId),
      );
      if (!owner.ok) return scopedOwnerFailureResponse(c, owner.failure);
      const denied = lifecycle.denyRecovery(sessionId, owner.subjectId);
      if (!denied.ok)
        return errorResponse(
          c,
          404,
          "session_not_found",
          "authorization session not found",
        );
      return c.json({ redirect_uri: denied.redirect_uri }, 200, NO_STORE);
    }
    const session = deps.sessions.get(sessionId);
    const owner = resolveScopedOwnerToken(
      deps,
      bearer(c),
      session?.subject_id,
      session?.snapshot.source_id,
    );
    if (!owner.ok) {
      return scopedOwnerFailureResponse(c, owner.failure);
    }
    if (
      session &&
      !session.ineligible &&
      !scopedOwnerCoversSnapshot(
        deps,
        session.subject_id,
        session.snapshot,
        owner.instanceIds,
      )
    ) {
      return errorResponse(
        c,
        403,
        "access_denied",
        "owner token is not scoped to the requested source",
      );
    }

    // The owner's optional note. Read defensively: a denial must succeed even
    // when the body is absent or malformed, because refusing is the safe
    // outcome and must never be blocked by the shape of an optional field.
    let reason: string | undefined;
    try {
      const body = (await c.req.json()) as { reason?: unknown } | null;
      if (typeof body?.reason === "string") reason = body.reason;
    } catch {
      reason = undefined;
    }

    const result = denyAuthorization({
      sessions: deps.sessions,
      tokens: deps.tokens,
      sessionId,
      ownerToken: bearer(c),
      ...(reason !== undefined && { reason }),
    });

    if (!result.ok) {
      return errorResponse(
        c,
        approvalStatus(result.failure.code),
        approvalOAuthError(result.failure.code),
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
      // L1806: a lifecycle recovery code redeems to a lifecycle-only token.
      if (lifecycle.isRecoveryCode(code)) {
        const recovered = lifecycle.redeemRecoveryCode({
          code,
          clientId,
          redirectUri,
          codeVerifier: asString(body.code_verifier) ?? undefined,
        });
        if (!recovered.ok) {
          if (recovered.code === "temporarily_unavailable")
            return unavailable(c, recovered.message);
          return errorResponse(c, 400, recovered.code, recovered.message);
        }
        return c.json(recovered.issued, 200, NO_STORE);
      }
      const result = deps.tokens.redeemAuthorizationCode({
        code,
        clientId,
        redirectUri,
        codeVerifier: asString(body.code_verifier) ?? undefined,
      });
      if (!result.ok) {
        if (result.failure.code === "temporarily_unavailable")
          return unavailable(c, result.failure.message);
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
      if (!result.ok && result.failure.code === "temporarily_unavailable") {
        return unavailable(c, result.failure.message);
      }
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
    if (!caller.subjectId) {
      return errorResponse(
        c,
        403,
        "access_denied",
        "introspection requires an owner token",
      );
    }

    const body = await c.req.parseBody();
    const token = asString(body.token);
    if (!token) {
      // RFC 7662: a missing token is a request error, not an inactive answer.
      return errorResponse(c, 400, "invalid_request", "token is required");
    }

    const target = deps.tokens.resolveToken(token);
    if (target.active) {
      if (target.grant) {
        const stored = deps.store.getGrant(target.grant.grant_id);
        if (
          !stored ||
          stored.subjectId !== caller.subjectId ||
          !grantContainedByOwnerScope(
            caller.subjectId,
            stored,
            caller.sourceId,
            caller.instanceIds,
          )
        ) {
          return c.json({ active: false }, 200, NO_STORE);
        }
      } else if (
        target.tokenKind !== "owner" ||
        target.subjectId !== caller.subjectId ||
        (caller.sourceId
          ? target.sourceId !== caller.sourceId
          : !caller.instanceIds ||
            !target.instanceIds ||
            !target.instanceIds.some((id) => caller.instanceIds?.includes(id)))
      ) {
        return c.json({ active: false }, 200, NO_STORE);
      }
    }

    return c.json(deps.tokens.introspect(token), 200, NO_STORE);
  });

  /**
   * RFC 7009 token revocation for clients (AS item 25, spec-core L2777-L2789).
   *
   * This is the advertised `revocation_endpoint`. PDPP clients are public
   * clients, so the client identifies itself with `client_id` (RFC 7009
   * §2.1); the token must have been issued to it. Revoking a refresh token
   * ends its grant; revoking an access token ends its grant only when no
   * refresh-token family covers it.
   *
   * `pdpp_disposition` (`keep` | `delete`) is accepted, any other value is
   * `invalid_request` (L2785), and a value is recorded — durably, in the
   * same transaction as the revocation — only when the request carries
   * current client authentication. A 200 is returned only after that commit
   * (L2787, AS item 44). `reported_at` is accepted only with `delete`.
   *
   * The owner path stays at `POST /revoke` (owner token + `grant_id`), which
   * is not advertised as `revocation_endpoint`.
   */
  app.post("/token/revoke", async (c) => {
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
    const token = asString(body.token);
    const clientId = asString(body.client_id);
    if (!token || !clientId) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "token and client_id are required",
      );
    }
    const rawDisposition = body.pdpp_disposition;
    if (
      rawDisposition !== undefined &&
      rawDisposition !== "keep" &&
      rawDisposition !== "delete"
    ) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "pdpp_disposition must be keep or delete",
      );
    }
    const reportedAt = body.reported_at;
    if (reportedAt !== undefined) {
      if (rawDisposition !== "delete") {
        return errorResponse(
          c,
          400,
          "invalid_request",
          "reported_at is accepted only with pdpp_disposition=delete",
        );
      }
      if (
        typeof reportedAt !== "string" ||
        !/^\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(\.\d+)?([zZ]|[+-]\d{2}:\d{2})$/.test(
          reportedAt,
        ) ||
        Number.isNaN(Date.parse(reportedAt)) ||
        // spec-core L1748: a reported time later than the request is invalid.
        Date.parse(reportedAt) > Date.now()
      ) {
        return errorResponse(
          c,
          400,
          "invalid_request",
          "reported_at must be an RFC 3339 date-time",
        );
      }
    }
    const hint = asString(body.token_type_hint) ?? undefined;
    let result: ReturnType<typeof deps.tokens.revokeClientToken>;
    try {
      result = deps.tokens.revokeClientToken({
        token,
        clientId,
        ...(hint && { tokenTypeHint: hint }),
        ...(rawDisposition !== undefined && {
          disposition: rawDisposition as "keep" | "delete",
        }),
        ...(typeof reportedAt === "string" && { reportedAt }),
        ...(bearer(c) !== undefined && { bearer: bearer(c) }),
      });
    } catch (err) {
      // spec-core L2787: 200 only once every ending and disposition is
      // durable; otherwise 503 with Retry-After. The transaction rolled back.
      deps.logger.error({ err }, "PDPP client token revocation not recorded");
      return c.json(
        {
          error: "temporarily_unavailable",
          error_description: "the revocation could not be recorded; retry",
        },
        503,
        { ...NO_STORE, "Retry-After": "5" },
      );
    }
    if (!result.ok) {
      if (result.code === "temporarily_unavailable")
        return unavailable(c, result.message);
      return errorResponse(c, 400, result.code, result.message);
    }
    deps.logger.info(
      {
        client_id: clientId,
        ended_grants: result.endedGrants,
        disposition_recorded: result.dispositionRecorded,
      },
      "PDPP client token revocation",
    );
    // RFC 7009 §2.2: an empty 200 body.
    return c.body(null, 200, NO_STORE);
  });

  /**
   * List the owner's PDPP grants, newest first, with each one's status.
   *
   * Sits at `/grants` rather than under `/owner` because `/owner/*` is the
   * wallet-proof-guarded path that mints owner tokens, while this route
   * authenticates the same way `/revoke` does — with the owner token that
   * exchange produced. It is the read half of the same owner grant-lifecycle
   * pair, so it belongs beside its writer, not beside the credential mint.
   *
   * The projection is exactly the review's `existing_grants` shape plus
   * `status` and `client_id`, so a surface that renders one can render the
   * other. What it deliberately omits is everything that is authority or
   * evidence rather than description: tokens, authorization codes, consent
   * evidence and review digests. A grant list is for showing an owner what
   * they have agreed to; none of those fields serve that, and each would turn
   * a read-only listing into a credential leak.
   *
   * `status` widens `grantStatus` by one value the store models as a separate
   * column: a `single_use` grant that has been redeemed reads `consumed`, not
   * `active`, because it can never issue another token.
   */
  app.get("/grants", (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;

    const clientFilter = c.req.query("client_id");
    const at = now();
    const grants = deps.store
      .listGrantsForSubject(caller.subjectId)
      .filter((stored) => !clientFilter || stored.clientId === clientFilter)
      .filter((stored) =>
        grantContainedByOwnerScope(
          caller.subjectId,
          stored,
          caller.sourceId,
          caller.instanceIds,
        ),
      )
      .map((stored) => ({
        grant_id: stored.grant.grant_id,
        client_id: stored.clientId,
        status: listedGrantStatus(deps.store, stored, at),
        issued_at: stored.grant.issued_at,
        ...(stored.grant.expires_at && { expires_at: stored.grant.expires_at }),
        access_mode: stored.grant.access_mode,
        purpose_code: stored.grant.purpose_code,
        streams: stored.grant.streams.map((s) => ({
          name: s.name,
          fields: s.fields,
        })),
        // AS items 42, 43, 46: read state, ending reason, disposition stage
        // and erasure stages. Additive; `status` above is unchanged.
        lifecycle: lifecycle.ownerView(stored, at),
      }));

    const pending = lifecycle.pendingOwnerActions(caller.subjectId);
    return c.json(
      {
        grants,
        // L1827-L1829: whether the history is current, and owner actions
        // recorded while it was not, shown as pending.
        history: {
          current: deps.store.history.isCurrent(),
          ...(pending.length > 0 && {
            pending_actions: pending.map((a) => ({
              action_id: a.action_id,
              recorded_at: a.recorded_at,
              kind: a.kind,
              action: a.action,
              grants: a.grant_ids.map((g) => ({
                grant_id: g,
                state: "pending",
                ...(a.dispositions[g] && { disposition: a.dispositions[g] }),
              })),
            })),
          }),
          ...((!deps.store.history.isCurrent() || pending.length > 0) && {
            statement: PENDING_HISTORY_STATEMENT,
          }),
        },
      },
      200,
      NO_STORE,
    );
  });

  /**
   * Revoke a grant. Owner-authenticated, and scoped to the owner's own grants
   * — a valid owner token is not authority over another subject's grant.
   *
   * AS item 41 / spec-core L1576: the request MUST carry `disposition`
   * (`keep` or `delete`); one without it is rejected with
   * `invalid_request` / `disposition_required` and no default is applied.
   * `action=narrowing` marks the revoke-and-reissue flow (L1529). Optional
   * `action_id` makes a retry idempotent. Form-encoded, as before.
   */
  app.post("/revoke", async (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;

    const body = await c.req.parseBody();
    const grantId = asString(body.grant_id);
    if (!grantId) {
      return errorResponse(c, 400, "invalid_request", "grant_id is required");
    }
    const disposition = asString(body.disposition);
    if (disposition !== "keep" && disposition !== "delete") {
      return c.json(
        {
          error: "invalid_request",
          error_code: "disposition_required",
          error_description:
            "an explicit disposition (keep or delete) is required for the grant",
          missing: [grantId],
        },
        400,
        NO_STORE,
      );
    }
    const actionParam = asString(body.action);
    if (
      actionParam &&
      actionParam !== "revoke" &&
      actionParam !== "narrowing"
    ) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "action must be revoke or narrowing",
      );
    }
    return applyOwnerEnding(c, caller, {
      action: (actionParam ?? "revoke") as OwnerEndingAction,
      grantIds: [grantId],
      dispositions: { [grantId]: disposition },
      actionId: asString(body.action_id) ?? `act_${crypto.randomUUID()}`,
      legacyGrantId: grantId,
    });
  });

  /**
   * The complete affected set of an owner ending, before its final step
   * (L1566, L1576, AS item 41): grants it will end and ended or consumed
   * grants whose disposition it will record, each with the keep and delete
   * statements and `preselected: null`.
   *
   *   ?action=revoke|narrowing&grant_id=<id>[&grant_id=...]
   *   ?action=disconnect_client&client_id=<id>
   */
  app.get("/owner/grants/affected", (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    const url = new URL(c.req.url);
    const action = url.searchParams.get("action") ?? "revoke";
    if (!["revoke", "narrowing", "disconnect_client"].includes(action)) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "action must be revoke, narrowing or disconnect_client",
      );
    }
    if (!deps.store.history.isCurrent()) {
      return unavailable(
        c,
        "the affected set cannot be listed from a history that is not current; name each grant and its disposition instead",
      );
    }
    const affected = lifecycle.affectedSet({
      subjectId: caller.subjectId,
      action: action as OwnerEndingAction,
      ...(url.searchParams.get("client_id") && {
        clientId: url.searchParams.get("client_id")!,
      }),
      grantIds: url.searchParams.getAll("grant_id"),
      inScope: ownerScope(caller),
    });
    if (!affected.ok) {
      return errorResponse(
        c,
        affected.message === "grant not found" ? 404 : 400,
        affected.message === "grant not found"
          ? "not_found"
          : "invalid_request",
        affected.message,
      );
    }
    return c.json(
      {
        action,
        grants: affected.grants,
        will_end: affected.grants
          .filter((g) => g.effect === "end")
          .map((g) => g.grant_id),
        will_record: affected.grants
          .filter((g) => g.effect === "record")
          .map((g) => g.grant_id),
      },
      200,
      NO_STORE,
    );
  });

  /**
   * Owner ending (AS item 41): JSON `{ action, client_id?, grant_ids?,
   * dispositions?: { <grant_id>: "keep" | "delete" }, disposition?, action_id? }`.
   * `disposition` applies one explicit choice to every grant in scope (L1566
   * "One choice MAY apply to all"); nothing is ever defaulted.
   */
  app.post("/owner/grants/end", async (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    const body = await readJsonObject(c);
    if (!body)
      return errorResponse(
        c,
        400,
        "invalid_request",
        "body must be a JSON object",
      );
    const action = body.action ?? "revoke";
    if (
      typeof action !== "string" ||
      !["revoke", "narrowing", "disconnect_client"].includes(action)
    ) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "action must be revoke, narrowing or disconnect_client",
      );
    }
    const grantIds = Array.isArray(body.grant_ids)
      ? body.grant_ids.filter((g): g is string => typeof g === "string")
      : [];
    const clientId =
      typeof body.client_id === "string" ? body.client_id : undefined;
    const dispositions = parseDispositions(body.dispositions);
    if (dispositions === null) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "dispositions maps grant ids to keep or delete",
      );
    }
    const all = body.disposition;
    if (all !== undefined && all !== "keep" && all !== "delete") {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "disposition must be keep or delete",
      );
    }
    if (all !== undefined) {
      const scope = deps.store.history.isCurrent()
        ? lifecycle.affectedSet({
            subjectId: caller.subjectId,
            action: action as OwnerEndingAction,
            ...(clientId && { clientId }),
            grantIds,
            inScope: ownerScope(caller),
          })
        : {
            ok: true as const,
            grants: grantIds.map((g) => ({
              grant_id: g,
              disposition_required: true,
            })),
          };
      if (scope.ok) {
        for (const g of scope.grants) {
          if (g.disposition_required && !dispositions[g.grant_id])
            dispositions[g.grant_id] = all;
        }
      }
    }
    return applyOwnerEnding(c, caller, {
      action: action as OwnerEndingAction,
      ...(clientId && { clientId }),
      grantIds,
      dispositions,
      actionId:
        typeof body.action_id === "string" && body.action_id
          ? body.action_id
          : `act_${crypto.randomUUID()}`,
    });
  });

  /**
   * Owner erasure request (L1586, AS item 46): JSON `{ grant_id, advance?,
   * action_id? }`. Immediate by default: ends an active grant, or records an
   * instruction for an ended grant whose held data may remain. `advance:
   * true` elects deletion at grant end without ending the grant.
   */
  app.post("/owner/grants/erasure", async (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    const body = await readJsonObject(c);
    if (!body || typeof body.grant_id !== "string" || !body.grant_id) {
      return errorResponse(c, 400, "invalid_request", "grant_id is required");
    }
    if (body.advance !== undefined && typeof body.advance !== "boolean") {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "advance must be a boolean",
      );
    }
    const result = lifecycle.requestErasureForOwner({
      subjectId: caller.subjectId,
      grantId: body.grant_id,
      advance: body.advance === true,
      actionId:
        typeof body.action_id === "string" && body.action_id
          ? body.action_id
          : `act_${crypto.randomUUID()}`,
      inScope: ownerScope(caller),
    });
    if (!result.ok) {
      return errorResponse(
        c,
        result.code === "not_found" ? 404 : 400,
        result.code,
        result.message,
      );
    }
    return ownerActionResponse(c, result.result, {
      ...(result.erasure && { erasure: result.erasure }),
    });
  });

  /**
   * AS decommission (L1574, AS item 46, case P9). GET lists every grant whose
   * held data may remain with its disposition stage (offered, recorded, sent,
   * receipt_reported) and a warning for each `delete` no client has
   * received. POST `{ dispositions?, disposition?, action_id? }` records an
   * explicit disposition for each grant still offered, then the confirmation.
   */
  app.get("/owner/decommission", (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    if (!deps.store.history.isCurrent()) {
      return unavailable(
        c,
        "the authorization history cannot be established as current",
      );
    }
    return c.json(
      lifecycle.decommissionView({
        subjectId: caller.subjectId,
        inScope: ownerScope(caller),
      }),
      200,
      NO_STORE,
    );
  });

  app.post("/owner/decommission/confirm", async (c) => {
    const caller = resolveWholeServerOwner(c);
    if (!caller.ok) return caller.response;
    if (!deps.store.history.isCurrent()) {
      return unavailable(
        c,
        "the authorization history cannot be established as current",
      );
    }
    const body = await readJsonObject(c);
    if (!body)
      return errorResponse(
        c,
        400,
        "invalid_request",
        "body must be a JSON object",
      );
    const dispositions = parseDispositions(body.dispositions);
    if (dispositions === null)
      return errorResponse(
        c,
        400,
        "invalid_request",
        "dispositions maps grant ids to keep or delete",
      );
    if (body.disposition !== undefined) {
      if (body.disposition !== "keep" && body.disposition !== "delete")
        return errorResponse(
          c,
          400,
          "invalid_request",
          "disposition must be keep or delete",
        );
      for (const g of lifecycle.decommissionView({
        subjectId: caller.subjectId,
        inScope: ownerScope(caller),
      }).grants) {
        if (g.stage === "offered" && !dispositions[g.grant_id])
          dispositions[g.grant_id] = body.disposition;
      }
    }
    const result = lifecycle.confirmDecommission({
      subjectId: caller.subjectId,
      dispositions,
      actionId:
        typeof body.action_id === "string" && body.action_id
          ? body.action_id
          : `act_${crypto.randomUUID()}`,
      inScope: ownerScope(caller),
    });
    if (!result.ok) {
      return c.json(
        {
          error: "invalid_request",
          error_code: result.code,
          error_description: result.message,
          ...(result.missing && { missing: result.missing }),
        },
        400,
        NO_STORE,
      );
    }
    if (!result.result.complete) {
      return c.json({ ...result.view, result: result.result }, 503, {
        ...NO_STORE,
        "Retry-After": "5",
      });
    }
    return c.json({ ...result.view, result: result.result }, 200, NO_STORE);
  });

  /**
   * Disable tokens for lifecycle use (L1716, case D3): JSON `{ client_id,
   * grant_ids }` disables every token issued to that client for those
   * grants; `token_sha256` names digests directly. Ends no grant and records
   * no disposition.
   */
  app.post("/owner/lifecycle/disable-tokens", async (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    if (!deps.store.history.isCurrent()) {
      return unavailable(
        c,
        "the authorization history cannot be established as current",
      );
    }
    const body = await readJsonObject(c);
    if (
      !body ||
      typeof body.client_id !== "string" ||
      !Array.isArray(body.grant_ids)
    ) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "client_id and grant_ids are required",
      );
    }
    const scope = ownerScope(caller);
    const grantIds = body.grant_ids.filter((g): g is string => {
      if (typeof g !== "string") return false;
      const stored = deps.store.getGrant(g);
      return !!stored && stored.subjectId === caller.subjectId && scope(stored);
    });
    // Only digests of tokens issued for grants inside the caller's scope.
    const inScopeDigests = new Set(
      deps.store.lifecycle.tokenDigestsFor(body.client_id, grantIds),
    );
    const digests = Array.isArray(body.token_sha256)
      ? body.token_sha256.filter(
          (d): d is string => typeof d === "string" && inScopeDigests.has(d),
        )
      : [];
    const disabled = lifecycle.disableForLifecycle({
      clientId: body.client_id,
      grantIds,
      tokenDigests: digests,
    });
    return c.json({ disabled }, 200, NO_STORE);
  });

  /** History currency, pending owner actions, and what re-establishing would end. */
  app.get("/owner/lifecycle/history", (c) => {
    const caller = resolveOwner(c);
    if (!caller.ok) return caller.response;
    const status = deps.store.history.current();
    return c.json(
      {
        current: status.current,
        ...(!status.current && {
          reason: status.reason,
          statement: PENDING_HISTORY_STATEMENT,
          reestablish_ends: lifecycle.reestablishAffected(),
        }),
        pending_actions: lifecycle.pendingOwnerActions(caller.subjectId),
      },
      200,
      NO_STORE,
    );
  });

  /**
   * Re-establish a history the mechanism found not current (L1823, L1827):
   * restores anchored erasure instructions, applies pending owner actions,
   * then ends every still-active grant with the owner's explicit
   * disposition. JSON `{ dispositions?, disposition?, action_id? }`.
   */
  app.post("/owner/lifecycle/reestablish", async (c) => {
    const caller = resolveWholeServerOwner(c);
    if (!caller.ok) return caller.response;
    const body = await readJsonObject(c);
    if (!body)
      return errorResponse(
        c,
        400,
        "invalid_request",
        "body must be a JSON object",
      );
    const dispositions = parseDispositions(body.dispositions);
    if (dispositions === null)
      return errorResponse(
        c,
        400,
        "invalid_request",
        "dispositions maps grant ids to keep or delete",
      );
    if (body.disposition !== undefined) {
      if (body.disposition !== "keep" && body.disposition !== "delete")
        return errorResponse(
          c,
          400,
          "invalid_request",
          "disposition must be keep or delete",
        );
      for (const g of lifecycle.reestablishAffected()) {
        if (!dispositions[g.grant_id])
          dispositions[g.grant_id] = body.disposition;
      }
    }
    try {
      const result = lifecycle.reestablishHistory({
        dispositions,
        actionId:
          typeof body.action_id === "string" && body.action_id
            ? body.action_id
            : `act_${crypto.randomUUID()}`,
      });
      if (!result.ok) {
        return c.json(
          {
            error: "invalid_request",
            error_code: result.code,
            error_description: result.message,
            missing: result.missing,
          },
          400,
          NO_STORE,
        );
      }
      deps.logger.warn(
        result,
        "PDPP authorization history re-established by the owner",
      );
      return c.json({ current: true, ...result }, 200, NO_STORE);
    } catch (err) {
      deps.logger.error({ err }, "PDPP history re-establishment failed");
      return unavailable(
        c,
        "the history could not be re-established; retry",
        5,
      );
    }
  });

  /**
   * The grant lifecycle operation (spec-core L1686-L1801, AS item 39):
   * `application/x-www-form-urlencoded` POST. Queries authenticate with any
   * token the AS issued to the client covering the grant; writes need
   * current client authentication. 200 with `{ grants }`; request-level
   * failures per RFC 6749 §5.2; 503 with Retry-After while the history is
   * not current; 429 past the per-grant query allowance.
   */
  app.post("/grant-lifecycle", async (c) => {
    const contentType = c.req.header("content-type") ?? "";
    if (!contentType.includes("application/x-www-form-urlencoded")) {
      return errorResponse(
        c,
        400,
        "invalid_request",
        "Content-Type must be application/x-www-form-urlencoded",
      );
    }
    const params = new Map<string, string[]>();
    for (const [k, v] of new URLSearchParams(await c.req.text())) {
      params.set(k, [...(params.get(k) ?? []), v]);
    }
    const result = lifecycle.handleLifecycleRequest(params);
    const headers: Record<string, string> = { ...NO_STORE };
    if (
      "retryAfterSeconds" in result &&
      result.retryAfterSeconds !== undefined
    ) {
      headers["Retry-After"] = String(result.retryAfterSeconds);
    }
    if (result.status === 401) {
      headers["WWW-Authenticate"] =
        result.body.error === "invalid_token"
          ? 'Bearer error="invalid_token"'
          : "Bearer";
    }
    return c.json(result.body, result.status, headers);
  });

  /**
   * The owner for a whole-server action. With the wallet-proof chain wired,
   * the verified signer (middleware above) and no scope ceiling; without it
   * (unit tests), the owner token as elsewhere.
   */
  function resolveWholeServerOwner(
    c: Context,
  ):
    | { ok: true; subjectId: string; sourceId?: string; instanceIds?: string[] }
    | { ok: false; response: ReturnType<typeof errorResponse> } {
    if (!deps.ownerAuth) return resolveOwner(c);
    const signer = (c.get("auth") as { signer?: string } | undefined)?.signer;
    const subjectId =
      deps.ownerSubjectId?.(c) ?? (signer ? signer.toLowerCase() : null);
    if (!subjectId) {
      return {
        ok: false,
        response: errorResponse(
          c,
          401,
          "unauthorized",
          "a verified owner proof is required",
        ),
      };
    }
    return { ok: true, subjectId };
  }

  function ownerScope(caller: {
    subjectId: string;
    sourceId?: string;
    instanceIds?: string[];
  }) {
    return (stored: StoredGrant) =>
      grantContainedByOwnerScope(
        caller.subjectId,
        stored,
        caller.sourceId,
        caller.instanceIds,
      );
  }

  /** 200 when every ending and disposition is durable; 202 while pending; 503 on a partial result (L1828). */
  function ownerActionResponse(
    c: Context,
    result: OwnerActionResult,
    extra: Record<string, unknown> = {},
  ) {
    if (result.complete) return c.json({ ...extra, result }, 200, NO_STORE);
    if (result.statement) {
      return c.json({ ...extra, result }, 202, NO_STORE);
    }
    return c.json({ ...extra, result }, 503, {
      ...NO_STORE,
      "Retry-After": "5",
    });
  }

  function applyOwnerEnding(
    c: Context,
    caller: { subjectId: string; sourceId?: string; instanceIds?: string[] },
    input: {
      action: OwnerEndingAction;
      clientId?: string;
      grantIds: string[];
      dispositions: Record<string, "keep" | "delete">;
      actionId: string;
      legacyGrantId?: string;
    },
  ) {
    const result = lifecycle.endGrantsForOwner({
      subjectId: caller.subjectId,
      action: input.action,
      ...(input.clientId && { clientId: input.clientId }),
      grantIds: input.grantIds,
      dispositions: input.dispositions,
      actionId: input.actionId,
      inScope: ownerScope(caller),
    });
    if (!result.ok) {
      if (result.code === "not_found")
        return errorResponse(c, 404, "not_found", "grant not found");
      return c.json(
        {
          error: "invalid_request",
          ...(result.code === "disposition_required" && {
            error_code: "disposition_required",
          }),
          error_description: result.message,
          ...(result.missing && { missing: result.missing }),
        },
        400,
        NO_STORE,
      );
    }
    deps.logger.info(
      {
        action: input.action,
        action_id: input.actionId,
        grants: result.result.grants,
      },
      "PDPP owner grant ending",
    );
    const legacy = input.legacyGrantId
      ? (() => {
          const stored = deps.store.getGrant(input.legacyGrantId);
          return {
            grant_id: input.legacyGrantId,
            // Back-compatible field: the grant is ended; `lifecycle` has the detail.
            status: !result.result.complete
              ? "pending"
              : stored &&
                  lifecycle.readStateOf(stored, now()).read_state === "expired"
                ? "expired"
                : "revoked",
            ...(stored && { lifecycle: lifecycle.ownerView(stored, now()) }),
          };
        })()
      : {};
    return ownerActionResponse(c, result.result, legacy);
  }

  /**
   * The single owner-token check the owner grant routes share.
   *
   * A client token is refused with the same 401 as no token at all: from the
   * caller's side, holding the wrong kind of credential and holding none are
   * the same answer, and distinguishing them would tell a client token holder
   * that owner scope exists to be reached for.
   */
  function resolveOwner(c: Context):
    | {
        ok: true;
        subjectId: string;
        sourceId?: string;
        instanceIds?: string[];
      }
    | { ok: false; response: ReturnType<typeof errorResponse> } {
    const ownerToken = bearer(c);
    if (!ownerToken) {
      return {
        ok: false,
        response: errorResponse(
          c,
          401,
          "unauthorized",
          "an owner token is required",
        ),
      };
    }
    const caller = deps.tokens.resolveToken(ownerToken);
    if (!caller.active || caller.tokenKind !== "owner" || !caller.subjectId) {
      return {
        ok: false,
        response: errorResponse(
          c,
          401,
          "unauthorized",
          "an active owner token is required",
        ),
      };
    }
    return {
      ok: true,
      subjectId: caller.subjectId,
      ...(caller.sourceId && { sourceId: caller.sourceId }),
      ...(caller.instanceIds && { instanceIds: caller.instanceIds }),
    };
  }

  return app;
}

/**
 * The owner-only refusal for a session whose owner-dependent checks failed at
 * `/authorize` (spec-core L1228). Called after the owner token has been
 * matched to the session's subject. A decided or expired session falls
 * through to the ordinary handling.
 */
function ineligibleResponse(
  c: Context,
  session: {
    ineligible?: { message: string };
    status: string;
    expires_at: string;
  } | null,
) {
  if (
    !session?.ineligible ||
    session.status !== "pending" ||
    Date.parse(session.expires_at) <= Date.now()
  )
    return undefined;
  return errorResponse(c, 403, "access_denied", session.ineligible.message);
}

/**
 * The lifecycle value an owner should see for one grant.
 *
 * `grantStatus` answers active/expired/revoked. A redeemed `single_use` grant
 * is none of those in the store's terms — it has not expired and nobody
 * revoked it — yet it can never issue another token, so reporting it as
 * "active" would tell the owner they still have live access they do not have.
 */
function listedGrantStatus(
  store: PdppAuthStore,
  stored: StoredGrant,
  now: Date,
): GrantStatus | "consumed" | "requires_fresh_consent" {
  // Pre-lock grants no longer authorize anything (AS item 21); the owner sees
  // that they must approve again rather than a live grant.
  if (!isSupportedPersistedGrant(stored.grant)) return "requires_fresh_consent";
  const status = store.grantStatus(stored, now);
  if (
    status === "active" &&
    stored.grant.access_mode === "single_use" &&
    stored.consumedAt
  ) {
    return "consumed";
  }
  return status;
}

/**
 * The wire error for one Core approval-failure code.
 *
 * Core keeps `selection_refused` distinct so the two refusal shapes can carry
 * different statuses and different UI handling, but PR #1 names
 * `access_denied` as the OAuth error a client sees for a refused selection.
 * This is the one place those two vocabularies meet, so a client reads
 * standard OAuth while Core keeps its precision.
 */
function approvalOAuthError(code: string): string {
  if (code === "selection_refused") return "access_denied";
  // v0.2: an unsupported recipient term is reported as a structured
  // authorization failure. `invalid_authorization_details` is the RFC 9396
  // code for authorization details the AS will not honour, which is what an
  // uncovered term makes them.
  if (code === "recipient_terms_unsupported") {
    return "invalid_authorization_details";
  }
  return code;
}

function approvalStatus(code: string): 400 | 401 | 403 | 404 | 409 {
  switch (code) {
    case "unauthorized":
      return 401;
    case "session_not_found":
      return 404;
    case "stale_review":
      return 409;
    case "recipient_terms_unsupported":
      // 409: the request and the owner's terms conflict, and neither side can
      // fix it alone -- the recipient has to accept the term. Not 403, which
      // would read as "the owner said no".
      return 409;
    case "selection_refused":
      // A refusal, not a malformed request: the client asked for something
      // well-formed and the owner's decision cannot satisfy it. 403 rather
      // than 400 so a consent UI can tell "fix your request" from "this
      // combination cannot be approved". `access_denied` keeps its existing
      // 400 for an already-decided session.
      return 403;
    default:
      return 400;
  }
}

async function readJsonObject(
  c: Context,
): Promise<Record<string, unknown> | null> {
  try {
    const body = (await c.req.json()) as unknown;
    return body && typeof body === "object" && !Array.isArray(body)
      ? (body as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** `{ <grant_id>: "keep" | "delete" }`, or null when malformed. Absent is `{}`. */
function parseDispositions(
  value: unknown,
): Record<string, "keep" | "delete"> | null {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const out: Record<string, "keep" | "delete"> = Object.create(null);
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (v !== "keep" && v !== "delete") return null;
    out[k] = v;
  }
  return out;
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
  const url = new URL(c.req.url);
  const choices: Record<string, string[]> = Object.create(null);
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "instance",
  )) {
    const nonemptyValues = values.filter((value) => value.length > 0);
    if (nonemptyValues.length > 0) choices[name] = nonemptyValues;
  }
  return Object.keys(choices).length > 0 ? choices : undefined;
}

/**
 * Read the owner's v0.2 narrowing from the review URL, so a re-fetch shows the
 * current proposal without the UI having to hold server state — the same
 * property `instance[...]` already has.
 *
 *   decline[<stream>]            — remove an optional stream (value ignored)
 *   field[<stream>]=<name>       — repeated; the narrowed field list
 *   since[<stream>]=<instant>    — narrowed window lower bound
 *   until[<stream>]=<instant>    — narrowed window upper bound
 *
 * A repeated `field[...]` with no values cannot be expressed in a query
 * string, which is why "share nothing from this stream" is `decline[...]`
 * rather than an empty field list. The two are different decisions and the
 * wire keeps them different: declining an optional stream succeeds, while
 * emptying a stream's fields is a refusal.
 */
/**
 * Read the owner's v0.2 conditions from the review URL.
 *
 *   retention_max_duration / retention_on_expiry — proposed retention term
 *   condition_purpose_code                       — proposed purpose code
 *
 * Both retention members are required together: a duration with no expiry
 * action, or the reverse, is half a term, and half a term cannot be matched
 * against what the recipient accepted.
 */
function parseOwnerConditions(c: Context): OwnerConditions | undefined {
  const url = new URL(c.req.url);
  const maxDuration = url.searchParams.get("retention_max_duration");
  const onExpiry = url.searchParams.get("retention_on_expiry");
  const purposeCode = url.searchParams.get("condition_purpose_code");

  const conditions: OwnerConditions = {
    ...(maxDuration &&
      (onExpiry === "delete" || onExpiry === "anonymize") && {
        retention: { max_duration: maxDuration, on_expiry: onExpiry },
      }),
    ...(purposeCode && { purpose_code: purposeCode }),
  };
  return Object.keys(conditions).length > 0 ? conditions : undefined;
}

function parseOwnerChoices(
  c: Context,
  strict = false,
): OwnerChoices | undefined | "invalid" {
  const declined: string[] = [];
  const approved: string[] = [];
  const url = new URL(c.req.url);
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "decline",
  )) {
    declined.push(...values.map(() => name));
  }
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "approve",
  )) {
    if (strict && values.some((value) => value !== "true")) return "invalid";
    approved.push(
      ...values.filter((value) => value === "true").map(() => name),
    );
  }

  const fields: Record<string, string[]> = Object.create(null);
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "field",
  )) {
    const nonemptyValues = values.filter((value) => value.length > 0);
    if (nonemptyValues.length > 0) fields[name] = nonemptyValues;
  }

  const windows: Record<string, { since?: string; until?: string }> =
    Object.create(null);
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "since",
  )) {
    const value = values.filter((entry) => entry.length > 0).at(-1);
    if (value !== undefined) (windows[name] ??= {}).since = value;
  }
  for (const [name, values] of readNamedQueryValues(
    url.searchParams,
    "until",
  )) {
    const value = values.filter((entry) => entry.length > 0).at(-1);
    if (value !== undefined) (windows[name] ??= {}).until = value;
  }

  const choices: OwnerChoices = {
    ...(declined.length > 0 && { declined_streams: declined }),
    ...(approved.length > 0 && { approved_streams: approved }),
    ...(Object.keys(fields).length > 0 && { fields }),
    ...(Object.keys(windows).length > 0 && { time_ranges: windows }),
  };
  return Object.keys(choices).length > 0 ? choices : undefined;
}
