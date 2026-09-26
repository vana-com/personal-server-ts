/**
 * PDPP grant-bound token issuance, introspection, and revocation (§8, §9 AS
 * items 8–10, 18–20; delivery scope §2).
 *
 * This module is the single token-validation authority. The RS resolves every
 * request through `resolveToken` and enforces only from the result — §8 is
 * explicit that the separated RS must not make a second AS lookup while
 * handling a request, and that a co-located RS may use a local equivalent.
 * `resolveToken` is that local equivalent, and `introspect` is the same
 * decision rendered onto the RFC 7662 wire shape. They share one code path so
 * the two deployments cannot drift apart.
 *
 * Revocation is immediate here by construction: resolution reads current store
 * state on every call rather than trusting a cached decision, so a revoked
 * grant reports `active: false` on the very next call. The 60-second bound in
 * §8 is the RS's positive-result cache, not slack in the AS.
 */

import { verifyCodeVerifier } from "./pkce.js";
import {
  newOpaqueToken,
  type PdppAuthStore,
  type StoredGrant,
} from "./store.js";
import {
  isV02Grant,
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type AccessMode,
  type Grant,
  type InactiveReason,
  type PdppAuthorizationDetail,
  type PdppAuthorizationEntry,
  type PdppIntrospectionResponse,
  type PdppTokenContext,
} from "./types.js";

/** Default client access-token lifetime. Short: the refresh path renews it. */
export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 60 * 60;

/** How long an authorization code stays redeemable. RFC 6749 §4.1.2 suggests <=10 min. */
export const AUTHORIZATION_CODE_TTL_SECONDS = 60;

export interface TokenIssuanceResult {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  /** Present only for continuous grants (§9 AS item 20). */
  refresh_token?: string;
  /** Echoed so a client can bind its own state to the grant. */
  grant_id: string;
  /**
   * The approved RFC 9396 detail, as granted. RFC 9396 §7 requires the token
   * response to return `authorization_details` as granted by the resource
   * owner and assigned to the access token — the same projection introspection
   * carries.
   *
   * One element per covered grant, each in its own revision's shape: a v0.1
   * grant yields the v0.1 projection, a v0.2 grant yields `{ type, grant }`
   * with the complete grant. v0.2 forbids a lossy summary, and the v0.1
   * projection is one, so the two cannot share a shape.
   */
  authorization_details: PdppAuthorizationEntry[];
}

export type TokenFailureCode = "invalid_grant" | "invalid_request";

export interface TokenFailure {
  code: TokenFailureCode;
  message: string;
}

export type TokenResult =
  | { ok: true; issued: TokenIssuanceResult }
  | { ok: false; failure: TokenFailure };

/**
 * Whether a grant may carry a refresh token.
 *
 * §9 AS item 20: refresh tokens are issued only for `continuous` grants, or
 * for a grant package only when *every* child grant is continuous. A
 * single-use grant with a refresh token would be a contradiction — the grant
 * is consumed at first issuance, so there is nothing left to refresh into.
 */
export function mayIssueRefreshToken(accessModes: AccessMode[]): boolean {
  return accessModes.length > 0 && accessModes.every((m) => m === "continuous");
}

function grantInactiveReason(
  store: PdppAuthStore,
  stored: StoredGrant,
  now: Date,
): InactiveReason | null {
  const status = store.grantStatus(stored, now);
  if (status === "revoked") return "grant_revoked";
  if (status === "expired") return "grant_expired";
  return null;
}

export interface PdppTokenServiceOptions {
  accessTokenTtlSeconds?: number;
}

export class PdppTokenService {
  private readonly accessTtl: number;

  constructor(
    private readonly store: PdppAuthStore,
    options: PdppTokenServiceOptions = {},
  ) {
    this.accessTtl =
      options.accessTokenTtlSeconds ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
  }

  /**
   * Issue the first client token for a grant, redeeming an authorization code.
   *
   * The code is consumed atomically before anything else happens (§9 AS item
   * 19) and a single-use grant is consumed atomically with the token insert
   * (§9 AS item 10). Both preconditions live in SQL WHERE clauses, so a
   * concurrent duplicate redemption loses the race rather than double-issuing.
   */
  redeemAuthorizationCode(input: {
    code: string;
    clientId: string;
    redirectUri: string;
    /** RFC 7636 verifier. Required when the code was issued with a challenge. */
    codeVerifier?: string;
    now?: Date;
  }): TokenResult {
    const now = input.now ?? new Date();

    const record = this.store.consumeAuthCode(input.code, now);
    if (!record) {
      // Unknown, expired, or already redeemed — deliberately one answer, so a
      // replay cannot be distinguished from a bad code.
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message:
            "authorization code is invalid, expired, or already redeemed",
        },
      };
    }

    // RFC 6749 §4.1.3: the client and redirect_uri must match the ones the
    // code was issued to. The code is already burned at this point, which is
    // correct — a mismatched redemption attempt must not leave it redeemable.
    if (record.clientId !== input.clientId) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message: "authorization code was not issued to this client",
        },
      };
    }
    if (record.redirectUri !== input.redirectUri) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message: "redirect_uri does not match the authorization request",
        },
      };
    }

    // RFC 7636 §4.6. Checked after the code is burned, like the client and
    // redirect checks above: an attacker who intercepted the code must not be
    // able to probe verifiers against a code that stays alive between guesses.
    // One wrong verifier costs them the code.
    const pkceFailure = verifyCodeVerifier(
      input.codeVerifier,
      record.codeChallenge,
      record.codeChallengeMethod,
    );
    if (pkceFailure) {
      return {
        ok: false,
        failure: { code: "invalid_grant", message: pkceFailure.message },
      };
    }

    const stored = this.store.getGrant(record.grantId);
    if (!stored) {
      return {
        ok: false,
        failure: { code: "invalid_grant", message: "grant not found" },
      };
    }

    const inactive = grantInactiveReason(this.store, stored, now);
    if (inactive) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message: `grant is ${inactive === "grant_revoked" ? "revoked" : "expired"}`,
        },
      };
    }

    return this.mintForGrant(stored, now);
  }

  /**
   * Rotate a refresh token within its family.
   *
   * Reuse of a superseded token revokes the family and every family-linked
   * access token inside `rotateRefreshToken`, then this returns
   * `invalid_grant`, which is what §9 AS item 20 requires: reject the reuse
   * and require fresh authorization.
   */
  refresh(input: { refreshToken: string; now?: Date }): TokenResult {
    const now = input.now ?? new Date();
    const rotation = this.store.rotateRefreshToken(input.refreshToken, now);

    if (!rotation.ok) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message:
            rotation.reason === "reuse_detected"
              ? "refresh token reuse detected; the token family has been revoked and fresh authorization is required"
              : "refresh token is unknown or its family is revoked",
        },
      };
    }

    const stored = this.store.getGrant(rotation.grantId);
    if (!stored) {
      return {
        ok: false,
        failure: { code: "invalid_grant", message: "grant not found" },
      };
    }

    const inactive = grantInactiveReason(this.store, stored, now);
    if (inactive) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message: `grant is ${inactive === "grant_revoked" ? "revoked" : "expired"}`,
        },
      };
    }

    return this.mintForGrant(stored, now, rotation.familyId);
  }

  /**
   * Mint an access token (and, for continuous grants, a refresh token) bound
   * to a grant.
   *
   * `existingFamilyId` carries a rotation into the same family so reuse
   * detection keeps working across the whole chain; a first issuance creates
   * the family.
   */
  private mintForGrant(
    stored: StoredGrant,
    now: Date,
    existingFamilyId?: string,
  ): TokenResult {
    const { grant } = stored;
    const continuous = mayIssueRefreshToken([grant.access_mode]);

    let familyId: string | null = existingFamilyId ?? null;
    if (continuous && familyId === null) {
      familyId = this.store.createRefreshFamily(grant.grant_id);
    }

    const accessToken = newOpaqueToken("pdpp_at");
    // A token must never outlive the grant it is bound to. Clamping here means
    // the RS's `min(token_exp, 60s)` cache bound can never extend access past
    // grant expiry either.
    const ttlExpiry = new Date(now.getTime() + this.accessTtl * 1000);
    const grantExpiry = grant.expires_at ? new Date(grant.expires_at) : null;
    const effectiveExpiry =
      grantExpiry && grantExpiry < ttlExpiry ? grantExpiry : ttlExpiry;

    const issued = this.store.issueAccessToken({
      token: accessToken,
      grantId: grant.grant_id,
      subjectId: stored.subjectId,
      clientId: grant.client.client_id,
      tokenKind: "client",
      familyId,
      expiresAt: effectiveExpiry.toISOString(),
      // A single-use grant is consumed exactly at first client-token issuance.
      // A rotation is never a first issuance, so it never re-consumes.
      consumeSingleUse:
        grant.access_mode === "single_use" && existingFamilyId === undefined,
      now,
    });

    if (!issued) {
      return {
        ok: false,
        failure: {
          code: "invalid_grant",
          message:
            "single_use grant has already been consumed; no further access tokens may be issued against it",
        },
      };
    }

    const expiresIn = Math.max(
      1,
      Math.floor((effectiveExpiry.getTime() - now.getTime()) / 1000),
    );

    let refreshToken: string | undefined;
    if (continuous && familyId) {
      refreshToken = newOpaqueToken("pdpp_rt");
      this.store.insertRefreshToken(refreshToken, familyId, now);
    }

    return {
      ok: true,
      issued: {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: expiresIn,
        ...(refreshToken && { refresh_token: refreshToken }),
        grant_id: grant.grant_id,
        authorization_details: [toAuthorizationEntry(grant)],
      },
    };
  }

  /**
   * The single shared token-validation path (§8 "Grant enforcement").
   *
   * Reads live store state every call. That is what makes revocation immediate
   * in introspection (§9 AS item 8) — there is no AS-side cache to invalidate.
   */
  resolveToken(accessToken: string, now: Date = new Date()): PdppTokenContext {
    const record = this.store.getAccessToken(accessToken);
    if (!record) {
      return { active: false, inactiveReason: "unknown" };
    }

    // Grant state is checked BEFORE the token's own revocation flag, because
    // revoking a grant also marks its linked tokens revoked. Checking the
    // token first would report `revoked` for what is really a grant
    // revocation, and the RS keys 403 `grant_revoked` off this exact reason
    // (§2 revocation propagation) — it would return the wrong error.
    if (record.tokenKind === "client" && record.grantId) {
      const stored = this.store.getGrant(record.grantId);
      if (!stored) {
        return { active: false, inactiveReason: "unknown" };
      }
      const grantInactive = grantInactiveReason(this.store, stored, now);
      if (grantInactive) {
        return { active: false, inactiveReason: grantInactive };
      }
    }

    if (record.revokedAt) {
      return { active: false, inactiveReason: "revoked" };
    }

    if (record.expiresAt && Date.parse(record.expiresAt) <= now.getTime()) {
      return { active: false, inactiveReason: "expired" };
    }

    // A token minted into a family that was later burned by reuse detection is
    // dead even if its own row was not individually marked — belt and braces
    // against a token inserted concurrently with the family revocation.
    if (record.familyId && this.store.isFamilyRevoked(record.familyId)) {
      return { active: false, inactiveReason: "revoked" };
    }

    if (record.tokenKind === "owner") {
      // An owner token carries no grant. The RS derives subject scope from
      // `subjectId` and must not synthesize a grant for it (§8).
      return {
        active: true,
        tokenKind: "owner",
        subjectId: record.subjectId,
        ...(record.ownerInstanceIds && {
          instanceIds: record.ownerInstanceIds,
        }),
        ...(record.expiresAt && { expiresAt: record.expiresAt }),
      };
    }

    if (!record.grantId) {
      // A client token with no grant link is unusable by definition.
      return { active: false, inactiveReason: "unknown" };
    }

    const stored = this.store.getGrant(record.grantId);
    if (!stored) {
      return { active: false, inactiveReason: "unknown" };
    }

    const inactive = grantInactiveReason(this.store, stored, now);
    if (inactive) {
      // grant_revoked is the reason the RS turns into 403 grant_revoked.
      return { active: false, inactiveReason: inactive };
    }

    return {
      active: true,
      tokenKind: "client",
      subjectId: stored.subjectId,
      grant: stored.grant,
      clientId: stored.grant.client.client_id,
      ...(record.expiresAt && { expiresAt: record.expiresAt }),
    };
  }

  /**
   * RFC 7662 introspection.
   *
   * An inactive token yields exactly `{ active: false }`. RFC 7662 §2.2 is
   * clear that the response must not distinguish revoked from expired from
   * never-issued — the reason stays internal (`resolveToken`) for the
   * co-located RS, which needs it to pick 403 `grant_revoked`.
   */
  introspect(
    accessToken: string,
    now: Date = new Date(),
  ): PdppIntrospectionResponse {
    const context = this.resolveToken(accessToken, now);
    if (!context.active) {
      return { active: false };
    }

    const base: PdppIntrospectionResponse = {
      active: true,
      pdpp_token_kind: context.tokenKind,
      subject_id: context.subjectId,
      ...(context.instanceIds && { instance_ids: context.instanceIds }),
      ...(context.expiresAt && {
        exp: Math.floor(Date.parse(context.expiresAt) / 1000),
      }),
    };

    if (context.tokenKind === "owner" || !context.grant) {
      return base;
    }

    return {
      ...base,
      grant_id: context.grant.grant_id,
      client_id: context.grant.client.client_id,
      // The complete resolved enforcement context, in one response (§9 item 18).
      authorization_details: [toAuthorizationEntry(context.grant)],
    };
  }

  /** Revoke a grant and every linked token family. Immediate (§2, §9 item 8). */
  revokeGrant(grantId: string, now: Date = new Date()): boolean {
    return this.store.revokeGrant(grantId, now);
  }

  /**
   * Issue an owner token for a subject.
   *
   * An owner token carries no grant (§8 "Authentication"): it scopes to a
   * single subject's data store, and the RS derives subject scope from it
   * rather than synthesizing a grant. It is also what authenticates a consent
   * decision — see `approval.ts` for why the AS requires this rather than
   * trusting the consent UI's affiliation.
   *
   * How the owner *obtains* this token is out of scope for Core; this build
   * mints it from the already-authenticated owner session paths.
   */
  issueOwnerToken(input: {
    subjectId: string;
    instanceIds?: string[];
    ttlSeconds?: number;
    now?: Date;
  }): { access_token: string; token_type: "Bearer"; expires_in: number } {
    const now = input.now ?? new Date();
    const ttl = input.ttlSeconds ?? this.accessTtl;
    const token = newOpaqueToken("pdpp_ot");
    const expiresAt = new Date(now.getTime() + ttl * 1000);

    this.store.issueAccessToken({
      token,
      grantId: null,
      subjectId: input.subjectId,
      clientId: null,
      tokenKind: "owner",
      ownerInstanceIds: input.instanceIds,
      expiresAt: expiresAt.toISOString(),
      consumeSingleUse: false,
      now,
    });

    return { access_token: token, token_type: "Bearer", expires_in: ttl };
  }

  /** Revoke a single access token without touching its grant. */
  revokeAccessToken(token: string, now: Date = new Date()): boolean {
    return this.store.revokeAccessToken(token, now);
  }
}

/**
 * Project a grant onto the RFC 9396 detail the introspection response carries.
 *
 * Note what is absent: `client_claims` and `retention` are not enforcement
 * fields. §6 keeps claims outside introspection rights and RS enforcement
 * entirely; retention is a policy commitment PDPP does not technically
 * enforce, so including it would invite an RS to act on it.
 */
/**
 * Project a grant onto the `authorization_details` element for *its own*
 * revision.
 *
 * v0.1 gets the narrow enforcement projection below, unchanged. v0.2 gets
 * `{ type, grant }` carrying the complete immutable grant, because v0.2 makes
 * the result the client's source of truth and forbids substituting the
 * original selection request or a lossy summary — and the v0.1 projection is
 * precisely a lossy summary. It drops `retention`, `expires_at`, the resolved
 * client identity, and the requested-vs-approved record, so a v0.2 client
 * receiving it could not tell a narrowed grant from an unnarrowed one.
 *
 * Branching on the grant rather than on a caller-supplied flag is what keeps
 * the two revisions from drifting: the same function serves the token response
 * and introspection, so a client and an authenticated RS cannot be handed
 * different facts about one grant.
 */
export function toAuthorizationEntry(grant: Grant): PdppAuthorizationEntry {
  if (isV02Grant(grant)) {
    return { type: PDPP_DATA_ACCESS_TYPE_V02, grant };
  }
  return toAuthorizationDetail(grant);
}

export function toAuthorizationDetail(grant: Grant): PdppAuthorizationDetail {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: grant.source,
    purpose_code: grant.purpose_code,
    ...(grant.purpose_description && {
      purpose_description: grant.purpose_description,
    }),
    access_mode: grant.access_mode,
    streams: grant.streams,
  };
}
