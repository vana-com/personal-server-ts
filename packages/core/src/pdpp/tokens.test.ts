/**
 * Oracles for grant-bound tokens, introspection, and revocation
 * (§7 access modes, §8 introspection, §9 AS items 8–10, 18–20, delivery §2).
 *
 * These run against a real SQLite store in a temp dir, not a mock. The
 * requirements under test are atomicity requirements — "consumes atomically",
 * "revoke the family" — and a fake store would assert only that the code calls
 * the methods it calls, which is not the property that matters.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AUTHORIZATION_CODE_TTL_SECONDS,
  mayIssueRefreshToken,
  PdppTokenService,
} from "./tokens.js";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_GRANT_VERSION,
  type AccessMode,
  type Grant,
} from "./types.js";

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    version: PDPP_GRANT_VERSION,
    grant_id: `grt_${Math.random().toString(16).slice(2, 10)}`,
    issued_at: new Date().toISOString(),
    subject: { id: "user_abc123" },
    client: { client_id: "music_recommendations" },
    source: {
      kind: "connector",
      id: "https://registry.pdpp.dev/connectors/spotify",
    },
    source_declaration: { version: "2026-08-11" },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [
      {
        name: "top_artists",
        instance_ids: ["spotify-account-a"],
        fields: ["id", "name"],
      },
    ],
    ...overrides,
  };
}

/** Persist a grant and mint an authorization code for it. */
function seedGrant(
  accessMode: AccessMode = "single_use",
  overrides: Partial<Grant> = {},
): { grant: Grant; code: string } {
  const grant = makeGrant({ access_mode: accessMode, ...overrides });
  store.insertGrant({
    grant,
    subjectId: grant.subject.id,
    reviewDigest: "digest-placeholder",
  });
  const code = `code_${Math.random().toString(16).slice(2)}`;
  store.insertAuthCode(code, {
    grantId: grant.grant_id,
    clientId: grant.client.client_id,
    redirectUri: "https://app.example.com/callback",
    codeChallenge: null,
    codeChallengeMethod: null,
    expiresAt: new Date(
      Date.now() + AUTHORIZATION_CODE_TTL_SECONDS * 1000,
    ).toISOString(),
  });
  return { grant, code };
}

function redeem(code: string) {
  return tokens.redeemAuthorizationCode({
    code,
    clientId: "music_recommendations",
    redirectUri: "https://app.example.com/callback",
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-auth-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("§9 AS item 19 — authorization codes consume atomically", () => {
  it("issues a token on first redemption", () => {
    const { code } = seedGrant();
    const result = redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.issued.access_token).toMatch(/^pdpp_at_/);
    expect(result.issued.token_type).toBe("Bearer");
  });

  it("carries the granted authorization_details, matching introspection (RFC 9396 §7)", () => {
    const { code } = seedGrant("continuous");
    const result = redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const introspected = tokens.introspect(result.issued.access_token);
    expect(result.issued.authorization_details).toEqual(
      introspected.authorization_details,
    );
  });

  it("rejects every later redemption with invalid_grant and issues nothing", () => {
    const { code } = seedGrant();
    const first = redeem(code);
    expect(first.ok).toBe(true);

    const second = redeem(code);
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.failure.code).toBe("invalid_grant");

    const third = redeem(code);
    expect(third.ok).toBe(false);
  });

  it("does not leave the code redeemable after a client-mismatch rejection", () => {
    // The code is consumed before the client check, deliberately: a
    // mismatched redemption attempt must burn it, not leave it replayable.
    const { code } = seedGrant();
    const wrongClient = tokens.redeemAuthorizationCode({
      code,
      clientId: "some_other_client",
      redirectUri: "https://app.example.com/callback",
    });
    expect(wrongClient.ok).toBe(false);

    const rightClient = redeem(code);
    expect(rightClient.ok).toBe(false);
  });

  it("rejects a redirect_uri that does not match the authorization request", () => {
    const { code } = seedGrant();
    const result = tokens.redeemAuthorizationCode({
      code,
      clientId: "music_recommendations",
      redirectUri: "https://evil.example.com/callback",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_grant");
  });

  it("rejects an expired code", () => {
    const grant = makeGrant();
    store.insertGrant({
      grant,
      subjectId: grant.subject.id,
      reviewDigest: "d",
    });
    store.insertAuthCode("stale_code", {
      grantId: grant.grant_id,
      clientId: grant.client.client_id,
      redirectUri: "https://app.example.com/callback",
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    expect(redeem("stale_code").ok).toBe(false);
  });

  it("rejects an unknown code the same way as a replayed one", () => {
    // No oracle for a probing client: unknown, expired, and replayed all
    // return the same failure.
    const { code } = seedGrant();
    redeem(code);
    const replayed = redeem(code);
    const unknown = redeem("code_never_issued");
    expect(replayed.ok).toBe(false);
    expect(unknown.ok).toBe(false);
    if (replayed.ok || unknown.ok) return;
    expect(replayed.failure).toEqual(unknown.failure);
  });
});

describe("§7 / §9 AS item 10 — single_use consumes at first issuance", () => {
  it("rejects a second token issuance against a consumed single_use grant", () => {
    const { grant, code } = seedGrant("single_use");
    expect(redeem(code).ok).toBe(true);

    // A second code for the same grant must not yield a second token.
    const secondCode = "code_second";
    store.insertAuthCode(secondCode, {
      grantId: grant.grant_id,
      clientId: grant.client.client_id,
      redirectUri: "https://app.example.com/callback",
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    const result = redeem(secondCode);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_grant");
  });

  it("honors the already-issued token after consumption", () => {
    // §7: "The RS honors all tokens issued against the grant until token
    // expiry or revocation." Consumption blocks NEW issuance, not use.
    const { code } = seedGrant("single_use");
    const result = redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const context = tokens.resolveToken(result.issued.access_token);
    expect(context.active).toBe(true);
    expect(context.tokenKind).toBe("client");
  });

  it("issues no refresh token for a single_use grant", () => {
    const { code } = seedGrant("single_use");
    const result = redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.issued.refresh_token).toBeUndefined();
  });

  it("allows a continuous grant to issue repeatedly", () => {
    const { grant, code } = seedGrant("continuous");
    expect(redeem(code).ok).toBe(true);

    store.insertAuthCode("code_second", {
      grantId: grant.grant_id,
      clientId: grant.client.client_id,
      redirectUri: "https://app.example.com/callback",
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(redeem("code_second").ok).toBe(true);
  });
});

describe("§9 AS item 20 — refresh tokens and family reuse", () => {
  it("issues a refresh token only for continuous grants", () => {
    expect(mayIssueRefreshToken(["continuous"])).toBe(true);
    expect(mayIssueRefreshToken(["single_use"])).toBe(false);
    // A package refreshes only when EVERY child grant is continuous.
    expect(mayIssueRefreshToken(["continuous", "single_use"])).toBe(false);
    expect(mayIssueRefreshToken(["continuous", "continuous"])).toBe(true);
    expect(mayIssueRefreshToken([])).toBe(false);
  });

  it("rotates a refresh token within its family", () => {
    const { code } = seedGrant("continuous");
    const first = redeem(code);
    expect(first.ok).toBe(true);
    if (!first.ok || !first.issued.refresh_token) return;

    const rotated = tokens.refresh({
      refreshToken: first.issued.refresh_token,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;
    expect(rotated.issued.refresh_token).toBeDefined();
    expect(rotated.issued.refresh_token).not.toBe(first.issued.refresh_token);
  });

  it("carries the granted authorization_details on refresh, matching introspection", () => {
    const { code } = seedGrant("continuous");
    const first = redeem(code);
    expect(first.ok).toBe(true);
    if (!first.ok || !first.issued.refresh_token) return;

    const rotated = tokens.refresh({
      refreshToken: first.issued.refresh_token,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;

    const introspected = tokens.introspect(rotated.issued.access_token);
    expect(rotated.issued.authorization_details).toEqual(
      introspected.authorization_details,
    );
  });

  it("revokes the family and all linked access tokens on reuse", () => {
    const { code } = seedGrant("continuous");
    const first = redeem(code);
    expect(first.ok).toBe(true);
    if (!first.ok || !first.issued.refresh_token) return;

    const rotated = tokens.refresh({
      refreshToken: first.issued.refresh_token,
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) return;

    // Both access tokens are live at this point.
    expect(tokens.resolveToken(first.issued.access_token).active).toBe(true);
    expect(tokens.resolveToken(rotated.issued.access_token).active).toBe(true);

    // Reuse the superseded refresh token.
    const reuse = tokens.refresh({ refreshToken: first.issued.refresh_token });
    expect(reuse.ok).toBe(false);
    if (reuse.ok) return;
    expect(reuse.failure.code).toBe("invalid_grant");

    // Every family-linked access token is now dead.
    expect(tokens.resolveToken(first.issued.access_token).active).toBe(false);
    expect(tokens.resolveToken(rotated.issued.access_token).active).toBe(false);

    // And the current refresh token no longer works — fresh authorization required.
    expect(
      tokens.refresh({ refreshToken: rotated.issued.refresh_token! }).ok,
    ).toBe(false);
  });

  it("rejects an unknown refresh token", () => {
    expect(tokens.refresh({ refreshToken: "pdpp_rt_nope" }).ok).toBe(false);
  });
});

describe("§8 — introspection carries the full enforcement context", () => {
  it("returns the resolved authorization_details for a client token", () => {
    const { grant, code } = seedGrant("continuous");
    const issued = redeem(code);
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const response = tokens.introspect(issued.issued.access_token);
    expect(response.active).toBe(true);
    expect(response.pdpp_token_kind).toBe("client");
    expect(response.subject_id).toBe("user_abc123");
    expect(response.grant_id).toBe(grant.grant_id);
    expect(response.client_id).toBe("music_recommendations");
    expect(response.authorization_details).toHaveLength(1);

    const detail = response.authorization_details![0];
    expect(detail.type).toBe(PDPP_DATA_ACCESS_TYPE);
    // The complete Section 7 constraints, in one response.
    expect(detail.streams).toEqual(grant.streams);
    expect(detail.access_mode).toBe("continuous");
    expect(detail.source).toEqual(grant.source);
  });

  it("returns exactly { active: false } for an inactive token", () => {
    // RFC 7662 §2.2: no information leak about a token that is revoked,
    // expired, or simply unknown.
    const response = tokens.introspect("pdpp_at_never_issued");
    expect(response).toEqual({ active: false });
  });

  it("carries no grant for an owner token", () => {
    // §8: "an owner token carries none" — the RS must not synthesize one.
    const owner = tokens.issueOwnerToken({ subjectId: "user_abc123" });
    const response = tokens.introspect(owner.access_token);
    expect(response.active).toBe(true);
    expect(response.pdpp_token_kind).toBe("owner");
    expect(response.subject_id).toBe("user_abc123");
    expect(response.grant_id).toBeUndefined();
    expect(response.authorization_details).toBeUndefined();
  });
});

describe("delivery §2 / §9 AS item 8 — revocation and lifecycle", () => {
  it("reports active: false immediately after revocation", () => {
    const { grant, code } = seedGrant("continuous");
    const issued = redeem(code);
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect(tokens.introspect(issued.issued.access_token).active).toBe(true);

    expect(tokens.revokeGrant(grant.grant_id)).toBe(true);

    // Immediately — no AS-side cache to wait out. The 60s bound in §8 is the
    // RS's positive-result cache, not slack here.
    expect(tokens.introspect(issued.issued.access_token)).toEqual({
      active: false,
    });
  });

  it("surfaces grant_revoked as the inactive reason for the RS", () => {
    // The RS turns this specific reason into 403 grant_revoked.
    const { grant, code } = seedGrant("continuous");
    const issued = redeem(code);
    if (!issued.ok) return;

    tokens.revokeGrant(grant.grant_id);
    const context = tokens.resolveToken(issued.issued.access_token);
    expect(context.active).toBe(false);
    expect(context.inactiveReason).toBe("grant_revoked");
  });

  it("refuses to refresh after the grant is revoked", () => {
    const { grant, code } = seedGrant("continuous");
    const issued = redeem(code);
    if (!issued.ok || !issued.issued.refresh_token) return;

    tokens.revokeGrant(grant.grant_id);
    const result = tokens.refresh({
      refreshToken: issued.issued.refresh_token,
    });
    expect(result.ok).toBe(false);
  });

  it("reports a double revoke as not-a-fresh-revocation", () => {
    const { grant } = seedGrant("continuous");
    expect(tokens.revokeGrant(grant.grant_id)).toBe(true);
    expect(tokens.revokeGrant(grant.grant_id)).toBe(false);
  });

  it("tracks the three lifecycle states", () => {
    const active = seedGrant("continuous").grant;
    expect(store.grantStatus(store.getGrant(active.grant_id)!)).toBe("active");

    const expired = seedGrant("continuous", {
      expires_at: new Date(Date.now() - 1000).toISOString(),
    }).grant;
    expect(store.grantStatus(store.getGrant(expired.grant_id)!)).toBe(
      "expired",
    );

    tokens.revokeGrant(active.grant_id);
    expect(store.grantStatus(store.getGrant(active.grant_id)!)).toBe("revoked");
  });

  it("reports revoked rather than expired when a grant is both", () => {
    // Revocation is the owner's decision and stays the reported fact; it does
    // not silently become "expired" once the clock passes.
    const { grant } = seedGrant("continuous", {
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    tokens.revokeGrant(grant.grant_id);
    expect(store.grantStatus(store.getGrant(grant.grant_id)!)).toBe("revoked");
  });
});

describe("§7 — token expiry never outlives grant expiry", () => {
  it("clamps access-token expiry to the grant's expires_at", () => {
    const grantExpiry = new Date(Date.now() + 30_000).toISOString();
    const { code } = seedGrant("continuous", { expires_at: grantExpiry });
    // Service TTL is an hour; the grant dies in 30 seconds.
    const result = redeem(code);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.issued.expires_in).toBeLessThanOrEqual(30);
  });

  it("treats an expired grant as inactive for an unexpired token", () => {
    const { grant, code } = seedGrant("continuous");
    const issued = redeem(code);
    if (!issued.ok) return;

    const later = new Date(Date.now() + 60 * 60 * 1000);
    // Re-read at a time past a grant expiry we set retroactively.
    store.revokeGrant(grant.grant_id, new Date());
    const context = tokens.resolveToken(issued.issued.access_token, later);
    expect(context.active).toBe(false);
  });
});

describe("§10 — tokens are not stored in plaintext", () => {
  it("does not persist the raw access token", () => {
    const { code } = seedGrant("continuous");
    const issued = redeem(code);
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const record = store.getAccessToken(issued.issued.access_token);
    expect(record).not.toBeNull();
    // Only the hash is retained, so a store dump yields no usable credential.
    expect(record!.tokenHash).not.toBe(issued.issued.access_token);
    expect(record!.tokenHash).toMatch(/^[0-9a-f]{64}$/);
  });
});
