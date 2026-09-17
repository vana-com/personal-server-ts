/**
 * Oracles for authenticated owner approval (§7 approval binding, §9 AS items
 * 14, 15) and for the threat model in `approval.ts`.
 *
 * The central claim under test: an approval is accepted only when a real
 * authenticated owner made it. Holding the session id, holding a correct
 * review digest, or being the requesting client are each insufficient —
 * individually and in combination. "Spoofed approval" here means a request
 * that is correct in every respect except that no authenticated owner
 * authorized it, which is exactly what an affiliation-trusting AS would let
 * through.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  approveAuthorization,
  AuthorizationSessionStore,
  denyAuthorization,
  fetchReview,
  REVIEW_SESSION_TTL_SECONDS,
} from "./approval.js";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import { PdppTokenService } from "./tokens.js";
import type { InstanceInventory } from "./resolve.js";
import type { RequesterIdentity } from "./review.js";
import {
  AI_TRAINING_PURPOSE,
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const OWNER = "user_abc123";
const OTHER_OWNER = "user_someone_else";

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
  ],
};

const requester: RequesterIdentity = {
  client_id: "music_recommendations",
  display_name: "Concert Finder",
  app_approved: false,
};

function selection(
  overrides: Partial<SelectionRequest> = {},
): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: snapshot.source_id },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [{ name: "top_artists" }],
    ...overrides,
  };
}

const oneInstance: InstanceInventory = {
  eligibleFor: () => ["spotify-account-a"],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let sessions: AuthorizationSessionStore;

/** Create a pending session and return it with the owner's fresh review digest. */
function pendingSession(request: SelectionRequest = selection()) {
  const session = sessions.create({
    subjectId: OWNER,
    request,
    snapshot,
    requester,
    redirectUri: "https://app.example.com/callback",
  });
  const ownerToken = tokens.issueOwnerToken({ subjectId: OWNER }).access_token;
  const review = fetchReview({
    sessions,
    tokens,
    sessionId: session.session_id,
    ownerToken,
    inventory: oneInstance,
  });
  if (!review.ok || !review.result.review) {
    throw new Error("fixture: review fetch failed");
  }
  return {
    session,
    ownerToken,
    digest: review.result.review.review_digest,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-approval-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("owner approval requires authentication, not affiliation", () => {
  it("accepts an approval from the authenticated owner", () => {
    const { session, ownerToken, digest } = pendingSession();
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.subject.id).toBe(OWNER);
  });

  it("DENIES a spoofed approval: correct digest, no owner token", () => {
    // This is the affiliation-trust failure. Everything about the request is
    // right except that no owner authenticated it. An AS that trusted the
    // calling UI's identity would issue a grant here.
    const { session, digest } = pendingSession();
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: undefined,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unauthorized");
  });

  it("DENIES a spoofed approval: correct digest, a DIFFERENT owner's token", () => {
    // A valid owner token is not authority over someone else's session.
    const { session, digest } = pendingSession();
    const intruderToken = tokens.issueOwnerToken({
      subjectId: OTHER_OWNER,
    }).access_token;

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: intruderToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Reported as not-found, not "wrong owner": a caller holding any owner
    // token must not be able to probe which session ids exist or whose they are.
    expect(result.failure.code).toBe("session_not_found");
  });

  it("DENIES a spoofed approval: correct digest, a CLIENT token", () => {
    // The requesting application must never be able to authorize itself.
    const { session, digest } = pendingSession();

    // Mint a real client token by issuing an unrelated grant first.
    const seeded = pendingSession();
    const issued = approveAuthorization({
      sessions,
      tokens,
      sessionId: seeded.session.session_id,
      ownerToken: seeded.ownerToken,
      reviewDigest: seeded.digest,
      inventory: oneInstance,
    });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    store.insertGrant({
      grant: issued.grant,
      subjectId: OWNER,
      reviewDigest: seeded.digest,
    });
    store.insertAuthCode("code_x", {
      grantId: issued.grant.grant_id,
      clientId: issued.grant.client.client_id,
      redirectUri: "https://app.example.com/callback",
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const clientToken = tokens.redeemAuthorizationCode({
      code: "code_x",
      clientId: issued.grant.client.client_id,
      redirectUri: "https://app.example.com/callback",
    });
    expect(clientToken.ok).toBe(true);
    if (!clientToken.ok) return;

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: clientToken.issued.access_token,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unauthorized");
  });

  it("DENIES an approval carrying a revoked owner token", () => {
    const { session, ownerToken, digest } = pendingSession();
    expect(tokens.revokeAccessToken(ownerToken)).toBe(true);

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unauthorized");
  });

  it("authenticates before checking the digest, so failures are indistinguishable", () => {
    // An unauthenticated caller must not learn whether their digest was fresh.
    const { session } = pendingSession();
    const goodDigestNoAuth = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: undefined,
      reviewDigest: pendingSession().digest,
      inventory: oneInstance,
    });
    const junkDigestNoAuth = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: undefined,
      reviewDigest: "00",
      inventory: oneInstance,
    });
    expect(goodDigestNoAuth.ok).toBe(false);
    expect(junkDigestNoAuth.ok).toBe(false);
    if (goodDigestNoAuth.ok || junkDigestNoAuth.ok) return;
    expect(goodDigestNoAuth.failure).toEqual(junkDigestNoAuth.failure);
  });

  it("refuses to disclose another owner's review", () => {
    const { session } = pendingSession();
    const intruderToken = tokens.issueOwnerToken({
      subjectId: OTHER_OWNER,
    }).access_token;

    const result = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: intruderToken,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("session_not_found");
  });
});

describe("§6 — instance choice is a consent step, not a dead end", () => {
  const twoInstances: InstanceInventory = {
    eligibleFor: () => ["account-a", "account-b"],
  };

  function sessionNeedingChoice() {
    const session = sessions.create({
      subjectId: OWNER,
      request: selection(),
      snapshot,
      requester,
      redirectUri: "https://app.example.com/callback",
    });
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    return { session, ownerToken };
  }

  it("surfaces the candidates instead of a review when a pick is needed", () => {
    const { session, ownerToken } = sessionNeedingChoice();
    const result = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // No review yet: there is no single decision to render.
    expect(result.result.review).toBeUndefined();
    expect(result.result.instance_choice_required).toEqual([
      { stream: "top_artists", candidates: ["account-a", "account-b"] },
    ]);
  });

  it("returns a reviewable decision once the owner picks", () => {
    const { session, ownerToken } = sessionNeedingChoice();
    const result = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
      instanceChoices: { top_artists: ["account-b"] },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.instance_choice_required).toBeUndefined();
    expect(result.result.review?.data.streams[0].instance_ids).toEqual([
      "account-b",
    ]);
  });

  it("issues a grant over exactly the chosen instance", () => {
    const { session, ownerToken } = sessionNeedingChoice();
    const choices = { top_artists: ["account-b"] };
    const reviewed = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
      instanceChoices: choices,
    });
    if (!reviewed.ok || !reviewed.result.review) return;

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: reviewed.result.review.review_digest,
      inventory: twoInstances,
      instanceChoices: choices,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.streams[0].instance_ids).toEqual(["account-b"]);
  });

  it("rejects approval when the pick differs from the reviewed one", () => {
    // Approving with a different handle than was reviewed must be stale, not
    // a silent substitution of which account gets shared.
    const { session, ownerToken } = sessionNeedingChoice();
    const reviewed = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
      instanceChoices: { top_artists: ["account-b"] },
    });
    if (!reviewed.ok || !reviewed.result.review) return;

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: reviewed.result.review.review_digest,
      inventory: twoInstances,
      instanceChoices: { top_artists: ["account-a"] },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("stale_review");
  });

  it("cannot choose a handle the owner has not connected", () => {
    // A pick narrows the eligible set; it never widens it.
    const { session, ownerToken } = sessionNeedingChoice();
    const result = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
      instanceChoices: { top_artists: ["someone-elses-account"] },
    });
    expect(result.ok).toBe(false);
  });

  it("asks for no choice when the request named its handles", () => {
    const session = sessions.create({
      subjectId: OWNER,
      request: selection({
        streams: [{ name: "top_artists", instance_ids: ["account-a"] }],
      }),
      snapshot,
      requester,
      redirectUri: "https://app.example.com/callback",
    });
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const result = fetchReview({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      inventory: twoInstances,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.result.instance_choice_required).toBeUndefined();
    expect(result.result.review).toBeDefined();
  });
});

describe("§7 / §9 AS item 15 — stale approvals are rejected", () => {
  it("rejects an approval whose digest does not match", () => {
    const { session, ownerToken } = pendingSession();
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: "f".repeat(64),
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("stale_review");
  });

  it("rejects approval when instance eligibility changed after review", () => {
    // The owner reviewed a single auto-resolved instance. Before they
    // approved, a second account connected — which under §6 means the AS can
    // no longer auto-resolve at all. The reviewed decision is no longer the
    // decision being made, so the approval must die.
    const { session, ownerToken, digest } = pendingSession();

    const twoInstances: InstanceInventory = {
      eligibleFor: () => ["spotify-account-a", "spotify-account-b"],
    };

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: twoInstances,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    // This is the canonical §6 drift case and it MUST classify as staleness.
    // The consent UI routes `stale_review` to re-fetch-and-re-render, so the
    // owner sees the new instance choice and decides again; `invalid_request`
    // would route to "report a bug" and strand them. Found by the consent lane
    // driving a real adapter against this AS.
    expect(result.failure.code).toBe("stale_review");
  });

  it("rejects approval when the resolved instance silently changed", () => {
    // Same handle count, different handle: the digest must still move.
    const { session, ownerToken, digest } = pendingSession();
    const differentInstance: InstanceInventory = {
      eligibleFor: () => ["spotify-account-b"],
    };
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: differentInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("stale_review");
  });

  it("rejects a second approval of an already-decided session", () => {
    const { session, ownerToken, digest } = pendingSession();
    expect(
      approveAuthorization({
        sessions,
        tokens,
        sessionId: session.session_id,
        ownerToken,
        reviewDigest: digest,
        inventory: oneInstance,
      }).ok,
    ).toBe(true);

    const second = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.failure.code).toBe("access_denied");
  });

  it("rejects approval of an expired review session", () => {
    const { session, digest } = pendingSession();
    // The review window is 10 minutes; step just past it. A long-lived owner
    // token is minted deliberately so this test isolates *session* expiry
    // rather than incidentally also expiring the owner's authentication.
    const longLivedOwnerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
      ttlSeconds: 24 * 60 * 60,
    }).access_token;
    const afterReviewWindow = new Date(
      Date.now() + (REVIEW_SESSION_TTL_SECONDS + 60) * 1000,
    );

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: longLivedOwnerToken,
      reviewDigest: digest,
      inventory: oneInstance,
      now: afterReviewWindow,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("session_not_found");
  });
});

describe("§6 / §9 AS item 14 — AI training consent", () => {
  const aiRequest = selection({ purpose_code: AI_TRAINING_PURPOSE });

  it("refuses to issue without explicit affirmative consent", () => {
    const { session, ownerToken, digest } = pendingSession(aiRequest);
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("ai_training_consent_required");
  });

  it("refuses when consent is explicitly withheld", () => {
    const { session, ownerToken, digest } = pendingSession(aiRequest);
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
      explicitAiTrainingConsent: false,
    });
    expect(result.ok).toBe(false);
  });

  it("issues with explicit affirmative consent and records it as evidence", () => {
    const { session, ownerToken, digest } = pendingSession(aiRequest);
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
      explicitAiTrainingConsent: true,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.consentEvidence.explicit_ai_training_consent).toBe(true);
  });

  it("does not gate a non-ai_training purpose on that flag", () => {
    const { session, ownerToken, digest } = pendingSession();
    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(true);
  });
});

describe("denial", () => {
  it("lets the authenticated owner deny", () => {
    const { session, ownerToken } = pendingSession();
    expect(
      denyAuthorization({
        sessions,
        tokens,
        sessionId: session.session_id,
        ownerToken,
      }).ok,
    ).toBe(true);
  });

  it("refuses an unauthenticated denial", () => {
    const { session } = pendingSession();
    const result = denyAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken: undefined,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unauthorized");
  });

  it("is terminal — no grant can be issued afterwards", () => {
    const { session, ownerToken, digest } = pendingSession();
    denyAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
    });

    const result = approveAuthorization({
      sessions,
      tokens,
      sessionId: session.session_id,
      ownerToken,
      reviewDigest: digest,
      inventory: oneInstance,
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("access_denied");
  });
});
