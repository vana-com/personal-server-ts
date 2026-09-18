/**
 * End-to-end oracles for the PDPP AS HTTP surface.
 *
 * These drive the real Hono app over real requests against a real SQLite
 * store — authorize → review → approve → redeem → introspect → revoke. The
 * unit suites in `packages/core/src/pdpp/` prove each rule in isolation; this
 * suite proves the wire contract the consent UI and the RS actually consume,
 * including the HTTP status codes both lanes branch on.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_API_VERSION,
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type InstanceInventory,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const OTHER_OWNER = "user_other";
const REDIRECT = "https://app.example.com/callback";
/** RFC 7636 §4.1 verifier + its S256 challenge, used by every code flow here. */
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres", "source_updated_at"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let sessions: AuthorizationSessionStore;
let app: Hono;
let eligible: string[];
/** The subject the (stubbed) owner-session middleware reports. */
let authenticatedSubject: string | null;

const inventory: InstanceInventory = { eligibleFor: () => eligible };

function selectionBody(overrides: Record<string, unknown> = {}) {
  return {
    client_id: "music_recommendations",
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_display: { name: "Concert Finder" },
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE,
        source: { id: snapshot.source_id },
        purpose_code: "https://pdpp.dev/purpose/personalization",
        access_mode: "continuous",
        streams: [{ name: "top_artists" }],
        ...overrides,
      },
    ],
  };
}

function post(
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function postForm(
  path: string,
  fields: Record<string, string>,
  headers: Record<string, string> = {},
) {
  return app.request(path, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...headers,
    },
    body: new URLSearchParams(fields).toString(),
  });
}

function ownerAuth(token: string) {
  return { authorization: `Bearer ${token}` };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-routes-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
  eligible = ["spotify-account-a"];
  authenticatedSubject = OWNER;

  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions,
      resolveDeclaration: (sourceId) =>
        sourceId === snapshot.source_id ? snapshot : null,
      inventoryFor: () => inventory,
      currentSubjectId: (_c: Context) => authenticatedSubject,
      // Registered client metadata: redirect_uri is validated by exact match,
      // so an attacker-chosen target cannot receive the authorization code.
      registeredClient: (clientId) =>
        clientId === "music_recommendations"
          ? { client_id: clientId, redirect_uris: [REDIRECT] }
          : null,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

/** Walk authorize → review, returning the session and the owner's digest. */
async function openSessionAndReview(body = selectionBody()) {
  const ownerToken = tokens.issueOwnerToken({ subjectId: OWNER }).access_token;
  const created = await post("/pdpp/v1/authorize", body);
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };

  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review`,
    { headers: ownerAuth(ownerToken) },
  );
  expect(reviewed.status).toBe(200);
  const review = (await reviewed.json()) as {
    review: { review_digest: string };
  };
  return {
    sessionId: session_id,
    ownerToken,
    digest: review.review.review_digest,
  };
}

describe("the full authorization journey", () => {
  it("runs authorize → review → approve → token → introspect → revoke", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();

    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(200);
    const { redirect_uri, grant_id } = (await approved.json()) as {
      redirect_uri: string;
      grant_id: string;
    };

    // The redirect carries a code and preserves the client's state param.
    const redirect = new URL(redirect_uri);
    const code = redirect.searchParams.get("code")!;
    expect(code).toBeTruthy();
    expect(redirect.searchParams.get("state")).toBe("xyz");

    const tokenResponse = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(tokenResponse.status).toBe(200);
    // §1 of the delivery scope: every token response is no-store.
    expect(tokenResponse.headers.get("cache-control")).toBe("no-store");
    expect(tokenResponse.headers.get("pragma")).toBe("no-cache");
    const issued = (await tokenResponse.json()) as {
      access_token: string;
      refresh_token?: string;
    };
    expect(issued.access_token).toBeTruthy();
    // continuous grant ⇒ a refresh token is issued.
    expect(issued.refresh_token).toBeTruthy();

    const introspected = await postForm(
      "/pdpp/v1/introspect",
      { token: issued.access_token },
      ownerAuth(ownerToken),
    );
    expect(introspected.status).toBe(200);
    const context = (await introspected.json()) as {
      active: boolean;
      grant_id: string;
      pdpp_token_kind: string;
      authorization_details: Array<{ streams: Array<{ fields: string[] }> }>;
    };
    expect(context.active).toBe(true);
    expect(context.pdpp_token_kind).toBe("client");
    expect(context.grant_id).toBe(grant_id);
    // The RS gets the complete resolved enforcement context in one response.
    expect(context.authorization_details[0].streams[0].fields).toContain("id");

    const revoked = await postForm(
      "/pdpp/v1/revoke",
      { grant_id },
      ownerAuth(ownerToken),
    );
    expect(revoked.status).toBe(200);

    // Immediately inactive — no waiting out an AS-side cache.
    const afterRevoke = await postForm(
      "/pdpp/v1/introspect",
      { token: issued.access_token },
      ownerAuth(ownerToken),
    );
    expect(await afterRevoke.json()).toEqual({ active: false });
  });
});

describe("owner authentication on the decision endpoints", () => {
  it("rejects an approval with a valid digest but no owner token (401)", async () => {
    // The spoofed-approval case: everything correct except the authentication.
    const { sessionId, digest } = await openSessionAndReview();
    const response = await post(`/pdpp/v1/authorize/${sessionId}/approve`, {
      review_digest: digest,
    });
    expect(response.status).toBe(401);
    expect((await response.json()).error).toBe("unauthorized");
  });

  it("rejects an approval carrying another owner's token (404)", async () => {
    const { sessionId, digest } = await openSessionAndReview();
    const intruder = tokens.issueOwnerToken({
      subjectId: OTHER_OWNER,
    }).access_token;

    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(intruder),
    );
    // Not-found rather than forbidden: a caller must not learn that the
    // session exists and belongs to someone else.
    expect(response.status).toBe(404);
  });

  it("refuses to disclose a review to another owner (404)", async () => {
    const { sessionId } = await openSessionAndReview();
    const intruder = tokens.issueOwnerToken({
      subjectId: OTHER_OWNER,
    }).access_token;
    const response = await app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: ownerAuth(intruder) },
    );
    expect(response.status).toBe(404);
  });

  it("refuses to open an authorization session without an owner (401)", async () => {
    authenticatedSubject = null;
    const response = await post("/pdpp/v1/authorize", selectionBody());
    expect(response.status).toBe(401);
  });

  it("refuses introspection without resource-server authentication (401)", async () => {
    const response = await postForm("/pdpp/v1/introspect", {
      token: "anything",
    });
    expect(response.status).toBe(401);
  });

  it("refuses to revoke another owner's grant (404)", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();
    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    const { grant_id } = (await approved.json()) as { grant_id: string };

    const intruder = tokens.issueOwnerToken({
      subjectId: OTHER_OWNER,
    }).access_token;
    const response = await postForm(
      "/pdpp/v1/revoke",
      { grant_id },
      ownerAuth(intruder),
    );
    expect(response.status).toBe(404);
  });
});

describe("staleness (§7 / §9 AS item 15)", () => {
  it("answers 409 stale_review when eligibility changed after review", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();
    // A different account is now the only eligible one.
    eligible = ["spotify-account-b"];

    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error).toBe("stale_review");
  });

  it("answers 409 when a SECOND instance connects after review", async () => {
    // The canonical §6 drift case, and the one a consent UI must be able to
    // recover from: the owner reviewed a single auto-resolved account, then
    // connected another before approving. Re-resolution can no longer pick a
    // handle, and that must surface as staleness (re-fetch and re-prompt) —
    // not as invalid_request, which routes the UI to a dead end.
    const { sessionId, ownerToken, digest } = await openSessionAndReview();
    eligible = ["spotify-account-a", "spotify-account-b"];

    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(response.status).toBe(409);
    expect((await response.json()).error).toBe("stale_review");

    // And the recovery path works: re-fetching now offers the choice.
    const refetched = await app.request(
      `/pdpp/v1/authorize/${sessionId}/review`,
      { headers: ownerAuth(ownerToken) },
    );
    expect(refetched.status).toBe(200);
    const body = (await refetched.json()) as {
      instance_choice_required?: Array<{ candidates: string[] }>;
    };
    expect(body.instance_choice_required?.[0].candidates).toEqual([
      "spotify-account-a",
      "spotify-account-b",
    ]);
  });

  it("answers 409 for a digest the owner never saw", async () => {
    const { sessionId, ownerToken } = await openSessionAndReview();
    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: "f".repeat(64) },
      ownerAuth(ownerToken),
    );
    expect(response.status).toBe(409);
  });
});

describe("§9 AS item 19 — authorization codes are single-redemption", () => {
  it("rejects a replayed code and issues no second token", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();
    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;

    const fields = {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    };
    expect((await postForm("/pdpp/v1/token", fields)).status).toBe(200);

    const replay = await postForm("/pdpp/v1/token", fields);
    expect(replay.status).toBe(400);
    expect((await replay.json()).error).toBe("invalid_grant");
  });
});

describe("§9 AS item 20 — refresh reuse burns the family", () => {
  it("revokes the family and rejects the reuse", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();
    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;

    const first = (await (
      await postForm("/pdpp/v1/token", {
        grant_type: "authorization_code",
        code,
        client_id: "music_recommendations",
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
      })
    ).json()) as { access_token: string; refresh_token: string };

    const rotated = (await (
      await postForm("/pdpp/v1/token", {
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
      })
    ).json()) as { access_token: string; refresh_token: string };

    // Reuse the superseded token.
    const reuse = await postForm("/pdpp/v1/token", {
      grant_type: "refresh_token",
      refresh_token: first.refresh_token,
    });
    expect(reuse.status).toBe(400);
    expect((await reuse.json()).error).toBe("invalid_grant");

    // Every access token in the family is now dead.
    for (const token of [first.access_token, rotated.access_token]) {
      const introspected = await postForm(
        "/pdpp/v1/introspect",
        { token },
        ownerAuth(ownerToken),
      );
      expect(await introspected.json()).toEqual({ active: false });
    }
  });
});

describe("§9 AS item 5 — Source validation failures map to RFC 9396", () => {
  it("returns invalid_authorization_details for both streams and preset", async () => {
    const response = await post(
      "/pdpp/v1/authorize",
      selectionBody({
        streams: [{ name: "top_artists" }],
        selection_preset: "anything",
      }),
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_authorization_details");
  });

  it("returns invalid_authorization_details for neither", async () => {
    const response = await post(
      "/pdpp/v1/authorize",
      selectionBody({ streams: undefined }),
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_authorization_details");
  });

  it("rejects an unknown source with no retained snapshot", async () => {
    const response = await post(
      "/pdpp/v1/authorize",
      selectionBody({
        source: { id: "https://registry.pdpp.dev/connectors/nope" },
      }),
    );
    expect(response.status).toBe(400);
  });
});

describe("§9 AS item 17 — PDPP-Version negotiation", () => {
  it("returns 400 unsupported_version for a version it does not implement", async () => {
    const response = await app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "pdpp-version": "9.9.9",
      },
      body: JSON.stringify(selectionBody()),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("unsupported_version");
  });

  it("echoes the selected version on a response", async () => {
    const response = await post("/pdpp/v1/authorize", selectionBody());
    expect(response.headers.get("pdpp-version")).toBe(PDPP_API_VERSION);
  });

  it("accepts an absent version header and uses the current stable version", async () => {
    const response = await post("/pdpp/v1/authorize", selectionBody());
    expect(response.status).toBe(201);
  });
});

describe("§9 AS item 14 — AI training consent over the wire", () => {
  it("refuses approval without the explicit flag", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview(
      selectionBody({ purpose_code: "https://pdpp.dev/purpose/ai_training" }),
    );
    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("ai_training_consent_required");
  });

  it("issues with the explicit flag", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview(
      selectionBody({ purpose_code: "https://pdpp.dev/purpose/ai_training" }),
    );
    const response = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest, explicit_ai_training_consent: true },
      ownerAuth(ownerToken),
    );
    expect(response.status).toBe(200);
  });
});

describe("denial", () => {
  it("returns an access_denied redirect and blocks later approval", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();

    const denied = await post(
      `/pdpp/v1/authorize/${sessionId}/deny`,
      {},
      ownerAuth(ownerToken),
    );
    expect(denied.status).toBe(200);
    const { redirect_uri } = (await denied.json()) as { redirect_uri: string };
    expect(new URL(redirect_uri).searchParams.get("error")).toBe(
      "access_denied",
    );

    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(400);
  });

  it("refuses an unauthenticated denial", async () => {
    const { sessionId } = await openSessionAndReview();
    const response = await post(`/pdpp/v1/authorize/${sessionId}/deny`, {});
    expect(response.status).toBe(401);
  });
});

describe("approval persistence failure (session/grant/code atomicity)", () => {
  it("does not strand the session as approved when the durable write fails, and allows retry", async () => {
    const { sessionId, ownerToken, digest } = await openSessionAndReview();

    // Simulate a local persistence failure between the two durable writes
    // (grant insert succeeds, auth-code insert fails) — e.g. disk full,
    // or a constraint violation during approval.
    const originalInsertAuthCode = store.insertAuthCode.bind(store);
    let shouldFail = true;
    store.insertAuthCode = ((
      ...args: Parameters<typeof originalInsertAuthCode>
    ) => {
      if (shouldFail) {
        shouldFail = false;
        throw new Error("simulated disk failure during auth-code persistence");
      }
      return originalInsertAuthCode(...args);
    }) as typeof store.insertAuthCode;

    const failed = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(failed.status).toBe(500);

    // No grant should have survived the failed approval — otherwise a grant
    // exists with no redeemable code, and no record of the failure.
    const grantsAfterFailure = store.listGrantsForSubject(OWNER);
    expect(grantsAfterFailure).toHaveLength(0);

    // The owner must be able to retry the SAME reviewed approval. If the
    // in-memory session was already marked "approved" before the durable
    // write failed, this retry would be rejected as "already decided" even
    // though nothing durable was ever persisted — stranding valid consent.
    const retried = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    expect(retried.status).toBe(200);
    const { redirect_uri, grant_id } = (await retried.json()) as {
      redirect_uri: string;
      grant_id: string;
    };

    // The retry must have produced a real, redeemable grant + code.
    expect(store.getGrant(grant_id)).not.toBeNull();
    const code = new URL(redirect_uri).searchParams.get("code");
    expect(code).toBeTruthy();

    const tokenResponse = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code: code!,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(tokenResponse.status).toBe(200);
  });

  it("rejects a concurrent duplicate approval of the same session, issuing exactly one grant", async () => {
    // Two approval requests racing for the same reviewed session must not
    // both succeed. Node's single-threaded, run-to-completion model makes
    // this safe as long as nothing awaits between checking the session is
    // pending and marking it approved — this proves that holds end-to-end.
    const { sessionId, ownerToken, digest } = await openSessionAndReview();

    const [first, second] = await Promise.all([
      post(
        `/pdpp/v1/authorize/${sessionId}/approve`,
        { review_digest: digest },
        ownerAuth(ownerToken),
      ),
      post(
        `/pdpp/v1/authorize/${sessionId}/approve`,
        { review_digest: digest },
        ownerAuth(ownerToken),
      ),
    ]);

    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual([200, 400]);

    const grants = store.listGrantsForSubject(OWNER);
    expect(grants).toHaveLength(1);
  });
});

describe("the consent review model the UI renders", () => {
  it("emits the four semantic categories separately", async () => {
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post(
      "/pdpp/v1/authorize",
      selectionBody({
        purpose_description: "Recommend concerts",
        client_claims: { commitments: ["Data used only for recommendations"] },
      }),
    );
    const { session_id } = (await created.json()) as { session_id: string };

    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: ownerAuth(ownerToken) },
    );
    const body = (await reviewed.json()) as {
      review: {
        requester: { display_name: string; app_approved: boolean };
        data: { streams: Array<{ name: string; fields: string[] }> };
        policy: { purpose_description: string; purpose_unregistered: boolean };
        client_claims: { attributed_to: string; commitments: string[] };
        review_digest: string;
      };
    };

    expect(body.review.requester.display_name).toBe("Concert Finder");
    // An inline-only client is never "approved".
    expect(body.review.requester.app_approved).toBe(false);
    expect(body.review.data.streams[0].name).toBe("top_artists");
    expect(body.review.policy.purpose_description).toBe("Recommend concerts");
    expect(body.review.client_claims.attributed_to).toBe("Concert Finder");
    expect(body.review.review_digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("shows fully resolved streams, never request-only conveniences", async () => {
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post(
      "/pdpp/v1/authorize",
      selectionBody({ streams: [{ name: "*" }] }),
    );
    const { session_id } = (await created.json()) as { session_id: string };
    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: ownerAuth(ownerToken) },
    );
    const body = (await reviewed.json()) as {
      review: {
        data: { streams: Array<{ name: string; instance_ids: string[] }> };
      };
    };

    // The wildcard is gone; handles are concrete.
    expect(body.review.data.streams.map((s) => s.name)).toEqual([
      "top_artists",
    ]);
    expect(body.review.data.streams[0].instance_ids).toEqual([
      "spotify-account-a",
    ]);
  });
});

describe("RFC 7636 — PKCE binds the code to the requesting client", () => {
  /** Drive a real flow to an authorization code the attacker would intercept. */
  async function codeFor(body = selectionBody()) {
    const { sessionId, ownerToken, digest } = await openSessionAndReview(body);
    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      { review_digest: digest },
      ownerAuth(ownerToken),
    );
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    return new URL(redirect_uri).searchParams.get("code")!;
  }

  it("rejects an authorization request with no code_challenge", async () => {
    // Public clients: without a challenge there is nothing to bind the code
    // to, so an intercepted code would be redeemable by the interceptor.
    const { code_challenge: _omitted, ...noChallenge } = selectionBody();
    const response = await post("/pdpp/v1/authorize", noChallenge);
    expect(response.status).toBe(400);
  });

  it("rejects the plain challenge method", async () => {
    const body = {
      ...selectionBody(),
      code_challenge: CHALLENGE,
      code_challenge_method: "plain",
    };
    const response = await post("/pdpp/v1/authorize", body);
    expect(response.status).toBe(400);
    expect((await response.json()).error_description).toContain("S256");
  });

  it("rejects an omitted method rather than defaulting to plain", async () => {
    const body = {
      ...selectionBody(),
      code_challenge: CHALLENGE,
      code_challenge_method: undefined,
    };
    const response = await post("/pdpp/v1/authorize", body);
    expect(response.status).toBe(400);
  });

  it("fails PKCE before the owner is asked to consent", async () => {
    // A client whose flow is unusable should learn that before a human makes
    // a decision that will be thrown away.
    const { code_challenge: _dropped, ...noChallenge } = selectionBody();
    const response = await post("/pdpp/v1/authorize", noChallenge);
    expect(response.status).toBe(400);
    // No session was opened, so nothing can be reviewed or approved.
    const body = (await response.json()) as { session_id?: string };
    expect(body.session_id).toBeUndefined();
  });

  it("redeems with the correct verifier", async () => {
    const code = await codeFor();
    const response = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(response.status).toBe(200);
  });

  it("REJECTS a stolen code redeemed with NO verifier", async () => {
    // The core attack PKCE exists to stop.
    const code = await codeFor();
    const response = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_grant");
  });

  it("REJECTS a stolen code redeemed with a WRONG verifier", async () => {
    const code = await codeFor();
    const response = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: "Z".repeat(43),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error).toBe("invalid_grant");
  });

  it("REJECTS the challenge echoed back as the verifier", async () => {
    // The challenge is public — it travelled in the authorization request.
    const code = await codeFor();
    const response = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: CHALLENGE,
    });
    expect(response.status).toBe(400);
  });

  it("burns the code on a failed verifier, so guesses cannot be replayed", async () => {
    // Without this, an attacker holding a stolen code could brute-force the
    // verifier against a code that stays alive between attempts.
    const code = await codeFor();

    const wrongGuess = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: "Q".repeat(43),
    });
    expect(wrongGuess.status).toBe(400);

    // Even the legitimate client, with the real verifier, now gets nothing.
    const withRealVerifier = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(withRealVerifier.status).toBe(400);
  });

  it("issues no token on any rejected redemption", async () => {
    const code = await codeFor();
    await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: "Z".repeat(43),
    });

    // Nothing was minted: the grant has no live client token to introspect.
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const grants = store.listGrantsForSubject(OWNER);
    expect(grants.length).toBeGreaterThan(0);
    const anyLive = await postForm(
      "/pdpp/v1/introspect",
      { token: "pdpp_at_nothing_was_issued" },
      ownerAuth(ownerToken),
    );
    expect(await anyLive.json()).toEqual({ active: false });
  });

  it("binds each code to its own challenge across concurrent flows", async () => {
    // Two flows with different verifiers: neither code may be redeemed with
    // the other's verifier.
    const otherVerifier = "a".repeat(43);
    const otherChallenge = computeS256Challenge(otherVerifier);

    const codeA = await codeFor();
    const codeB = await codeFor({
      ...selectionBody(),
      code_challenge: otherChallenge,
      code_challenge_method: "S256",
    });

    const crossed = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code: codeB,
      client_id: "music_recommendations",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(crossed.status).toBe(400);

    // Each still works with its own verifier.
    expect(
      (
        await postForm("/pdpp/v1/token", {
          grant_type: "authorization_code",
          code: codeA,
          client_id: "music_recommendations",
          redirect_uri: REDIRECT,
          code_verifier: VERIFIER,
        })
      ).status,
    ).toBe(200);
  });
});

describe("owner-token exchange", () => {
  it("mints an owner token for a request that passed the owner proof", async () => {
    // The stubbed `currentSubjectId` stands in for the verified signer the
    // web3-auth + owner-check middleware chain populates in production.
    const response = await post("/pdpp/v1/owner/token", {});
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const issued = (await response.json()) as {
      access_token: string;
      token_type: string;
      expires_in: number;
    };
    expect(issued.token_type).toBe("Bearer");
    // Short-lived: it authorizes consent decisions, not long-term access.
    expect(issued.expires_in).toBeLessThanOrEqual(15 * 60);

    // The minted token is a real owner token the decision endpoints accept.
    const context = tokens.resolveToken(issued.access_token);
    expect(context.active).toBe(true);
    expect(context.tokenKind).toBe("owner");
    expect(context.subjectId).toBe(OWNER);
    expect(context.grant).toBeUndefined();
  });

  it("refuses to mint when no verified owner is present", async () => {
    // Fails closed rather than inventing a subject: an owner token for an
    // unidentified subject is the credential this design exists to prevent.
    authenticatedSubject = null;
    const response = await post("/pdpp/v1/owner/token", {});
    expect(response.status).toBe(401);
  });

  it("mints a token usable end-to-end for approval", async () => {
    const minted = (await (await post("/pdpp/v1/owner/token", {})).json()) as {
      access_token: string;
    };

    const created = await post("/pdpp/v1/authorize", selectionBody());
    const { session_id } = (await created.json()) as { session_id: string };

    const reviewed = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: ownerAuth(minted.access_token) },
    );
    expect(reviewed.status).toBe(200);
    const { review } = (await reviewed.json()) as {
      review: { review_digest: string };
    };

    const approved = await post(
      `/pdpp/v1/authorize/${session_id}/approve`,
      { review_digest: review.review_digest },
      ownerAuth(minted.access_token),
    );
    expect(approved.status).toBe(200);
  });

  it("mints a token scoped to its own subject only", async () => {
    // A token minted for one owner is not authority over another's session.
    const mintedForOwner = (await (
      await post("/pdpp/v1/owner/token", {})
    ).json()) as { access_token: string };

    const created = await post("/pdpp/v1/authorize", selectionBody());
    const { session_id } = (await created.json()) as { session_id: string };

    // A session belonging to a different subject.
    const otherSession = sessions.create({
      subjectId: OTHER_OWNER,
      request: selectionBody().authorization_details[0] as never,
      snapshot,
      requester: {
        client_id: "music_recommendations",
        display_name: "Concert Finder",
        app_approved: false,
      },
      redirectUri: REDIRECT,
    });

    const own = await app.request(`/pdpp/v1/authorize/${session_id}/review`, {
      headers: ownerAuth(mintedForOwner.access_token),
    });
    expect(own.status).toBe(200);

    const foreign = await app.request(
      `/pdpp/v1/authorize/${otherSession.session_id}/review`,
      { headers: ownerAuth(mintedForOwner.access_token) },
    );
    expect(foreign.status).toBe(404);
  });
});

describe("§6 — instance choice over the wire", () => {
  it("returns candidates instead of a review, then resolves on the pick", async () => {
    eligible = ["spotify-account-a", "spotify-account-b"];
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post("/pdpp/v1/authorize", selectionBody());
    const { session_id } = (await created.json()) as { session_id: string };

    const pending = await app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: ownerAuth(ownerToken) },
    );
    expect(pending.status).toBe(200);
    const pendingBody = (await pending.json()) as {
      review?: unknown;
      instance_choice_required?: Array<{
        stream: string;
        candidates: string[];
      }>;
    };
    expect(pendingBody.review).toBeUndefined();
    expect(pendingBody.instance_choice_required).toEqual([
      {
        stream: "top_artists",
        candidates: ["spotify-account-a", "spotify-account-b"],
      },
    ]);

    // The owner picks; the choice rides along as a query parameter.
    const picked = await app.request(
      `/pdpp/v1/authorize/${session_id}/review?${new URLSearchParams({
        "instance[top_artists]": "spotify-account-b",
      })}`,
      { headers: ownerAuth(ownerToken) },
    );
    const pickedBody = (await picked.json()) as {
      review: { data: { streams: Array<{ instance_ids: string[] }> } };
    };
    expect(pickedBody.review.data.streams[0].instance_ids).toEqual([
      "spotify-account-b",
    ]);
  });

  it("issues over exactly the chosen instance", async () => {
    eligible = ["spotify-account-a", "spotify-account-b"];
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post("/pdpp/v1/authorize", selectionBody());
    const { session_id } = (await created.json()) as { session_id: string };

    const picked = await app.request(
      `/pdpp/v1/authorize/${session_id}/review?${new URLSearchParams({
        "instance[top_artists]": "spotify-account-b",
      })}`,
      { headers: ownerAuth(ownerToken) },
    );
    const { review } = (await picked.json()) as {
      review: { review_digest: string };
    };

    const approved = await post(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        review_digest: review.review_digest,
        instance_choices: { top_artists: ["spotify-account-b"] },
      },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(200);
    const { grant_id } = (await approved.json()) as { grant_id: string };
    expect(store.getGrant(grant_id)!.grant.streams[0].instance_ids).toEqual([
      "spotify-account-b",
    ]);
  });

  it("answers 409 when the approved pick differs from the reviewed one", async () => {
    eligible = ["spotify-account-a", "spotify-account-b"];
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post("/pdpp/v1/authorize", selectionBody());
    const { session_id } = (await created.json()) as { session_id: string };

    const picked = await app.request(
      `/pdpp/v1/authorize/${session_id}/review?${new URLSearchParams({
        "instance[top_artists]": "spotify-account-b",
      })}`,
      { headers: ownerAuth(ownerToken) },
    );
    const { review } = (await picked.json()) as {
      review: { review_digest: string };
    };

    const approved = await post(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        review_digest: review.review_digest,
        instance_choices: { top_artists: ["spotify-account-a"] },
      },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(409);
  });
});

describe("existing OAuth behavior is untouched", () => {
  it("serves PDPP under its own /pdpp/v1 prefix only", async () => {
    // The legacy /oauth/token surface is a different app and is not mounted
    // here; PDPP must not shadow or claim that path.
    const response = await app.request("/oauth/token", { method: "POST" });
    expect(response.status).toBe(404);
  });
});

describe("redirect_uri validation (RFC 6749 §3.1.2, §10.6)", () => {
  /**
   * The authorization code travels in the redirect. If the AS honours whatever
   * `redirect_uri` a caller supplies, an attacker opens a session pointing at
   * their own host, the owner approves what looks like a legitimate consent
   * screen, and the code is delivered to the attacker.
   *
   * PKCE does not save this. The attacker chose the challenge, so they hold the
   * verifier too — they redeem the stolen code and receive a grant-bound token.
   */
  async function approveWith(redirectUri: string) {
    const ownerToken = tokens.issueOwnerToken({
      subjectId: OWNER,
    }).access_token;
    const created = await post("/pdpp/v1/authorize", {
      ...selectionBody(),
      redirect_uri: redirectUri,
    });
    return { created, ownerToken };
  }

  it("EXPLOIT: refuses to exfiltrate a code to an attacker-chosen host", async () => {
    const { created } = await approveWith("https://evil.example.com/steal");
    expect(created.status).toBe(400);
  });

  it("refuses a javascript: redirect target", async () => {
    const { created } = await approveWith("javascript:alert(document.cookie)");
    expect(created.status).toBe(400);
  });

  it("refuses a data: redirect target", async () => {
    const { created } = await approveWith("data:text/html,<script>1</script>");
    expect(created.status).toBe(400);
  });

  it("refuses plain http for a non-loopback host", async () => {
    const { created } = await approveWith("http://app.example.com/callback");
    expect(created.status).toBe(400);
  });

  it("refuses a redirect carrying a fragment (RFC 6749 §3.1.2)", async () => {
    const { created } = await approveWith("https://app.example.com/cb#frag");
    expect(created.status).toBe(400);
  });

  it("refuses a near-miss on the registered host", async () => {
    const { created } = await approveWith(
      "https://app.example.com.evil.test/callback",
    );
    expect(created.status).toBe(400);
  });

  it("refuses a path that only prefixes the registered one", async () => {
    const { created } = await approveWith(
      "https://app.example.com/callback/../../evil",
    );
    expect(created.status).toBe(400);
  });

  it("accepts the exact registered redirect", async () => {
    const { created } = await approveWith(REDIRECT);
    expect(created.status).toBe(201);
  });
});
