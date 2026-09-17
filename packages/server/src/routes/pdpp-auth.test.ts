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
