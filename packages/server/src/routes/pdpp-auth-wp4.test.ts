/**
 * Wire oracles for the locked PDPP Core v0.1.0 §9 AS items in work package 4:
 * metadata (items 14, 25, 33, case O7), public invalidity (items 2, 5, 6, 9,
 * 11, 14, 31, 33), ineligible streams (item 53), review binding (items 15,
 * 31, 34), the `{ type, grant }` result (item 32), RFC 7009 revocation
 * (item 25) and terminal-event durability across issuance paths (item 44,
 * held-data case D1 as far as this AS has those paths).
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { Hono, type Context } from "hono";
import pino from "pino";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  AuthorizationSessionStore,
  computeS256Challenge,
  openPdppAuthStore,
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const CLIENT = "music_recommendations";
const REDIRECT = "https://app.example.com/callback";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const INSTANCE = "spotify-account-a";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

const snapshot: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  display: {
    name: "Spotify",
    name_map: { en: "Spotify", es: "Spotify en español" },
    default_language: "en",
  },
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres"],
      required_fields: ["id"],
      primary_key: ["id"],
      display: {
        label: "Top artists",
        label_map: { en: "Top artists", es: "Artistas principales" },
      },
    },
    {
      name: "profile",
      fields: ["id", "display_name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let sessions: AuthorizationSessionStore;
let app: Hono;
let eligible: Record<string, string[]>;

function detail(overrides: Record<string, unknown> = {}) {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: SOURCE_ID },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "continuous",
    streams: [{ name: "top_artists", fields: ["*"] }],
    ...overrides,
  };
}

function body(
  overrides: Record<string, unknown> = {},
  top: Record<string, unknown> = {},
) {
  return {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_display: { name: "Concert Finder" },
    authorization_details: [detail(overrides)],
    ...top,
  };
}

function ownerToken(): string {
  return tokens.issueOwnerToken({ subjectId: OWNER, sourceId: SOURCE_ID })
    .access_token;
}

function auth(token: string) {
  return { authorization: `Bearer ${token}` };
}

function postJson(path: string, payload: unknown, token = ownerToken()) {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/json", ...auth(token) },
    body: JSON.stringify(payload),
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

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-wp4-routes-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
  eligible = { top_artists: [INSTANCE], profile: [INSTANCE] };
  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions,
      issuer: "https://ps.example",
      resolveDeclaration: (id) => (id === SOURCE_ID ? snapshot : null),
      inventoryFor: () => ({ eligibleFor: (s) => eligible[s] ?? [] }),
      currentSubjectId: (c: Context) =>
        c.req.header("authorization") ? OWNER : null,
      registeredClient: (id) =>
        id === CLIENT ? { client_id: id, redirect_uris: [REDIRECT] } : null,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

async function openReview(payload = body(), query = "") {
  const token = ownerToken();
  const created = await postJson("/pdpp/v1/authorize", payload, token);
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };
  const reviewed = await app.request(
    `/pdpp/v1/authorize/${session_id}/review${query}`,
    { headers: auth(token) },
  );
  return { token, sessionId: session_id, reviewed };
}

async function approveAndRedeem(payload = body()) {
  const { token, sessionId, reviewed } = await openReview(payload);
  expect(reviewed.status).toBe(200);
  const { review } = (await reviewed.json()) as {
    review: { review_digest: string };
  };
  const approved = await postJson(
    `/pdpp/v1/authorize/${sessionId}/approve`,
    { review_digest: review.review_digest },
    token,
  );
  expect(approved.status).toBe(200);
  const { redirect_uri, grant_id } = (await approved.json()) as {
    redirect_uri: string;
    grant_id: string;
  };
  const code = new URL(redirect_uri).searchParams.get("code")!;
  return { token, code, grantId: grant_id };
}

async function redeem(code: string) {
  return postForm("/pdpp/v1/token", {
    grant_type: "authorization_code",
    code,
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
  });
}

describe("metadata (AS items 14, 25, 33; case O7)", () => {
  it("advertises the RFC 7009 endpoint and no processing permission", async () => {
    const res = await app.request(
      "/pdpp/v1/.well-known/oauth-authorization-server",
    );
    const metadata = (await res.json()) as Record<string, unknown>;
    expect(metadata.revocation_endpoint).toBe(
      "https://ps.example/pdpp/v1/token/revoke",
    );
    expect(metadata.pdpp_processing_permissions_supported).toEqual([]);
    expect(metadata.authorization_details_types_supported).toContain(
      PDPP_DATA_ACCESS_TYPE,
    );
    // AS item 33 (WP6): grant-lifecycle is advertised with its endpoint.
    expect(metadata.authorization_details_types_supported).toContain(
      "https://pdpp.dev/grant-lifecycle",
    );
    expect(metadata.pdpp_grant_lifecycle_endpoint).toBe(
      "https://ps.example/pdpp/v1/grant-lifecycle",
    );
  });
});

describe("public invalidity → invalid_authorization_details (AS items 2, 5, 14, 33)", () => {
  it.each([
    [
      "an unknown release permission (O7)",
      { processing_permissions: ["https://example.com/processing/release"] },
    ],
    [
      "the reserved AI training permission (item 14)",
      { processing_permissions: ["https://pdpp.dev/processing/ai_training"] },
    ],
    ["an undefined detail member (item 33)", { future_control: "x" }],
    ["an unsupported type (item 5)", { type: "https://example.com/x" }],
    [
      "a non-Appendix-A code without description (item 6)",
      { purpose_code: "https://w3id.org/dpv#ServiceProvision" },
    ],
    [
      "a retention that is not PnD (item 31)",
      { retention: { max_duration: "P1M", on_expiry: "delete" } },
    ],
    [
      "a non-canonical compound resource key (item 11)",
      {
        streams: [
          { name: "top_artists", fields: ["*"], resources: ['[ "a"]'] },
        ],
      },
    ],
    [
      "resources over two instances (item 11)",
      {
        streams: [
          {
            name: "top_artists",
            fields: ["*"],
            instance_ids: ["a", "b"],
            resources: ["r"],
          },
        ],
      },
    ],
  ])(
    "rejects %s, opens no session and issues nothing",
    async (_l, override) => {
      const before = store.listGrantsForSubject(OWNER).length;
      const res = await postJson("/pdpp/v1/authorize", body(override));
      expect(res.status).toBe(400);
      expect(((await res.json()) as { error: string }).error).toBe(
        "invalid_authorization_details",
      );
      expect(store.listGrantsForSubject(OWNER)).toHaveLength(before);
    },
  );

  it("rejects more than one Core data-access detail (item 9)", async () => {
    const res = await postJson("/pdpp/v1/authorize", {
      ...body(),
      authorization_details: [detail(), detail()],
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_authorization_details",
    );
  });

  it("does not reject for an unsupported ui_locales tag (item 34)", async () => {
    const res = await postJson(
      "/pdpp/v1/authorize",
      body({}, { ui_locales: "tlh-Piqd zz_ZZ" }),
    );
    expect(res.status).toBe(201);
  });
});

describe("review model (AS items 6, 15, 31, 34)", () => {
  it("displays a non-Appendix-A purpose with its description", async () => {
    const { reviewed } = await openReview(
      body({
        purpose_code: "https://w3id.org/dpv#ServiceProvision",
        purpose_description: "Run the service you signed up for",
      }),
    );
    const { review } = (await reviewed.json()) as {
      review: {
        policy: { purpose_description: string; purpose_unregistered: boolean };
      };
    };
    expect(review.policy.purpose_description).toBe(
      "Run the service you signed up for",
    );
    expect(review.policy.purpose_unregistered).toBe(true);
  });

  it("discloses envelope identifiers and binds the chosen language", async () => {
    const { reviewed } = await openReview(body({}, { ui_locales: "es-MX" }));
    const { review } = (await reviewed.json()) as {
      review: {
        envelope_disclosure: { statement: string };
        data: {
          source: { display_name: string };
          streams: Array<{
            display_label: string;
            envelope_identifiers: { primary_key: string[] };
          }>;
        };
        display_values: Array<{ id: string; value: string; language?: string }>;
      };
    };
    expect(review.envelope_disclosure.statement).toMatch(/identifiers/);
    expect(review.data.streams[0].envelope_identifiers.primary_key).toEqual([
      "id",
    ]);
    expect(review.data.source.display_name).toBe("Spotify en español");
    expect(review.data.streams[0].display_label).toBe("Artistas principales");
    expect(review.display_values).toContainEqual({
      id: "streams[top_artists].display.label",
      value: "Artistas principales",
      language: "es",
    });
  });

  it("retains the displayed values in consent evidence (item 34)", async () => {
    const { grantId } = await approveAndRedeem(body({}, { ui_locales: "es" }));
    const db = new Database(join(dir, "auth.db"), { readonly: true });
    const row = db
      .prepare(
        "SELECT consent_evidence_json FROM pdpp_grants WHERE grant_id = ?",
      )
      .get(grantId) as { consent_evidence_json: string };
    db.close();
    const evidence = JSON.parse(row.consent_evidence_json) as {
      displayed: {
        client: { display_name: string };
        display_values: Array<{ id: string; language?: string }>;
      };
    };
    expect(evidence.displayed.client.display_name).toBe("Concert Finder");
    expect(evidence.displayed.display_values).toContainEqual({
      id: "display.name",
      value: "Spotify en español",
      language: "es",
    });
  });

  it("rejects an approval whose digest bound a different language (item 15)", async () => {
    const token = ownerToken();
    const es = await openReview(body({}, { ui_locales: "es" }));
    const en = await openReview(body({}, { ui_locales: "en" }));
    const esDigest = (
      (await es.reviewed.json()) as { review: { review_digest: string } }
    ).review.review_digest;
    const enDigest = (
      (await en.reviewed.json()) as { review: { review_digest: string } }
    ).review.review_digest;
    expect(esDigest).not.toBe(enDigest);
    // The owner reviewed the English text; approving the Spanish session
    // with that digest is stale.
    const stale = await postJson(
      `/pdpp/v1/authorize/${es.sessionId}/approve`,
      { review_digest: enDigest },
      token,
    );
    expect(stale.status).toBe(409);
  });
});

describe("ineligible streams (AS item 53)", () => {
  it("omits an optional stream with no eligible instance", async () => {
    eligible = { top_artists: [INSTANCE] };
    const { reviewed } = await openReview(
      body({
        streams: [
          { name: "top_artists", fields: ["*"] },
          { name: "profile", fields: ["*"] },
        ],
      }),
    );
    expect(reviewed.status).toBe(200);
    const { review } = (await reviewed.json()) as {
      review: {
        data: { streams: Array<{ name: string }>; omitted_streams: string[] };
      };
    };
    expect(review.data.streams.map((s) => s.name)).toEqual(["top_artists"]);
    expect(review.data.omitted_streams).toEqual(["profile"]);
  });

  it("refuses a required stream with no eligible instance; client sees access_denied", async () => {
    eligible = { top_artists: [INSTANCE] };
    const { token, sessionId, reviewed } = await openReview(
      body({
        streams: [
          { name: "top_artists", fields: ["*"] },
          { name: "profile", necessity: "required", fields: ["*"] },
        ],
      }),
    );
    expect(reviewed.status).toBe(403);
    expect(((await reviewed.json()) as { error: string }).error).toBe(
      "access_denied",
    );
    const denied = await postJson(
      `/pdpp/v1/authorize/${sessionId}/deny`,
      {},
      token,
    );
    expect(
      ((await denied.json()) as { redirect_uri: string }).redirect_uri,
    ).toBe(`${REDIRECT}?error=access_denied&state=xyz`);
    expect(store.listGrantsForSubject(OWNER)).toHaveLength(0);
  });
});

describe("{ type, grant } result (AS items 9, 32)", () => {
  it("returns the complete grant in code and refresh responses and introspection", async () => {
    const { token, code, grantId } = await approveAndRedeem();
    const first = (await (await redeem(code)).json()) as {
      access_token: string;
      refresh_token: string;
      authorization_details: Array<{
        type: string;
        grant: { grant_id: string };
      }>;
    };
    // The complete grant as issued to this client: the stored grant with the
    // client's pairwise instance handles (AS item 29).
    const stored = store.clientGrantView(store.getGrant(grantId)!);
    expect(first.authorization_details).toEqual([
      { type: PDPP_DATA_ACCESS_TYPE, grant: stored },
    ]);

    const refreshed = (await (
      await postForm("/pdpp/v1/token", {
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
      })
    ).json()) as { access_token: string; authorization_details: unknown };
    expect(refreshed.authorization_details).toEqual(
      first.authorization_details,
    );

    const introspected = (await (
      await postForm(
        "/pdpp/v1/introspect",
        { token: refreshed.access_token },
        auth(token),
      )
    ).json()) as Record<string, unknown>;
    // PDPP introspection extension fields (item 9) and the same element.
    expect(introspected).toMatchObject({
      active: true,
      pdpp_token_kind: "client",
      grant_id: grantId,
      client_id: CLIENT,
      subject_id: OWNER,
    });
    expect(introspected.authorization_details).toEqual(
      first.authorization_details,
    );
  });
});

describe("RFC 7009 revocation (AS item 25)", () => {
  async function issued() {
    const { token, code, grantId } = await approveAndRedeem();
    const tokenResponse = (await (await redeem(code)).json()) as {
      access_token: string;
      refresh_token: string;
    };
    return { ownerTokenValue: token, grantId, ...tokenResponse };
  }

  it("ends the grant on refresh-token revocation and records the disposition", async () => {
    const t = await issued();
    const res = await postForm("/pdpp/v1/token/revoke", {
      token: t.refresh_token,
      token_type_hint: "refresh_token",
      client_id: CLIENT,
      pdpp_disposition: "delete",
      reported_at: "2026-11-26T09:00:00Z",
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(store.getGrant(t.grantId)?.revokedAt).not.toBeNull();
    expect(store.listDispositions(t.grantId)).toMatchObject([
      { disposition: "delete", reportedAt: "2026-11-26T09:00:00Z" },
    ]);
  });

  it("rejects a disposition value other than keep or delete", async () => {
    const t = await issued();
    const res = await postForm("/pdpp/v1/token/revoke", {
      token: t.refresh_token,
      client_id: CLIENT,
      pdpp_disposition: "archive",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe(
      "invalid_request",
    );
    expect(store.getGrant(t.grantId)?.revokedAt).toBeNull();
  });

  it("rejects reported_at without delete, and a malformed reported_at", async () => {
    const t = await issued();
    for (const fields of [
      { pdpp_disposition: "keep", reported_at: "2026-11-26T09:00:00Z" },
      { pdpp_disposition: "delete", reported_at: "yesterday" },
      // L1748: a time later than the request.
      { pdpp_disposition: "delete", reported_at: "2999-01-01T00:00:00Z" },
    ]) {
      const res = await postForm("/pdpp/v1/token/revoke", {
        token: t.refresh_token,
        client_id: CLIENT,
        ...fields,
      });
      expect(res.status).toBe(400);
    }
  });

  it("answers 200 for an unknown token and refuses a missing client_id", async () => {
    expect(
      (
        await postForm("/pdpp/v1/token/revoke", {
          token: "pdpp_rt_unknown",
          client_id: CLIENT,
        })
      ).status,
    ).toBe(200);
    expect(
      (await postForm("/pdpp/v1/token/revoke", { token: "x" })).status,
    ).toBe(400);
  });

  it("answers a token issued to another client exactly like an unknown token, with no effect", async () => {
    const t = await issued();
    const foreign = await postForm("/pdpp/v1/token/revoke", {
      token: t.access_token,
      client_id: "someone_else",
    });
    const unknown = await postForm("/pdpp/v1/token/revoke", {
      token: "never-issued",
      client_id: "someone_else",
    });
    // RFC 7009 §2.2; no signal about which client a token belongs to.
    expect(foreign.status).toBe(200);
    expect(await foreign.text()).toBe(await unknown.text());
    expect(unknown.status).toBe(200);
    // The real client's token still works.
    const still = await postForm(
      "/pdpp/v1/introspect",
      { token: t.access_token },
      auth(t.ownerTokenValue),
    );
    expect(((await still.json()) as { active: boolean }).active).toBe(true);
  });

  it("keeps the owner grant revocation on its own non-advertised route", async () => {
    const t = await issued();
    const res = await postForm(
      "/pdpp/v1/revoke",
      { grant_id: t.grantId, disposition: "keep" },
      auth(t.ownerTokenValue),
    );
    expect(res.status).toBe(200);
    expect(store.getGrant(t.grantId)?.revokedAt).not.toBeNull();
  });
});

describe("terminal events vs every issuance path (AS item 44, case D1 here)", () => {
  it.each(["owner", "client"])(
    "after a %s revocation, no path returns an active result or a token",
    async (who) => {
      // Grant A: token issued. Grant B: code minted but not yet redeemed.
      const a = await approveAndRedeem();
      const aTokens = (await (await redeem(a.code)).json()) as {
        access_token: string;
        refresh_token: string;
      };
      const b = await approveAndRedeem();

      for (const grantId of [a.grantId, b.grantId]) {
        if (who === "owner") {
          const res = await postForm(
            "/pdpp/v1/revoke",
            { grant_id: grantId, disposition: "keep" },
            auth(a.token),
          );
          expect(res.status).toBe(200);
        } else if (grantId === a.grantId) {
          const res = await postForm("/pdpp/v1/token/revoke", {
            token: aTokens.refresh_token,
            client_id: CLIENT,
          });
          expect(res.status).toBe(200);
        } else {
          // No client credential exists yet for B; the owner ends it.
          tokens.revokeGrant(grantId);
        }
      }

      // Refresh exchange.
      const refreshed = await postForm("/pdpp/v1/token", {
        grant_type: "refresh_token",
        refresh_token: aTokens.refresh_token,
      });
      expect(refreshed.status).toBe(400);
      expect(((await refreshed.json()) as { error: string }).error).toBe(
        "invalid_grant",
      );
      // Authorization-code exchange.
      const codeExchange = await redeem(b.code);
      expect(codeExchange.status).toBe(400);
      expect(((await codeExchange.json()) as { error: string }).error).toBe(
        "invalid_grant",
      );
      // Introspection.
      const introspected = await postForm(
        "/pdpp/v1/introspect",
        { token: aTokens.access_token },
        auth(ownerToken()),
      );
      expect(await introspected.json()).toEqual({ active: false });
      // Co-located RS resolution.
      expect(tokens.resolveToken(aTokens.access_token).active).toBe(false);
    },
  );
});
