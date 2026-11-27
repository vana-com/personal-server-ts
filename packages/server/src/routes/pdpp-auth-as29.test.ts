/**
 * Wire oracles for AS item 29 (spec-core L2545, L1427-L1435): each client
 * receives a pairwise `subject.id`, stable for that client and different
 * between clients; the internal subject goes only to the RS (introspection
 * `subject_id`); owner views keep working off the internal subject.
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
const CLIENT_B = "concert_finder";
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
  dir = mkdtempSync(join(tmpdir(), "pdpp-as29-routes-"));
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
        id === CLIENT || id === CLIENT_B
          ? { client_id: id, redirect_uris: [REDIRECT] }
          : null,
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

async function redeem(code: string, clientId = CLIENT) {
  return postForm("/pdpp/v1/token", {
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_verifier: VERIFIER,
  });
}

type TokenBody = {
  access_token: string;
  authorization_details: Array<{
    type: string;
    grant: { subject: { id: string }; grant_id: string };
  }>;
};

async function grantFor(clientId: string) {
  const { code } = await approveAndRedeem(body({}, { client_id: clientId }));
  const res = await redeem(code, clientId);
  expect(res.status).toBe(200);
  const json = (await res.json()) as TokenBody;
  return {
    token: json.access_token,
    grant: json.authorization_details[0].grant,
  };
}

describe("AS item 29 — pairwise subject identifiers", () => {
  it("gives two clients different subject.id values, neither the internal subject", async () => {
    const a = await grantFor(CLIENT);
    const b = await grantFor(CLIENT_B);
    expect(a.grant.subject.id).not.toBe(b.grant.subject.id);
    for (const g of [a.grant, b.grant]) {
      expect(g.subject.id).not.toBe(OWNER);
      expect(g.subject.id).not.toContain(OWNER);
      expect(g.subject.id).toMatch(/^pws_[A-Za-z0-9_-]{43}$/);
    }
  });

  it("keeps one client's subject.id the same across grants", async () => {
    const first = await grantFor(CLIENT);
    const second = await grantFor(CLIENT);
    expect(first.grant.grant_id).not.toBe(second.grant.grant_id);
    expect(second.grant.subject.id).toBe(first.grant.subject.id);
  });

  it("keeps the assignment across a store reopen (never reassigned)", async () => {
    const first = await grantFor(CLIENT);
    const path = join(dir, "auth.db");
    store.close();
    const reopened = openPdppAuthStore(path);
    try {
      expect(reopened.findPairwiseSubjectId(OWNER, CLIENT)).toBe(
        first.grant.subject.id,
      );
      expect(reopened.findPairwiseSubjectId(OWNER, CLIENT_B)).toBeNull();
    } finally {
      reopened.close();
      store = openPdppAuthStore(path);
    }
  });

  it("returns the internal subject only to the RS (introspection subject_id)", async () => {
    const a = await grantFor(CLIENT);
    const res = await postForm(
      "/pdpp/v1/introspect",
      { token: a.token },
      auth(ownerToken()),
    );
    const introspection = (await res.json()) as {
      active: boolean;
      subject_id: string;
      authorization_details: TokenBody["authorization_details"];
    };
    expect(introspection.active).toBe(true);
    expect(introspection.subject_id).toBe(OWNER);
    expect(introspection.authorization_details[0].grant.subject.id).toBe(
      a.grant.subject.id,
    );
  });

  it("stores the grant under the internal subject, so owner views still list it", async () => {
    const a = await grantFor(CLIENT);
    const b = await grantFor(CLIENT_B);
    const stored = store
      .listGrantsForSubject(OWNER)
      .map((g) => g.grant.grant_id);
    expect(stored).toEqual(
      expect.arrayContaining([a.grant.grant_id, b.grant.grant_id]),
    );
    const res = await app.request("/pdpp/v1/grants", {
      headers: auth(ownerToken()),
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain(a.grant.grant_id);
    expect(text).toContain(b.grant.grant_id);
  });

  it("records the pairwise identifier and its client in consent evidence", async () => {
    const a = await grantFor(CLIENT);
    const db = new Database(join(dir, "auth.db"), { readonly: true });
    const row = db
      .prepare(
        "SELECT consent_evidence_json FROM pdpp_grants WHERE grant_id = ?",
      )
      .get(a.grant.grant_id) as { consent_evidence_json: string };
    db.close();
    expect(JSON.parse(row.consent_evidence_json).subject_identifier).toEqual({
      id: a.grant.subject.id,
      client_id: CLIENT,
      kind: "pairwise",
    });
  });

  it("records the assignment in the history log before disclosure (L1824)", async () => {
    await grantFor(CLIENT);
    const db = new Database(join(dir, "auth.db"), { readonly: true });
    const kinds = (
      db
        .prepare("SELECT kind FROM pdpp_history_log ORDER BY seq")
        .all() as Array<{
        kind: string;
      }>
    ).map((r) => r.kind);
    db.close();
    expect(kinds.indexOf("pairwise_subject_assigned")).toBeGreaterThanOrEqual(
      0,
    );
    expect(kinds.indexOf("pairwise_subject_assigned")).toBeLessThan(
      kinds.indexOf("grant_issued"),
    );
  });
});
