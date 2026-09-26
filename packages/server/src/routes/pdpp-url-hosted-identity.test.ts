/**
 * URL-hosted client identity, at the ROUTE level.
 *
 * The resolver had unit tests, but nothing asserted what the AS does with a
 * validated document once it has one. It turned out to do almost nothing: the
 * route used the document to admit the client's `redirect_uri` and then threw
 * it away, resolving the requester identity from the client's own inline
 * `client_display`.
 *
 * That splits identity from the trust that admitted it. A client could publish
 * a document at its `client_id` URL to earn redirect admission, then send an
 * inline display name the verified domain never asserted — and the consent
 * screen would show the inline name next to a "verified domain" badge earned
 * by the document. Not token theft, but the owner is deciding based on a name
 * nobody verified, which is the thing §6's precedence order exists to prevent.
 *
 * Core §6 precedence:
 *   registration > validated binding metadata > inline client_display > client_id
 *
 * These tests drive the real Hono app over real requests and assert on the
 * requester the OWNER ACTUALLY SEES in the review, not on the resolver's
 * return value.
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
  PDPP_DATA_ACCESS_TYPE,
  PdppTokenService,
  resolveUrlHostedClientIdentity,
  type DeclarationSnapshot,
  type InstanceInventory,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

/** The client is identified BY the URL its document lives at. */
const CLIENT_ID = "https://client.example.com/pdpp-client.json";
const REDIRECT = "https://client.example.com/callback";
const OWNER_INSTANCE = "spotify-account-a";

const DOCUMENT_NAME = "Document Name";
const INLINE_NAME = "Inline Name";

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
  ],
};

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let app: Hono;
/** The body served at CLIENT_ID; each test shapes it. */
let servedDocument: string;
let servedStatus: number;

const inventory: InstanceInventory = {
  eligibleFor: () => [OWNER_INSTANCE],
};

function authorizeBody(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    // The client asserts its own name inline. It must lose to the document.
    client_display: { name: INLINE_NAME },
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE,
        source: { id: snapshot.source_id },
        purpose_code: "https://pdpp.dev/purpose/personalization",
        access_mode: "continuous",
        streams: [{ name: "top_artists" }],
      },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-url-identity-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  servedStatus = 200;
  servedDocument = JSON.stringify({
    client_id: CLIENT_ID,
    client_name: DOCUMENT_NAME,
    redirect_uris: [REDIRECT],
  });

  app = new Hono();
  app.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      resolveDeclaration: (sourceId) =>
        sourceId === snapshot.source_id ? snapshot : null,
      inventoryFor: () => inventory,
      currentSubjectId: (_c: Context) => OWNER,
      // No registration at all: this client is known only by its document.
      registeredClient: () => null,
      resolveClientIdentity: (clientId) =>
        resolveUrlHostedClientIdentity({
          clientId,
          // The real resolver, with a stub transport — the bounded fetch
          // policy is exercised by its own unit suite.
          fetcher: async (url) =>
            url === CLIENT_ID
              ? { status: servedStatus, body: servedDocument, finalUrl: url }
              : null,
          policy: { allowAnyHttpsHost: true },
        }),
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

/** A genuinely minted owner token, as the consent surface would hold. */
function ownerToken() {
  return tokens.issueOwnerToken({
    subjectId: OWNER,
    instanceIds: [OWNER_INSTANCE],
  }).access_token;
}

async function openSession(body: unknown = authorizeBody()) {
  return app.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${ownerToken()}`,
    },
    body: JSON.stringify(body),
  });
}

/** The requester as rendered to the owner, which is what actually matters. */
async function reviewFor(sessionId: string, token: string) {
  const response = await app.request(`/pdpp/v1/authorize/${sessionId}/review`, {
    headers: { authorization: `Bearer ${token}` },
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    review: {
      requester: {
        client_id: string;
        display_name: string;
        verified_domain?: string;
        app_approved: boolean;
      };
      review_digest: string;
    };
  };
  return body.review;
}

/** The requester as rendered to the owner, which is what actually matters. */
async function requesterInReview(sessionId: string) {
  return (await reviewFor(sessionId, ownerToken())).requester;
}

describe("a validated document decides the identity the owner is shown", () => {
  it("prefers the document's name over the client's inline assertion", async () => {
    const opened = await openSession();
    expect(opened.status).toBe(201);
    const { session_id } = (await opened.json()) as { session_id: string };

    const requester = await requesterInReview(session_id);

    // The whole point: the name that earned redirect trust is the name shown.
    expect(requester.display_name).toBe(DOCUMENT_NAME);
    expect(requester.display_name).not.toBe(INLINE_NAME);
  });

  it("names the verified domain alongside it", async () => {
    const opened = await openSession();
    const { session_id } = (await opened.json()) as { session_id: string };

    const requester = await requesterInReview(session_id);

    // §6 obligation 5: a named domain, never a blanket "verified app".
    expect(requester.verified_domain).toBe("client.example.com");
    // Domain control is not an admission decision.
    expect(requester.app_approved).toBe(false);
  });

  it("falls back to the inline name when the document declares none", async () => {
    servedDocument = JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uris: [REDIRECT],
    });

    const opened = await openSession();
    expect(opened.status).toBe(201);
    const { session_id } = (await opened.json()) as { session_id: string };

    const requester = await requesterInReview(session_id);

    // A nameless document must not shadow the inline name with a blank one.
    expect(requester.display_name).toBe(INLINE_NAME);
    // It is still a validated document, so the domain is still verified.
    expect(requester.verified_domain).toBe("client.example.com");
  });

  it("falls back to the client_id when neither names the client", async () => {
    servedDocument = JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uris: [REDIRECT],
    });

    const opened = await openSession(
      authorizeBody({ client_display: undefined }),
    );
    const { session_id } = (await opened.json()) as { session_id: string };

    const requester = await requesterInReview(session_id);

    // §6 obligation 2: the surface is never left with nothing to render.
    expect(requester.display_name).toBe(CLIENT_ID);
  });

  it("does not let an unvalidated document supply the name", async () => {
    // A document asserting someone else's client_id fails the identity check,
    // so it must contribute nothing at all — not a name, not a domain.
    servedDocument = JSON.stringify({
      client_id: "https://attacker.example.net/other.json",
      client_name: "Someone Else",
      redirect_uris: [REDIRECT],
    });

    const opened = await openSession();

    // It also loses redirect admission, so the flow stops here.
    expect(opened.status).toBe(400);
  });

  it("carries the document identity through approval into the issued grant", async () => {
    const token = ownerToken();
    const opened = await openSession();
    const { session_id } = (await opened.json()) as { session_id: string };

    // The owner reviews, then approves the exact digest they were shown.
    const review = await reviewFor(session_id, token);
    expect(review.requester.display_name).toBe(DOCUMENT_NAME);

    const approved = await app.request(
      `/pdpp/v1/authorize/${session_id}/approve`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ review_digest: review.review_digest }),
      },
    );
    expect(approved.status).toBe(200);
    const { grant_id } = (await approved.json()) as { grant_id: string };

    // The grant must belong to the client the document identified. If the AS
    // admitted on the document but bound the grant to something else, the
    // consent evidence would not describe the requester the owner approved.
    const grant = store.getGrant(grant_id);
    expect(grant?.clientId).toBe(CLIENT_ID);
  });
});
