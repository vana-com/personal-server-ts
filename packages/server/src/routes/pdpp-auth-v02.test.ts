/**
 * End-to-end oracles for the v0.2 authorization journey over HTTP.
 *
 * Anchors: PR vana-com/pdpp#1 spec-core.md "Limits and owner choices",
 * "Explicit authorization minima", "Recipient commitments and approval", §7
 * "Client-visible authorization result".
 *
 * The core suites prove each rule against the Core functions. This suite
 * proves the *wire contract* the consent UI and the RS actually consume: that
 * the owner's narrowing survives a query string, that the digest it produced
 * is the one the approval must carry, and that the status codes each lane
 * branches on are the ones PR #1 names. A rule that holds in Core and is
 * unreachable over HTTP is not implemented.
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
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION_V02,
  PdppTokenService,
  type DeclarationSnapshot,
  type Grant,
  type InstanceInventory,
  type PdppAuthStore,
  type RecipientTerms,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const REDIRECT = "https://app.example.com/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const Q4 = { since: "2025-10-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "d".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant", "private_note"],
      // A v0.1 consent floor. v0.2 revokes its consent effect; the projection
      // test below is the wire-level proof.
      required_fields: ["date", "private_note"],
      consent_time_field: "date",
      primary_key: ["date"],
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
let standingTerms: RecipientTerms | null;

const inventory: InstanceInventory = {
  eligibleFor: () => ["account_example"],
};

function v02Body(streamOverrides: Record<string, unknown> = {}) {
  return {
    client_id: "budget_example",
    redirect_uri: REDIRECT,
    state: "xyz",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    client_display: { name: "Budget Example" },
    authorization_details: [
      {
        type: PDPP_DATA_ACCESS_TYPE_V02,
        source: { id: snapshot.source_id },
        purpose_code: "https://apps.example.com/purposes/budget",
        access_mode: "continuous",
        retention: { max_duration: "P30D", on_expiry: "delete" },
        streams: [
          {
            name: "transactions",
            necessity: "required",
            fields: ["date", "amount", "merchant"],
            time_range: YEAR,
            minimum: { fields: ["date", "amount"], time_range: Q4 },
            ...streamOverrides,
          },
          {
            name: "profile",
            necessity: "optional",
            fields: ["id", "display_name"],
          },
        ],
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

function postForm(path: string, fields: Record<string, string>) {
  return app.request(path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
  });
}

function ownerAuth(token: string) {
  return { authorization: `Bearer ${token}` };
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-v02-routes-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
  sessions = new AuthorizationSessionStore();
  standingTerms = null;

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
      currentSubjectId: (_c: Context) => OWNER,
      registeredClient: (clientId) =>
        clientId === "budget_example"
          ? { client_id: clientId, redirect_uris: [REDIRECT] }
          : null,
      standingTermsFor: () => standingTerms,
    }),
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

/**
 * Open a session and fetch the review, optionally with the owner's narrowing
 * in the query string — the same way the consent UI re-fetches after a choice.
 */
async function review(narrowing = "", body = v02Body()) {
  const ownerToken = tokens.issueOwnerToken({ subjectId: OWNER }).access_token;
  const created = await post("/pdpp/v1/authorize", body);
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };

  const response = await app.request(
    `/pdpp/v1/authorize/${session_id}/review${narrowing}`,
    { headers: ownerAuth(ownerToken) },
  );
  return { sessionId: session_id, ownerToken, response };
}

describe("v0.2 authorize → review", () => {
  it("accepts a v0.2 selection request", async () => {
    const created = await post("/pdpp/v1/authorize", v02Body());
    expect(created.status).toBe(201);
  });

  it("rejects a malformed minimum as invalid_authorization_details", async () => {
    // The request-limit-vs-minimum conflict from PR #1's "Minimum window
    // exceeds request limit" scenario: only December is requested, October is
    // declared as the floor.
    const created = await post(
      "/pdpp/v1/authorize",
      v02Body({
        time_range: { since: "2025-12-01T00:00:00Z", until: YEAR.until },
        minimum: { time_range: Q4 },
      }),
    );
    expect(created.status).toBe(400);
    const body = (await created.json()) as { error: string };
    expect(body.error).toBe("invalid_authorization_details");
  });

  // The wire half of the independent review's finding 4. Core's own table
  // (`selection-malformed-json.test.ts`) proves validation returns a typed
  // failure instead of throwing; this proves what that is worth at the
  // boundary — a 400 with an RFC 9396 code, not the 500 a thrown TypeError
  // produced. The distinction matters to a client, which cannot retry its way
  // out of a 500 and cannot tell it from a broken server.
  it.each([
    ["minimum.time_range: null", { minimum: { time_range: null } }],
    ["fields: null", { fields: null }],
    ["resources: null", { resources: null }],
    ["time_range: null", { time_range: null }],
    ["minimum: an array", { minimum: [] }],
    ["fields: a string", { fields: "date" }],
  ])("answers 400, not 500, for %s in the body", async (_label, override) => {
    const created = await post("/pdpp/v1/authorize", v02Body(override));
    expect(created.status).toBe(400);
    const body = (await created.json()) as { error: string };
    expect(["invalid_request", "invalid_authorization_details"]).toContain(
      body.error,
    );
  });

  it("answers 400 for a malformed streams container", async () => {
    const malformed = v02Body();
    (malformed.authorization_details[0] as Record<string, unknown>).streams = [
      null,
    ];
    const created = await post("/pdpp/v1/authorize", malformed);
    expect(created.status).toBe(400);
  });

  it("shows the owner the ceiling, the floor, and each stream's necessity", async () => {
    const { response } = await review();
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      review: {
        data: {
          streams: Array<{
            name: string;
            fields: string[];
            necessity?: string;
            requested_fields?: string[];
            minimum?: { fields?: string[] };
          }>;
        };
      };
    };
    const transactions = body.review.data.streams.find(
      (s) => s.name === "transactions",
    )!;
    expect(transactions.necessity).toBe("required");
    expect(transactions.requested_fields).toEqual([
      "date",
      "amount",
      "merchant",
    ]);
    expect(transactions.minimum?.fields).toEqual(["date", "amount"]);

    const profile = body.review.data.streams.find((s) => s.name === "profile")!;
    expect(profile.necessity).toBe("optional");
  });

  it("does not add a schema-required field to the reviewed projection", async () => {
    // `private_note` is in `required_fields` and was not requested. Under
    // v0.1 the owner would have been shown it as unavoidable.
    const { response } = await review();
    const body = (await response.json()) as {
      review: { data: { streams: Array<{ name: string; fields: string[] }> } };
    };
    const transactions = body.review.data.streams.find(
      (s) => s.name === "transactions",
    )!;
    expect(transactions.fields).not.toContain("private_note");
  });
});

describe("the owner's narrowing survives the wire", () => {
  it("applies field, window, and decline choices from the query string", async () => {
    const { response } = await review(
      "?field[transactions]=date&field[transactions]=amount" +
        `&since[transactions]=${Q4.since}&until[transactions]=${Q4.until}` +
        "&decline[profile]=1",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      review: {
        data: {
          streams: Array<{
            name: string;
            fields: string[];
            time_constraint?: { since?: string; until?: string };
          }>;
          omitted_streams?: string[];
        };
      };
    };
    expect(body.review.data.streams.map((s) => s.name)).toEqual([
      "transactions",
    ]);
    expect(body.review.data.streams[0].fields).toEqual(["date", "amount"]);
    expect(body.review.data.streams[0].time_constraint?.since).toBe(Q4.since);
    // The declined stream stays visible as declined rather than vanishing.
    expect(body.review.data.omitted_streams).toEqual(["profile"]);
  });

  it("refuses a narrowing below a required minimum with 403 access_denied", async () => {
    const { response } = await review("?field[transactions]=date");
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("refuses declining a required stream with 403 access_denied", async () => {
    const { response } = await review("?decline[transactions]=1");
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toBe("access_denied");
  });

  it("clamps a narrowing that tries to widen past the request", async () => {
    const { response } = await review(
      "?since[transactions]=2019-01-01T00:00:00Z",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      review: {
        data: {
          streams: Array<{ time_constraint?: { since?: string } }>;
        };
      };
    };
    expect(body.review.data.streams[0].time_constraint?.since).toBe(YEAR.since);
  });
});

describe("the narrowed grant reaches the client", () => {
  it("issues and returns the complete narrowed grant", async () => {
    const narrowing =
      "?field[transactions]=date&field[transactions]=amount" +
      `&since[transactions]=${Q4.since}&until[transactions]=${Q4.until}` +
      "&decline[profile]=1";
    const { sessionId, ownerToken, response } = await review(narrowing);
    const reviewed = (await response.json()) as {
      review: { review_digest: string };
    };

    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      {
        review_digest: reviewed.review.review_digest,
        // The approval carries the same narrowing the review was rendered
        // with. A different one re-derives a different digest and fails.
        owner_choices: {
          fields: { transactions: ["date", "amount"] },
          time_ranges: { transactions: Q4 },
          declined_streams: ["profile"],
        },
      },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(200);
    const { redirect_uri } = (await approved.json()) as {
      redirect_uri: string;
    };
    const code = new URL(redirect_uri).searchParams.get("code")!;

    const redeemed = await postForm("/pdpp/v1/token", {
      grant_type: "authorization_code",
      code,
      client_id: "budget_example",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    });
    expect(redeemed.status).toBe(200);
    const issued = (await redeemed.json()) as {
      access_token: string;
      authorization_details: Array<{ type: string; grant: Grant }>;
    };

    const [entry] = issued.authorization_details;
    expect(entry.type).toBe(PDPP_DATA_ACCESS_TYPE_V02);
    expect(entry.grant.version).toBe(PDPP_GRANT_VERSION_V02);

    // Approved: the narrowed shape only.
    expect(entry.grant.streams).toHaveLength(1);
    expect(entry.grant.streams[0].fields).toEqual(["date", "amount"]);
    expect(entry.grant.streams[0].time_constraint).toEqual({
      field: "date",
      ...Q4,
    });

    // Requested: the ceiling, so the client can see what the owner removed.
    expect(entry.grant.requested?.streams[0].fields).toEqual([
      "date",
      "amount",
      "merchant",
    ]);
    expect(entry.grant.requested?.omitted_streams).toEqual(["profile"]);

    // Commitments travel as first-class grant members.
    expect(entry.grant.retention).toEqual({
      max_duration: "P30D",
      on_expiry: "delete",
    });
    expect(entry.grant.purpose_code).toBe(
      "https://apps.example.com/purposes/budget",
    );
  });

  it("rejects an approval whose narrowing is not the reviewed one", async () => {
    // The owner reviewed the unnarrowed request; the approval claims a
    // narrowing. 409 stale_review, so the UI re-fetches rather than issuing.
    const { sessionId, ownerToken, response } = await review();
    const reviewed = (await response.json()) as {
      review: { review_digest: string };
    };

    const approved = await post(
      `/pdpp/v1/authorize/${sessionId}/approve`,
      {
        review_digest: reviewed.review.review_digest,
        owner_choices: { fields: { transactions: ["date", "amount"] } },
      },
      ownerAuth(ownerToken),
    );
    expect(approved.status).toBe(409);
    const body = (await approved.json()) as { error: string };
    expect(body.error).toBe("stale_review");
  });
});

describe("recipient commitments over the wire", () => {
  it("refuses an owner condition outside recipient authority with 409", async () => {
    const { response } = await review(
      "?retention_max_duration=P7D&retention_on_expiry=delete",
    );
    expect(response.status).toBe(409);
    const body = (await response.json()) as { error: string };
    expect(body.error).toBe("invalid_authorization_details");
  });

  it("accepts an owner condition the recipient's standing terms cover", async () => {
    standingTerms = {
      id: "https://apps.example.com/terms/data-handling",
      version: "2026-08-01",
      accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
    };
    const { response } = await review(
      "?retention_max_duration=P7D&retention_on_expiry=delete",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      review: { policy: { retention?: { max_duration: string } } };
    };
    // The owner sees their own covered condition, not the client's ask.
    expect(body.review.policy.retention?.max_duration).toBe("P7D");
  });
});
