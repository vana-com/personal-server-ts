/**
 * The v0.2 query journey, end to end: real AS, real token, real RS read.
 *
 * Inventory rows `v0.2-4-1`, `v0.2-4-2`, `v0.2-4-3`, `v0.2-2-1`, `v0.2-2-2`,
 * `v0.2-2-3`, `v0.2-8.4-*`. Batch 3 exit evidence: "Black-box record,
 * metadata, filter/expand rejection, revocation, and empty-result journeys
 * pass."
 *
 * ## Why this exists when the unit suites already pass
 *
 * The projection suites feed the RS a hand-written grant. That proves the RS
 * enforces the grant it is given; it cannot prove the grant it is given is
 * the one the owner approved. Those are different claims, and the gap between
 * them is exactly where this defect lived: the AS was already resolving a
 * v0.2 grant WITHOUT the schema-required field the owner never saw, and the
 * RS was adding it back from the declaration at read time. Both components
 * passed their own tests. The owner's decision still did not survive the trip.
 *
 * So this drives the real thing: POST /authorize, the owner's narrowing in
 * the review query string, an approval bound to that review's digest, a token
 * exchange, and then reads through the RS with the token that came out. The
 * declaration is one snapshot shared by both halves, because a journey where
 * each half gets its own fixture would prove nothing about the seam between
 * them.
 *
 * `private_note` is the load-bearing detail: it is in the declaration's
 * `required_fields`, it is not in the client's request, and the owner is
 * never shown it. Under v0.1 it was disclosed on every read anyway. If it
 * appears in a response body here, the owner's consent was not enforced.
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
  PdppTokenService,
  type DeclarationSnapshot,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type {
  Grant,
  PdppAuthorizationService,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppAuthRoutes } from "./routes/pdpp-auth.js";
import { pdppRecordsRoutes } from "./routes/pdpp-records.js";

const logger = pino({ level: "silent" });
const OWNER = "user_abc123";
const REDIRECT = "https://app.example.com/callback";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const INSTANCE = "account_example";

const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const Q4 = { since: "2025-10-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };

/** ONE declaration, shared by the AS and the RS. See the header comment. */
const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "d".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant", "private_note"],
      // `private_note` is schema-required and never requested. Under v0.1 it
      // rode along on every read; under v0.2 it must not.
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

/** The same snapshot, projected onto what the RS enforces. */
const declarations = createStreamDeclarationRegistry(
  snapshot.streams.map((s) => ({
    name: s.name,
    semantics: "mutable_state" as const,
    primaryKey: s.primary_key,
    cursorField: "emitted_at",
    consentTimeField: s.consent_time_field,
    requiredFields: s.required_fields,
    declaredFields: s.fields,
  })),
);

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;
let as: Hono;
let records: PdppRecordStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-v02-journey-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);

  as = new Hono();
  as.route(
    "/pdpp/v1",
    pdppAuthRoutes({
      logger,
      store,
      tokens,
      sessions: new AuthorizationSessionStore(),
      resolveDeclaration: (sourceId) =>
        sourceId === snapshot.source_id ? snapshot : null,
      inventoryFor: () => ({ eligibleFor: () => [INSTANCE] }),
      currentSubjectId: (_c: Context) => OWNER,
      registeredClient: (clientId) =>
        clientId === "budget_example"
          ? { client_id: clientId, redirect_uris: [REDIRECT] }
          : null,
      standingTermsFor: () => null,
    }),
  );

  records = createMemoryRecordStore();
  records.ingestBatch(
    [
      {
        instance: INSTANCE,
        stream: "transactions",
        key: "2025-11-04T00:00:00Z",
        data: {
          date: "2025-11-04T00:00:00Z",
          amount: 42,
          merchant: "acme",
          private_note: "SENTINEL_NEVER_APPROVED",
        },
        emitted_at: "2025-11-04T00:00:00Z",
        op: "upsert",
      },
      {
        // Outside the owner's approved Q4 window, so the grant must not
        // disclose it even though the client asked for the whole year.
        instance: INSTANCE,
        stream: "transactions",
        key: "2025-03-02T00:00:00Z",
        data: {
          date: "2025-03-02T00:00:00Z",
          amount: 7,
          merchant: "other",
          private_note: "SENTINEL_NEVER_APPROVED",
        },
        emitted_at: "2025-03-02T00:00:00Z",
        op: "upsert",
      },
    ],
    () => "mutable_state",
    () => ["date"],
  );
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

/**
 * Drive the real authorization journey and return the issued access token
 * plus the grant the client was handed.
 *
 * `narrowing` is the owner's choice, expressed exactly as the consent UI
 * expresses it: in the review query string, and again in the approval, whose
 * digest must match the review it was rendered from.
 */
async function authorize(): Promise<{ accessToken: string; grant: Grant }> {
  const ownerToken = tokens.issueOwnerToken({ subjectId: OWNER }).access_token;

  const created = await as.request("/pdpp/v1/authorize", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
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
            },
            {
              name: "profile",
              necessity: "optional",
              fields: ["id", "display_name"],
            },
          ],
        },
      ],
    }),
  });
  expect(created.status).toBe(201);
  const { session_id } = (await created.json()) as { session_id: string };

  // The owner keeps date+amount, narrows to Q4, and declines `profile`.
  const narrowing =
    "?field[transactions]=date&field[transactions]=amount" +
    `&since[transactions]=${Q4.since}&until[transactions]=${Q4.until}` +
    "&decline[profile]=1";
  const reviewRes = await as.request(
    `/pdpp/v1/authorize/${session_id}/review${narrowing}`,
    { headers: { authorization: `Bearer ${ownerToken}` } },
  );
  expect(reviewRes.status).toBe(200);
  const reviewed = (await reviewRes.json()) as {
    review: { review_digest: string };
  };

  const approved = await as.request(
    `/pdpp/v1/authorize/${session_id}/approve`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${ownerToken}`,
      },
      body: JSON.stringify({
        review_digest: reviewed.review.review_digest,
        owner_choices: {
          fields: { transactions: ["date", "amount"] },
          time_ranges: { transactions: Q4 },
          declined_streams: ["profile"],
        },
      }),
    },
  );
  expect(approved.status).toBe(200);
  const { redirect_uri } = (await approved.json()) as { redirect_uri: string };
  const code = new URL(redirect_uri).searchParams.get("code")!;

  const redeemed = await as.request("/pdpp/v1/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: "budget_example",
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });
  expect(redeemed.status).toBe(200);
  const issued = (await redeemed.json()) as {
    access_token: string;
    authorization_details: Array<{ grant: Grant }>;
  };
  return {
    accessToken: issued.access_token,
    grant: issued.authorization_details[0].grant,
  };
}

/**
 * The RS, resolving each read through the AS's own token service.
 *
 * This is the co-located equivalent of RFC 7662 introspection that `v0.2-2-1`
 * and `v0.2-2-2` require: ONE lookup, and the grant enforcement context comes
 * entirely from its result. It is also what makes revocation observable per
 * `v0.2-2-3` — the token is not self-contained, so a revoked grant denies the
 * next read rather than waiting for expiry.
 */
function rs(): Hono {
  const auth: PdppAuthorizationService = {
    async resolveToken(accessToken) {
      const context = tokens.resolveToken(accessToken);
      if (!context.active) {
        return {
          active: false as const,
          inactiveReason: context.inactiveReason,
        };
      }
      return {
        active: true as const,
        tokenKind: context.tokenKind ?? "client",
        subjectId: context.subjectId ?? "",
        grant: context.grant as Grant | undefined,
        clientId: context.clientId,
        expiresAt: context.expiresAt,
      };
    },
  };
  const app = new Hono();
  app.route(
    "/v1",
    pdppRecordsRoutes({
      store: records,
      auth,
      declarations,
      instancesForSubject: () => [INSTANCE],
    }),
  );
  return app;
}

function bearer(token: string) {
  return { Authorization: `Bearer ${token}` };
}

describe("v0.2 journey: the owner's narrowing is what the client reads", () => {
  it("discloses exactly the approved members, and no schema-required extra", async () => {
    const { accessToken, grant } = await authorize();
    // The grant itself carries the owner's decision...
    expect(grant.streams[0].fields).toEqual(["date", "amount"]);
    expect(grant.streams[0].fields).not.toContain("private_note");

    // ...and so does the record the RS actually serves.
    const res = await rs().request("/v1/streams/transactions/records", {
      headers: bearer(accessToken),
    });
    expect(res.status).toBe(200);
    const raw = await res.text();
    expect(raw).not.toContain("SENTINEL_NEVER_APPROVED");

    const body = JSON.parse(raw) as {
      data: Array<{ data: Record<string, unknown> }>;
    };
    // The owner's Q4 window excluded the March record.
    expect(body.data).toHaveLength(1);
    expect(Object.keys(body.data[0].data).sort()).toEqual(["amount", "date"]);
    // `merchant` was requested by the client but removed by the owner.
    expect(body.data[0].data).not.toHaveProperty("merchant");
  });

  it("discloses the same members on a single-record read", async () => {
    const { accessToken } = await authorize();
    const res = await rs().request(
      `/v1/streams/transactions/records/${encodeURIComponent("2025-11-04T00:00:00Z")}`,
      { headers: bearer(accessToken) },
    );
    expect(res.status).toBe(200);
    const raw = await res.text();
    expect(raw).not.toContain("SENTINEL_NEVER_APPROVED");
    const body = JSON.parse(raw) as { data: Record<string, unknown> };
    expect(Object.keys(body.data).sort()).toEqual(["amount", "date"]);
  });

  it("describes the same shape in stream metadata", async () => {
    const { accessToken } = await authorize();
    const res = await rs().request("/v1/streams/transactions", {
      headers: bearer(accessToken),
    });
    expect(res.status).toBe(200);
    expect(await res.text()).not.toContain("private_note");
  });

  it("does not list the stream the owner declined", async () => {
    const { accessToken } = await authorize();
    const res = await rs().request("/v1/streams", {
      headers: bearer(accessToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Array<{ name: string }> };
    expect(body.data.map((s) => s.name)).toEqual(["transactions"]);
  });

  it("refuses the declined stream's records with 403", async () => {
    const { accessToken } = await authorize();
    const res = await rs().request("/v1/streams/profile/records", {
      headers: bearer(accessToken),
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "grant_stream_not_allowed",
    );
  });

  it("rejects a filter the v0.2 client surface does not carry", async () => {
    const { accessToken } = await authorize();
    const res = await rs().request(
      "/v1/streams/transactions/records?filter[merchant]=acme",
      { headers: bearer(accessToken) },
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "invalid_request",
    );
  });
});

describe("v0.2 journey: revocation and empty results", () => {
  it("denies the next read after the grant is revoked", async () => {
    const { accessToken, grant } = await authorize();
    // Reading works first, so the denial below is attributable to the
    // revocation and not to a journey that never worked.
    expect(
      (
        await rs().request("/v1/streams/transactions/records", {
          headers: bearer(accessToken),
        })
      ).status,
    ).toBe(200);

    store.revokeGrant(grant.grant_id);

    const after = await rs().request("/v1/streams/transactions/records", {
      headers: bearer(accessToken),
    });
    expect(after.status).toBe(403);
    const body = await after.text();
    expect(JSON.parse(body).error.code).toBe("grant_revoked");
    // The refusal discloses nothing the grant used to reach.
    expect(body).not.toContain("SENTINEL_NEVER_APPROVED");
    expect(body).not.toContain("acme");
  });

  it("answers an empty list, not a denial, when the window matches nothing", async () => {
    const { accessToken } = await authorize();
    // Remove the only Q4 record. The grant stays valid and servable; there is
    // simply nothing in it. `v0.2-4-7` sits beside "empty data is not
    // permission denial", so this must stay a 200.
    records.deleteRecord(
      INSTANCE,
      "transactions",
      "2025-11-04T00:00:00Z",
      new Date().toISOString(),
      "mutable_state",
    );
    const res = await rs().request("/v1/streams/transactions/records", {
      headers: bearer(accessToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown[]; has_more: boolean };
    expect(body.data).toEqual([]);
    expect(body.has_more).toBe(false);
  });
});
