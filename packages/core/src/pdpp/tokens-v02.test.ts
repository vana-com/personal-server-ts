/**
 * Oracles for the v0.2 client-visible authorization result.
 *
 * Anchors: PR vana-com/pdpp#1 spec-core.md §7 "Client-visible authorization
 * result" and §8 introspection; the `authorization-disclosure-contract`
 * requirement "Authorization results SHALL be complete and authoritative".
 *
 * The property under test: for a v0.2 grant the result is `{ type, grant }`
 * carrying the *complete* grant — never the original selection request and
 * never a lossy summary. The v0.1 detail shape is exactly such a summary
 * (it drops retention, expiry, the resolved client identity, and the
 * requested-vs-approved record), so v0.2 cannot reuse it. Both shapes coexist:
 * a token over a v0.1 grant still returns the v0.1 detail unchanged.
 *
 * Real SQLite store, not a mock — these assertions are about what a client and
 * an authenticated RS actually receive from the same resolution path.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AUTHORIZATION_CODE_TTL_SECONDS, PdppTokenService } from "./tokens.js";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION,
  PDPP_GRANT_VERSION_V02,
  type Grant,
  type PdppAuthorizationResultV02,
} from "./types.js";

let dir: string;
let store: PdppAuthStore;
let tokens: PdppTokenService;

const Q4 = { since: "2025-10-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };

/** A grant expiry comfortably ahead of any wall clock this test runs under. */
const FUTURE_EXPIRY = new Date(
  Date.now() + 30 * 24 * 60 * 60 * 1000,
).toISOString();

function v02Grant(overrides: Partial<Grant> = {}): Grant {
  return {
    version: PDPP_GRANT_VERSION_V02,
    grant_id: `grt_${Math.random().toString(16).slice(2, 10)}`,
    issued_at: "2026-09-14T20:00:00Z",
    subject: { id: "subject_example" },
    client: {
      client_id: "budget_example",
      client_display: { name: "Budget Example" },
    },
    source: { kind: "provider_native", id: "https://data.example.com/finance" },
    source_declaration: { version: "2026-09-01" },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    retention: { max_duration: "P30D", on_expiry: "delete" },
    // Must be in the future: an expired grant is not redeemable, and these
    // tests are about the *shape* of a successful result.
    expires_at: FUTURE_EXPIRY,
    streams: [
      {
        name: "transactions",
        instance_ids: ["account_example"],
        fields: ["date", "amount"],
        time_constraint: { field: "date", ...Q4 },
      },
    ],
    requested: {
      streams: [
        {
          name: "transactions",
          necessity: "required",
          fields: ["date", "amount", "merchant"],
          time_range: {
            since: "2025-01-01T00:00:00Z",
            until: "2026-01-01T00:00:00Z",
          },
          minimum: { fields: ["date", "amount"], time_range: Q4 },
        },
        {
          name: "profile",
          necessity: "optional",
          fields: ["id", "display_name"],
        },
      ],
      omitted_streams: ["profile"],
    },
    ...overrides,
  };
}

function v01Grant(): Grant {
  return {
    version: PDPP_GRANT_VERSION,
    grant_id: `grt_${Math.random().toString(16).slice(2, 10)}`,
    issued_at: "2026-09-14T20:00:00Z",
    subject: { id: "subject_example" },
    client: { client_id: "budget_example" },
    source: { kind: "provider_native", id: "https://data.example.com/finance" },
    source_declaration: { version: "2026-09-01" },
    purpose_code: "https://pdpp.dev/purpose/portability",
    access_mode: "single_use",
    retention: { max_duration: "P30D", on_expiry: "delete" },
    streams: [
      {
        name: "transactions",
        instance_ids: ["account_example"],
        fields: ["date", "amount"],
      },
    ],
  };
}

function seed(grant: Grant): string {
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
  return code;
}

function redeem(code: string) {
  return tokens.redeemAuthorizationCode({
    code,
    clientId: "budget_example",
    redirectUri: "https://app.example.com/callback",
  });
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-v02-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
  tokens = new PdppTokenService(store);
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("v0.2 token response carries the complete grant", () => {
  it("returns { type, grant } with the v0.2 detail type", () => {
    const grant = v02Grant();
    const result = redeem(seed(grant));
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.issued.authorization_details).toHaveLength(1);
    const entry = result.issued
      .authorization_details[0] as PdppAuthorizationResultV02;
    expect(entry.type).toBe(PDPP_DATA_ACCESS_TYPE_V02);
    expect(entry.grant).toEqual(grant);
  });

  it("includes every field the v0.1 summary would have dropped", () => {
    // These are exactly the members the lossy v0.1 projection omits. Naming
    // them individually is the point: a future refactor that reintroduces a
    // projection fails here rather than silently shipping a summary.
    const grant = v02Grant();
    const result = redeem(seed(grant));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { grant: returned } = result.issued
      .authorization_details[0] as PdppAuthorizationResultV02;

    expect(returned.version).toBe(PDPP_GRANT_VERSION_V02);
    expect(returned.grant_id).toBe(grant.grant_id);
    expect(returned.issued_at).toBe(grant.issued_at);
    expect(returned.subject).toEqual({ id: "subject_example" });
    expect(returned.client.client_display).toEqual({ name: "Budget Example" });
    expect(returned.source_declaration).toEqual({ version: "2026-09-01" });
    expect(returned.retention).toEqual({
      max_duration: "P30D",
      on_expiry: "delete",
    });
    expect(returned.expires_at).toBe(FUTURE_EXPIRY);
  });

  it("exposes the requested-vs-approved record for containment checks", () => {
    // This is what lets a Consent Gateway compute containment against the
    // approved shape rather than against the request it happens to remember.
    const result = redeem(seed(v02Grant()));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { grant } = result.issued
      .authorization_details[0] as PdppAuthorizationResultV02;

    expect(grant.streams[0].fields).toEqual(["date", "amount"]);
    expect(grant.requested?.streams[0].fields).toEqual([
      "date",
      "amount",
      "merchant",
    ]);
    expect(grant.requested?.omitted_streams).toEqual(["profile"]);
    // An omitted stream is not a grant and must not read as authorized.
    expect(grant.streams.map((s) => s.name)).not.toContain("profile");
  });

  it("does not substitute the original selection request", () => {
    // The result is the *grant*, so it carries resolved facts the request
    // never had: concrete instance handles and a frozen time field.
    const result = redeem(seed(v02Grant()));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const { grant } = result.issued
      .authorization_details[0] as PdppAuthorizationResultV02;
    expect(grant.streams[0].instance_ids).toEqual(["account_example"]);
    expect(grant.streams[0].time_constraint?.field).toBe("date");
  });
});

describe("v0.1 results are unchanged", () => {
  it("still returns the v0.1 detail projection for a v0.1 grant", () => {
    const result = redeem(seed(v01Grant()));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const entry = result.issued.authorization_details[0] as unknown as Record<
      string,
      unknown
    >;
    expect(entry.type).toBe(PDPP_DATA_ACCESS_TYPE);
    // The v0.1 shape is a projection, not a grant envelope.
    expect(entry.grant).toBeUndefined();
    expect(entry.streams).toBeDefined();
    // And it still omits the members §6 keeps out of enforcement.
    expect(entry.retention).toBeUndefined();
  });
});

describe("introspection returns the same resolved grant facts", () => {
  it("returns the v0.2 result to an authenticated resource server", () => {
    // v0.2: "the same resolved grant facts to the client and to an
    // authenticated RS, apart from token-specific active-state and expiry".
    const grant = v02Grant({ access_mode: "continuous" });
    const issued = redeem(seed(grant));
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const introspected = tokens.introspect(issued.issued.access_token);
    expect(introspected.active).toBe(true);
    expect(introspected.grant_id).toBe(grant.grant_id);

    const entry = introspected
      .authorization_details?.[0] as PdppAuthorizationResultV02;
    expect(entry.type).toBe(PDPP_DATA_ACCESS_TYPE_V02);
    expect(entry.grant).toEqual(grant);
  });

  it("returns exactly the same entry to the client and to the RS", () => {
    const grant = v02Grant({ access_mode: "continuous" });
    const issued = redeem(seed(grant));
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    const introspected = tokens.introspect(issued.issued.access_token);
    expect(introspected.authorization_details).toEqual(
      issued.issued.authorization_details,
    );
  });

  it("reports an inactive token without leaking the grant", () => {
    const grant = v02Grant({ access_mode: "continuous" });
    const issued = redeem(seed(grant));
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;

    tokens.revokeGrant(grant.grant_id);
    expect(tokens.introspect(issued.issued.access_token)).toEqual({
      active: false,
    });
  });
});
