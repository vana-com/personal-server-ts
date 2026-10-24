/**
 * `insertGrantWithAuthCode` atomicity.
 *
 * A grant and its authorization code must land together or not at all: a
 * grant with no redeemable code is stranded, and a caller retrying after a
 * failed write must find no partial state left behind.
 */

import { mkdtempSync, rmSync } from "node:fs";
import Database from "better-sqlite3";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import type { Grant } from "./types.js";
import { parseDeclaration } from "./declaration.js";
import { computeGrantArtifactDigest, computeReviewDigest } from "./review.js";

let dir: string;
let store: PdppAuthStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pdpp-store-"));
  store = openPdppAuthStore(join(dir, "auth.db"));
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function grantFixture(overrides: Partial<Grant> = {}): Grant {
  return {
    version: "0.1.0",
    grant_id: "grant_abc",
    subject: { id: "user_1" },
    client: { client_id: "client_1" },
    source: {
      kind: "connector",
      id: "https://registry.pdpp.dev/connectors/spotify",
    },
    source_declaration: { version: "2026-08-11" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [],
    issued_at: new Date().toISOString(),
    ...overrides,
  };
}

function insertApprovedGrant(): Grant {
  const grant = grantFixture({
    streams: [
      {
        name: "top_artists",
        instance_ids: ["instance_1"],
        fields: ["id", "name"],
      },
    ],
  });
  const document = JSON.stringify({
    source_id: grant.source.id,
    source_kind: grant.source.kind,
    version: grant.source_declaration.version,
    streams: [
      {
        name: "top_artists",
        fields: ["id", "name"],
        required_fields: ["id"],
        primary_key: ["id"],
      },
    ],
  });
  const parsed = parseDeclaration(document, grant.source.id);
  if (!parsed.ok) throw new Error("invalid test declaration");
  store.retainDeclaration(parsed.snapshot, document);
  const reviewDigest = computeReviewDigest({
    subject_id: grant.subject.id,
    client_id: grant.client.client_id,
    source_id: grant.source.id,
    source_kind: grant.source.kind,
    source_declaration_version: grant.source_declaration.version,
    declaration_digest: parsed.snapshot.digest,
    purpose_code: grant.purpose_code,
    access_mode: grant.access_mode,
    streams: grant.streams,
  });
  store.insertGrant({
    grant,
    subjectId: grant.subject.id,
    reviewDigest,
    consentEvidence: {
      review_digest: reviewDigest,
      grant_digest: computeGrantArtifactDigest(grant),
      approved_at: new Date().toISOString(),
      declaration: {
        source_id: grant.source.id,
        version: grant.source_declaration.version,
        digest: parsed.snapshot.digest,
      },
    },
  });
  return grant;
}

describe("insertGrantWithAuthCode", () => {
  it("persists both the grant and the code together", () => {
    const grant = grantFixture();
    store.insertGrantWithAuthCode({
      grant,
      subjectId: "user_1",
      reviewDigest: "d".repeat(64),
      code: "pdpp_code_ok",
      authCode: {
        grantId: grant.grant_id,
        clientId: "client_1",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: null,
        codeChallengeMethod: null,
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      },
    });

    expect(store.getGrant(grant.grant_id)).not.toBeNull();
    expect(store.consumeAuthCode("pdpp_code_ok")).not.toBeNull();
  });

  it("rolls back the grant when the auth-code insert fails, leaving nothing durable", () => {
    const grant = grantFixture();
    const authCode = {
      grantId: grant.grant_id,
      clientId: "client_1",
      redirectUri: "https://app.example.com/callback",
      codeChallenge: null,
      codeChallengeMethod: null,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    // Pre-insert an unrelated grant and a code pointing at it, so the code
    // value is already taken. The transaction's own insertAuthCode call then
    // hits a real PRIMARY KEY (code_hash) violation — a genuine SQLite-level
    // failure, not a mocked throw.
    const priorGrant = grantFixture({ grant_id: "grant_prior" });
    store.insertGrant({
      grant: priorGrant,
      subjectId: "user_1",
      reviewDigest: "e".repeat(64),
    });
    store.insertAuthCode("pdpp_code_collide", {
      ...authCode,
      grantId: priorGrant.grant_id,
    });

    expect(() =>
      store.insertGrantWithAuthCode({
        grant,
        subjectId: "user_1",
        reviewDigest: "d".repeat(64),
        code: "pdpp_code_collide",
        authCode,
      }),
    ).toThrow();

    // The grant must not have survived the failed transaction — otherwise a
    // grant exists with no code a caller could ever redeem for it.
    expect(store.getGrant(grant.grant_id)).toBeNull();
    expect(store.getGrant(priorGrant.grant_id)).not.toBeNull();
    expect(store.consumeAuthCode("pdpp_code_collide")?.grantId).toBe(
      priorGrant.grant_id,
    );
  });
});

describe("validated persisted grants", () => {
  it("loads a valid v0.1.0 grant bound to its declaration and approved artifact", () => {
    const grant = insertApprovedGrant();
    const validated = store.getValidatedGrant(grant.grant_id);
    expect(validated?.grant).toEqual(grant);
    expect(validated?.declarationSnapshot.version).toBe(
      grant.source_declaration.version,
    );
  });

  it("retains vA facts when a later declaration vB is present", () => {
    const grant = insertApprovedGrant();
    const document = JSON.stringify({
      source_id: grant.source.id,
      source_kind: grant.source.kind,
      version: "2026-09-01",
      streams: [
        {
          name: "top_artists",
          fields: ["id", "name", "genre"],
          required_fields: ["id", "genre"],
          primary_key: ["id", "name"],
        },
      ],
    });
    const parsed = parseDeclaration(document, grant.source.id);
    if (!parsed.ok) throw new Error("invalid vB test declaration");
    store.retainDeclaration(parsed.snapshot, document);

    const validated = store.getValidatedGrant(grant.grant_id);
    expect(validated?.declarationSnapshot.version).toBe("2026-08-11");
    expect(validated?.declarationSnapshot.streams[0]?.primary_key).toEqual([
      "id",
    ]);
  });

  it.each([
    [
      "unsupported major version",
      (grant: Record<string, unknown>) => {
        grant.version = "9.0.0";
      },
    ],
    [
      "changed approved fields",
      (grant: Record<string, unknown>) => {
        const streams = grant.streams as Record<string, unknown>[];
        streams[0]!.fields = ["id", "name", "secret"];
      },
    ],
    [
      "changed client identity",
      (grant: Record<string, unknown>) => {
        (grant.client as Record<string, unknown>).client_id = "other_client";
      },
    ],
    [
      "changed source identity",
      (grant: Record<string, unknown>) => {
        (grant.source as Record<string, unknown>).id = "other_source";
      },
    ],
    [
      "changed indexed expiry",
      (grant: Record<string, unknown>) => {
        grant.expires_at = "2027-01-01T00:00:00Z";
      },
    ],
    [
      "missing required members",
      (grant: Record<string, unknown>) => {
        delete grant.source_declaration;
      },
    ],
    [
      "duplicate fields",
      (grant: Record<string, unknown>) => {
        const streams = grant.streams as Record<string, unknown>[];
        streams[0]!.fields = ["id", "id"];
      },
    ],
    [
      "invalid temporal shape",
      (grant: Record<string, unknown>) => {
        const streams = grant.streams as Record<string, unknown>[];
        streams[0]!.time_constraint = {
          field: "created_at",
          since: "2027-01-01T00:00:00Z",
          until: "2026-01-01T00:00:00Z",
        };
      },
    ],
  ])("refuses %s as a token grant", (_name, mutate) => {
    const grant = insertApprovedGrant();
    const db = new Database(join(dir, "auth.db"));
    const raw = JSON.parse(
      db
        .prepare("SELECT grant_json FROM pdpp_grants WHERE grant_id = ?")
        .get(grant.grant_id)?.grant_json as string,
    ) as Record<string, unknown>;
    mutate(raw);
    db.prepare("UPDATE pdpp_grants SET grant_json = ? WHERE grant_id = ?").run(
      JSON.stringify(raw),
      grant.grant_id,
    );
    db.close();

    expect(store.getValidatedGrant(grant.grant_id)).toBeNull();
  });

  it("refuses a grant when its retained declaration artifact is missing", () => {
    const grant = insertApprovedGrant();
    const db = new Database(join(dir, "auth.db"));
    db.prepare(
      "DELETE FROM pdpp_declarations WHERE source_id = ? AND version = ?",
    ).run(grant.source.id, grant.source_declaration.version);
    db.close();
    expect(store.getValidatedGrant(grant.grant_id)).toBeNull();
  });
});

describe("client access-token expiration", () => {
  it.each([null, "not-a-date", "Infinity"])(
    "rejects nonfinite expiration %s before persistence",
    (expiresAt) => {
      expect(() =>
        store.issueAccessToken({
          token: "invalid-expiry",
          grantId: null,
          subjectId: "user_1",
          clientId: "client_1",
          tokenKind: "client",
          expiresAt,
          consumeSingleUse: false,
        }),
      ).toThrow(/finite expiration/);
      expect(store.getAccessToken("invalid-expiry")).toBeNull();
    },
  );
});
