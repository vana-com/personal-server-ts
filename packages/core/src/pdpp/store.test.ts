/**
 * `insertGrantWithAuthCode` atomicity.
 *
 * A grant and its authorization code must land together or not at all: a
 * grant with no redeemable code is stranded, and a caller retrying after a
 * failed write must find no partial state left behind.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openPdppAuthStore, type PdppAuthStore } from "./store.js";
import type { Grant } from "./types.js";

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
