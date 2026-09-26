/**
 * The owner's optional reason for denying is retained, and goes no further.
 *
 * A consent surface must not offer a box whose contents are discarded. That is
 * the same defect as presenting an optional selection as compulsory, seen from
 * the other side: a control is offered, the owner uses it, and nothing the
 * owner did survives. So the reason has a real destination before the textarea
 * exists on the screen.
 *
 * It stops at the session. The OAuth binding answers a denial with
 * `access_denied` and nothing else, so forwarding a reason to the requester
 * would turn an optional courtesy into a disclosure the owner never intended —
 * "I don't trust this company" is not something a refusal should leak back to
 * the company.
 */

import { describe, expect, it } from "vitest";
import { AuthorizationSessionStore, denyAuthorization } from "./approval.js";
import { PdppTokenService } from "./tokens.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";
import { openPdppAuthStore } from "./store.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
      primary_key: ["id"],
    },
  ],
};

const request: SelectionRequest = {
  type: PDPP_DATA_ACCESS_TYPE,
  source: { id: snapshot.source_id },
  purpose_code: "https://pdpp.dev/purpose/personalization",
  access_mode: "single_use",
  streams: [{ name: "top_artists" }],
};

function harness() {
  const dir = mkdtempSync(join(tmpdir(), "pdpp-deny-"));
  const store = openPdppAuthStore(join(dir, "pdpp.sqlite"));
  const tokens = new PdppTokenService(store);
  const sessions = new AuthorizationSessionStore();
  const session = sessions.create({
    subjectId: "user_abc123",
    request,
    snapshot,
    requester: {
      client_id: "music_recommendations",
      display_name: "Concert Finder",
      app_approved: false,
    },
    redirectUri: "https://app.example/callback",
  });
  const ownerToken = tokens.issueOwnerToken({ subjectId: "user_abc123" });
  return {
    sessions,
    tokens,
    session,
    ownerToken: ownerToken.access_token,
    cleanup: () => {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

describe("denyAuthorization retains the owner's reason", () => {
  it("keeps the reason on the denied session", () => {
    const h = harness();
    try {
      const result = denyAuthorization({
        sessions: h.sessions,
        tokens: h.tokens,
        sessionId: h.session.session_id,
        ownerToken: h.ownerToken,
        reason: "I did not ask this app for my data",
      });

      expect(result.ok).toBe(true);
      const after = h.sessions.get(h.session.session_id);
      expect(after?.status).toBe("denied");
      expect(after?.denial_reason).toBe("I did not ask this app for my data");
    } finally {
      h.cleanup();
    }
  });

  it("denies successfully with no reason at all", () => {
    const h = harness();
    try {
      // Refusing is the safe outcome and must never depend on the owner
      // explaining themselves.
      const result = denyAuthorization({
        sessions: h.sessions,
        tokens: h.tokens,
        sessionId: h.session.session_id,
        ownerToken: h.ownerToken,
      });

      expect(result.ok).toBe(true);
      expect(h.sessions.get(h.session.session_id)?.status).toBe("denied");
      expect(
        h.sessions.get(h.session.session_id)?.denial_reason,
      ).toBeUndefined();
    } finally {
      h.cleanup();
    }
  });

  it("treats a whitespace-only reason as no reason", () => {
    const h = harness();
    try {
      denyAuthorization({
        sessions: h.sessions,
        tokens: h.tokens,
        sessionId: h.session.session_id,
        ownerToken: h.ownerToken,
        reason: "   \n  ",
      });

      // Retaining "" would make a denial look annotated when it was not.
      expect(
        h.sessions.get(h.session.session_id)?.denial_reason,
      ).toBeUndefined();
    } finally {
      h.cleanup();
    }
  });

  it("does not retain a reason when the denial itself failed", () => {
    const h = harness();
    try {
      const result = denyAuthorization({
        sessions: h.sessions,
        tokens: h.tokens,
        sessionId: h.session.session_id,
        ownerToken: "not-an-owner-token",
        reason: "should not be kept",
      });

      expect(result.ok).toBe(false);
      // An unauthenticated caller must not be able to write to a session it
      // could not act on.
      expect(
        h.sessions.get(h.session.session_id)?.denial_reason,
      ).toBeUndefined();
      expect(h.sessions.get(h.session.session_id)?.status).toBe("pending");
    } finally {
      h.cleanup();
    }
  });
});
