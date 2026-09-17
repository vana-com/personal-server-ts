/**
 * Oracles for the consent review model, the binding digest, and requester
 * identity resolution (§6 rendering obligations, §7 approval binding, §9 AS
 * items 6, 7, 14, 15).
 */

import { describe, expect, it } from "vitest";
import {
  buildConsentReview,
  isRegisteredPurposeCode,
  normalizeClientClaims,
  type RequesterIdentity,
} from "./review.js";
import {
  mayRenderRemoteLogo,
  resolveRequesterIdentity,
  verifyClientIdDocument,
} from "./client-metadata.js";
import { openPdppAuthStore, UnsupportedAuthStateError } from "./store.js";
import {
  AI_TRAINING_PURPOSE,
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamGrant,
} from "./types.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

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

const requester: RequesterIdentity = {
  client_id: "music_recommendations",
  display_name: "Concert Finder",
  app_approved: false,
};

const resolvedStreams: StreamGrant[] = [
  {
    name: "top_artists",
    instance_ids: ["spotify-account-a"],
    fields: ["id", "name"],
  },
];

function request(overrides: Partial<SelectionRequest> = {}): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: snapshot.source_id },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [{ name: "top_artists" }],
    ...overrides,
  };
}

function review(overrides: Partial<SelectionRequest> = {}) {
  return buildConsentReview({
    subjectId: "user_abc123",
    request: request(overrides),
    snapshot,
    resolvedStreams,
    requester,
  });
}

describe("§6 / §9 AS item 7 — four distinct consent categories", () => {
  it("keeps requester, data, policy, and client claims separate", () => {
    const model = review({
      client_claims: {
        commitments: ["Data used only for concert recommendations"],
      },
    });
    expect(model.requester.client_id).toBe("music_recommendations");
    expect(model.data.streams).toHaveLength(1);
    expect(model.policy.purpose_code).toBe(
      "https://pdpp.dev/purpose/personalization",
    );
    expect(model.client_claims?.commitments).toEqual([
      "Data used only for concert recommendations",
    ]);
  });

  it("attributes client claims to the client", () => {
    // §6: rendered as "[client name] says:", never as a server term.
    const model = review({ client_claims: { commitments: ["We are lovely"] } });
    expect(model.client_claims?.attributed_to).toBe("Concert Finder");
  });

  it("omits the claims category entirely when none were made", () => {
    expect(review().client_claims).toBeUndefined();
  });

  it("normalizes claims before binding", () => {
    expect(
      normalizeClientClaims({ commitments: ["  a   b  ", "", "  "] }),
    ).toEqual(["a b"]);
    expect(normalizeClientClaims({ commitments: [] })).toBeUndefined();
    expect(normalizeClientClaims(undefined)).toBeUndefined();
  });
});

describe("§9 AS item 6 — unregistered purpose codes render, never reject", () => {
  it("flags an unregistered code for display without failing", () => {
    const model = review({
      purpose_code: "https://vendor.example/purpose/custom",
    });
    expect(model.policy.purpose_unregistered).toBe(true);
    expect(model.policy.purpose_code).toBe(
      "https://vendor.example/purpose/custom",
    );
  });

  it("does not flag a registered code", () => {
    expect(review().policy.purpose_unregistered).toBe(false);
    expect(
      isRegisteredPurposeCode("https://pdpp.dev/purpose/personalization"),
    ).toBe(true);
    expect(isRegisteredPurposeCode("https://vendor.example/x")).toBe(false);
  });

  it("carries purpose_description through for display", () => {
    const model = review({
      purpose_code: "https://vendor.example/purpose/custom",
      purpose_description: "Recommend concerts",
    });
    expect(model.policy.purpose_description).toBe("Recommend concerts");
  });
});

describe("§6 / §9 AS item 14 — AI training flag surfaces on the review", () => {
  it("marks the mandatory consent requirement", () => {
    expect(
      review({ purpose_code: AI_TRAINING_PURPOSE }).policy
        .requires_explicit_ai_training_consent,
    ).toBe(true);
  });

  it("does not mark it for other purposes", () => {
    expect(review().policy.requires_explicit_ai_training_consent).toBe(false);
  });
});

describe("§7 — the review digest binds the decision fields", () => {
  it("is stable for an identical decision", () => {
    expect(review().review_digest).toBe(review().review_digest);
  });

  it("changes when a resolved field list changes", () => {
    const narrow = buildConsentReview({
      subjectId: "user_abc123",
      request: request(),
      snapshot,
      resolvedStreams,
      requester,
    });
    const wide = buildConsentReview({
      subjectId: "user_abc123",
      request: request(),
      snapshot,
      resolvedStreams: [
        { ...resolvedStreams[0], fields: ["id", "name", "genres"] },
      ],
      requester,
    });
    expect(narrow.review_digest).not.toBe(wide.review_digest);
  });

  it("changes when the resolved instance changes", () => {
    const other = buildConsentReview({
      subjectId: "user_abc123",
      request: request(),
      snapshot,
      resolvedStreams: [
        { ...resolvedStreams[0], instance_ids: ["spotify-account-b"] },
      ],
      requester,
    });
    expect(other.review_digest).not.toBe(review().review_digest);
  });

  it("changes when the declaration snapshot changes", () => {
    // The declaration digest is inside the review digest, so a re-fetched or
    // edited declaration is by construction a stale review.
    const newer = buildConsentReview({
      subjectId: "user_abc123",
      request: request(),
      snapshot: { ...snapshot, version: "2026-09-01", digest: "e".repeat(64) },
      resolvedStreams,
      requester,
    });
    expect(newer.review_digest).not.toBe(review().review_digest);
  });

  it("changes when client claims change", () => {
    const a = review({ client_claims: { commitments: ["one"] } });
    const b = review({ client_claims: { commitments: ["two"] } });
    expect(a.review_digest).not.toBe(b.review_digest);
  });

  it("is insensitive to claim whitespace, because claims are normalized first", () => {
    const a = review({ client_claims: { commitments: ["a b"] } });
    const b = review({ client_claims: { commitments: ["  a   b "] } });
    expect(a.review_digest).toBe(b.review_digest);
  });

  it("changes when the subject changes", () => {
    const other = buildConsentReview({
      subjectId: "user_someone_else",
      request: request(),
      snapshot,
      resolvedStreams,
      requester,
    });
    expect(other.review_digest).not.toBe(review().review_digest);
  });
});

describe("§6 — requester identity precedence and trust signals", () => {
  const inline = { name: "Inline Name" };
  const registeredDisplay = { name: "Registered Name" };
  const docDisplay = { name: "Document Name" };

  it("prefers local registration over everything else", () => {
    const identity = resolveRequesterIdentity({
      client_id: "https://app.example.com/id",
      registered: {
        client_id: "https://app.example.com/id",
        display: registeredDisplay,
        approved: true,
      },
      document: {
        retrieved_from: "https://app.example.com/id",
        client_id: "https://app.example.com/id",
        display: docDisplay,
        https: true,
      },
      inline,
    });
    expect(identity.display_name).toBe("Registered Name");
    expect(identity.app_approved).toBe(true);
  });

  it("prefers a validated document over inline client_display", () => {
    const identity = resolveRequesterIdentity({
      client_id: "https://app.example.com/id",
      document: {
        retrieved_from: "https://app.example.com/id",
        client_id: "https://app.example.com/id",
        display: docDisplay,
        https: true,
      },
      inline,
    });
    expect(identity.display_name).toBe("Document Name");
  });

  it("falls back to inline, then to client_id", () => {
    expect(
      resolveRequesterIdentity({ client_id: "abc", inline }).display_name,
    ).toBe("Inline Name");
    // §6 obligation 2: with no name available, display client_id.
    expect(resolveRequesterIdentity({ client_id: "abc" }).display_name).toBe(
      "abc",
    );
  });

  it("verifies domain control only when the document self-identifies consistently", () => {
    expect(
      verifyClientIdDocument({
        retrieved_from: "https://app.example.com/id",
        client_id: "https://app.example.com/id",
        display: docDisplay,
        https: true,
      }),
    ).toEqual({ verifiedDomain: "app.example.com" });
  });

  it("rejects a document claiming to be a different client", () => {
    // The check that stops a document impersonating another client.
    expect(
      verifyClientIdDocument({
        retrieved_from: "https://app.example.com/id",
        client_id: "https://victim.example.com/id",
        display: docDisplay,
        https: true,
      }),
    ).toBeNull();
  });

  it("rejects a document not retrieved over HTTPS", () => {
    expect(
      verifyClientIdDocument({
        retrieved_from: "http://app.example.com/id",
        client_id: "http://app.example.com/id",
        display: docDisplay,
        https: false,
      }),
    ).toBeNull();
  });

  it("keeps verified domain control distinct from app approval", () => {
    // §6 obligation 5: domain control is NOT an assertion about conduct, and
    // must never be rendered as an unqualified "verified app".
    const identity = resolveRequesterIdentity({
      client_id: "https://app.example.com/id",
      document: {
        retrieved_from: "https://app.example.com/id",
        client_id: "https://app.example.com/id",
        display: docDisplay,
        https: true,
      },
    });
    expect(identity.verified_domain).toBe("app.example.com");
    expect(identity.app_approved).toBe(false);
  });

  it("does not verify an unregistered client with no document", () => {
    const identity = resolveRequesterIdentity({ client_id: "abc", inline });
    expect(identity.verified_domain).toBeUndefined();
    expect(identity.app_approved).toBe(false);
  });

  it("refuses to render a remote logo for an unverified client", () => {
    // §6 obligation 6: logo_uri is untrusted content until accepted by policy.
    const unverified = resolveRequesterIdentity({ client_id: "abc", inline });
    expect(mayRenderRemoteLogo(unverified)).toBe(false);
    expect(
      mayRenderRemoteLogo(unverified, { assetProxiedAndApproved: true }),
    ).toBe(true);

    const verified = resolveRequesterIdentity({
      client_id: "https://app.example.com/id",
      document: {
        retrieved_from: "https://app.example.com/id",
        client_id: "https://app.example.com/id",
        display: docDisplay,
        https: true,
      },
    });
    expect(mayRenderRemoteLogo(verified)).toBe(true);
  });
});

describe("§7 / §9 AS item 21 — unsupported persisted state is rejected", () => {
  it("refuses to open a store whose version it cannot validate", () => {
    // The AS must not reconstruct missing authorization facts from current
    // configuration; it fails loudly and requires migration or fresh consent.
    const dir = mkdtempSync(join(tmpdir(), "pdpp-state-"));
    const dbPath = join(dir, "auth.db");
    try {
      const store = openPdppAuthStore(dbPath);
      store.close();

      // Simulate state written by a future, unknown contract version.
      const raw = new Database(dbPath);
      raw
        .prepare("UPDATE pdpp_state_meta SET version = 999 WHERE id = 1")
        .run();
      raw.close();

      expect(() => openPdppAuthStore(dbPath)).toThrow(
        UnsupportedAuthStateError,
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
