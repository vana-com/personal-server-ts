/**
 * Oracles for v0.2 grant issuance under owner narrowing.
 *
 * Anchors: PR vana-com/pdpp#1 spec-core.md §7 "Client-visible authorization
 * result" and "Recipient commitments and approval"; the
 * `authorization-disclosure-contract` requirement "Authorization results SHALL
 * be complete and authoritative".
 *
 * Two properties:
 *
 *   1. A v0.2 grant carries `version: "0.2.0"` and the requested-vs-approved
 *      record. Without the second the client cannot tell a narrowed grant
 *      from an unnarrowed one, and §7 forbids it from diffing against its own
 *      memory of the request to find out.
 *   2. The owner's narrowing is inside the review digest. A narrowing the
 *      owner never saw must not be issuable, which means it has to be a
 *      decision field rather than a parameter carried beside the decision.
 */

import { describe, expect, it } from "vitest";
import { issueGrant } from "./issuance.js";
import { buildConsentReview, type RequesterIdentity } from "./review.js";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION,
  PDPP_GRANT_VERSION_V02,
  type DeclarationSnapshot,
  type OwnerChoices,
  type SelectionRequest,
} from "./index.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "a".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant", "private_note"],
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

const inventory: InstanceInventory = {
  eligibleFor: () => ["account_example"],
};

const requester: RequesterIdentity = {
  client_id: "budget_example",
  display_name: "Budget Example",
  app_approved: false,
};

const YEAR = { since: "2025-01-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };
const Q4 = { since: "2025-10-01T00:00:00Z", until: "2026-01-01T00:00:00Z" };

function request(
  type: typeof PDPP_DATA_ACCESS_TYPE | typeof PDPP_DATA_ACCESS_TYPE_V02,
): SelectionRequest {
  return {
    type,
    source: { id: snapshot.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    retention: { max_duration: "P30D", on_expiry: "delete" },
    streams: [
      {
        name: "transactions",
        necessity: "required",
        fields: ["date", "amount", "merchant"],
        time_range: YEAR,
        ...(type === PDPP_DATA_ACCESS_TYPE_V02 && {
          minimum: { fields: ["date", "amount"], time_range: Q4 },
        }),
      },
      {
        name: "profile",
        necessity: "optional",
        fields: ["id", "display_name"],
      },
    ],
  };
}

/** Issue with the digest the owner would actually have been shown. */
function issue(
  selection: SelectionRequest,
  ownerChoices?: OwnerChoices,
  expiresAt?: string,
) {
  const resolution = resolveSelection(
    selection,
    snapshot,
    inventory,
    ownerChoices,
  );
  if (!resolution.ok) throw new Error(`unresolvable: ${resolution.failure.code}`);
  const review = buildConsentReview({
    subjectId: "subject_example",
    request: selection,
    snapshot,
    resolvedStreams: resolution.streams,
    omittedStreams: resolution.omittedStreams,
    requester,
    expiresAt,
  });
  return issueGrant({
    subjectId: "subject_example",
    request: selection,
    snapshot,
    inventory,
    ownerChoices,
    requester,
    approvedReviewDigest: review.review_digest,
    expiresAt,
    now: new Date("2026-09-14T20:00:00Z"),
  });
}

describe("v0.2 grant version and requested-vs-approved record", () => {
  it("issues a 0.2.0 grant for a v0.2 request", () => {
    const result = issue(request(PDPP_DATA_ACCESS_TYPE_V02));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.version).toBe(PDPP_GRANT_VERSION_V02);
  });

  it("still issues a 0.1.0 grant for a v0.1 request", () => {
    const result = issue(request(PDPP_DATA_ACCESS_TYPE));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.version).toBe(PDPP_GRANT_VERSION);
    expect(result.grant.requested).toBeUndefined();
  });

  it("records what was requested beside what was approved", () => {
    const result = issue(request(PDPP_DATA_ACCESS_TYPE_V02), {
      fields: { transactions: ["date", "amount"] },
      time_ranges: { transactions: Q4 },
      declined_streams: ["profile"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Approved: the narrowed shape, and only the retained stream.
    expect(result.grant.streams).toHaveLength(1);
    expect(result.grant.streams[0].fields).toEqual(["date", "amount"]);
    expect(result.grant.streams[0].time_constraint).toEqual({
      field: "date",
      ...Q4,
    });

    // Requested: the original ceiling, so the client can see the narrowing.
    expect(result.grant.requested?.streams).toEqual([
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
    ]);
    expect(result.grant.requested?.omitted_streams).toEqual(["profile"]);
  });

  it("does not list an omitted stream among the authorized streams", () => {
    // An omitted optional stream is not a grant and must never read as
    // authorized. Only `requested.omitted_streams` mentions it.
    const result = issue(request(PDPP_DATA_ACCESS_TYPE_V02), {
      declined_streams: ["profile"],
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.streams.map((s) => s.name)).toEqual(["transactions"]);
  });

  it("omits the omitted_streams member when nothing was dropped", () => {
    const result = issue(request(PDPP_DATA_ACCESS_TYPE_V02));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.requested?.omitted_streams).toBeUndefined();
  });
});

describe("owner narrowing is bound into the approval", () => {
  it("rejects an approval whose narrowing differs from the reviewed one", () => {
    // The owner reviewed the full request; the approval arrives claiming a
    // narrowing. The digest re-derivation catches it, so a narrowing nobody
    // reviewed cannot be issued. (Narrower is still a different decision: it
    // changes what the client receives and what the owner was told.)
    const selection = request(PDPP_DATA_ACCESS_TYPE_V02);
    const reviewed = resolveSelection(selection, snapshot, inventory);
    if (!reviewed.ok) throw new Error("unresolvable");
    const review = buildConsentReview({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      resolvedStreams: reviewed.streams,
      requester,
    });

    const result = issueGrant({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      inventory,
      ownerChoices: { fields: { transactions: ["date", "amount"] } },
      requester,
      approvedReviewDigest: review.review_digest,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("stale_approval");
  });

  it("refuses issuance when a required minimum cannot be met", () => {
    const selection = request(PDPP_DATA_ACCESS_TYPE_V02);
    const result = issueGrant({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      inventory,
      ownerChoices: { fields: { transactions: ["date"] } },
      requester,
      // Any digest: the refusal must precede the staleness check, since a
      // refused selection has no grant to have been reviewed.
      approvedReviewDigest: "irrelevant",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("access_denied");
  });

  it("refuses issuance when the owner declines every stream", () => {
    const selection: SelectionRequest = {
      ...request(PDPP_DATA_ACCESS_TYPE_V02),
      streams: [
        { name: "profile", necessity: "optional", fields: ["id"] },
      ],
    };
    const result = issueGrant({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      inventory,
      ownerChoices: { declined_streams: ["profile"] },
      requester,
      approvedReviewDigest: "irrelevant",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("access_denied");
  });
});

describe("purpose and retention as first-class commitments", () => {
  it("carries the resolved purpose and retention into the grant", () => {
    const result = issue(request(PDPP_DATA_ACCESS_TYPE_V02));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.purpose_code).toBe(
      "https://apps.example.com/purposes/budget",
    );
    expect(result.grant.retention).toEqual({
      max_duration: "P30D",
      on_expiry: "delete",
    });
  });

  it("carries grant expiry into the grant when policy sets one", () => {
    const result = issue(
      request(PDPP_DATA_ACCESS_TYPE_V02),
      undefined,
      "2026-09-15T20:00:00Z",
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.expires_at).toBe("2026-09-15T20:00:00Z");
  });

  it("does not change access_mode as a consequence of narrowing", () => {
    // v0.2 is explicit that grant lifetime and record time scope are separate
    // axes: narrowing the data must not silently downgrade a continuous grant
    // to single-use or the reverse.
    const selection: SelectionRequest = {
      ...request(PDPP_DATA_ACCESS_TYPE_V02),
      access_mode: "continuous",
    };
    const result = issue(selection, {
      fields: { transactions: ["date", "amount"] },
      time_ranges: { transactions: Q4 },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.access_mode).toBe("continuous");
  });
});
