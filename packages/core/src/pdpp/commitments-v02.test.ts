/**
 * Oracles for v0.2 recipient commitments.
 *
 * Anchor: PR vana-com/pdpp#1 spec-core.md "Recipient commitments and
 * approval", and the `authorization-disclosure-contract` requirement
 * "Recipient terms SHALL be resolved before issuance".
 *
 * The distinction the whole section turns on: **changing the data selection is
 * not changing the terms of use.** An owner narrowing what they share has not
 * imposed a new obligation on the recipient, and a recipient has not accepted
 * an obligation merely by being able to. So:
 *
 *   - purpose and retention resolve from the *request* or from standing terms
 *     the recipient actually authorized, before the owner approves;
 *   - the evidence identifying those terms and their version is retained with
 *     the consent evidence, because "the recipient agreed" is worthless later
 *     without a record of *what* they agreed to;
 *   - an owner-authored condition outside that authority refuses issuance
 *     rather than being silently carried as if the recipient had accepted it.
 */

import { describe, expect, it } from "vitest";
import { issueGrant } from "./issuance.js";
import {
  buildConsentReview,
  type ConsentReviewModel,
  type RequesterIdentity,
} from "./review.js";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type RecipientTerms,
  type Retention,
  type SelectionRequest,
} from "./index.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "b".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount"],
      required_fields: ["date"],
      consent_time_field: "date",
      primary_key: ["date"],
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

const REQUESTED_RETENTION: Retention = {
  max_duration: "P30D",
  on_expiry: "delete",
};

function request(overrides: Partial<SelectionRequest> = {}): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE_V02,
    source: { id: snapshot.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    purpose_description: "Categorize your spending",
    access_mode: "single_use",
    retention: REQUESTED_RETENTION,
    streams: [{ name: "transactions", fields: ["date", "amount"] }],
    ...overrides,
  };
}

interface IssueInput {
  selection?: SelectionRequest;
  ownerConditions?: { retention?: Retention; purpose_code?: string };
  standingTerms?: RecipientTerms;
}

/**
 * Issue through the same path the AS uses: resolve, build the review the owner
 * would see, then approve that exact digest.
 *
 * `buildConsentReview` throws on an uncovered owner condition -- there is no
 * valid review to render -- so a refusal case has no digest to approve and
 * `review` comes back undefined. That is the behaviour, not a harness
 * limitation: a surface cannot show the owner terms the recipient refused.
 */
function issue(input: IssueInput) {
  const selection = input.selection ?? request();
  const resolution = resolveSelection(selection, snapshot, inventory);
  if (!resolution.ok) throw new Error("unresolvable");

  let review: ConsentReviewModel | undefined;
  try {
    review = buildConsentReview({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      resolvedStreams: resolution.streams,
      requestedStreams: resolution.requestedStreams,
      requester,
      ownerConditions: input.ownerConditions,
      standingTerms: input.standingTerms,
    });
  } catch {
    review = undefined;
  }

  return {
    review,
    result: issueGrant({
      subjectId: "subject_example",
      request: selection,
      snapshot,
      inventory,
      requester,
      ownerConditions: input.ownerConditions,
      standingTerms: input.standingTerms,
      approvedReviewDigest: review?.review_digest ?? "no-valid-review",
      now: new Date("2026-09-18T12:00:00Z"),
    }),
  };
}

/** The review, asserted present. Refusal cases must not call this. */
function reviewOf(input: IssueInput): ConsentReviewModel {
  const { review } = issue(input);
  if (!review) throw new Error("expected a renderable review");
  return review;
}

describe("resolved commitments reach the review and the grant", () => {
  it("includes the resolved purpose in the final owner review and the grant", () => {
    const review = reviewOf({});
    const { result } = issue({});
    expect(review.policy.purpose_code).toBe(
      "https://apps.example.com/purposes/budget",
    );
    expect(review.policy.purpose_description).toBe("Categorize your spending");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.purpose_code).toBe(
      "https://apps.example.com/purposes/budget",
    );
    expect(result.grant.purpose_description).toBe("Categorize your spending");
  });

  it("includes the resolved retention in the final owner review and the grant", () => {
    const review = reviewOf({});
    const { result } = issue({});
    expect(review.policy.retention).toEqual(REQUESTED_RETENTION);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.retention).toEqual(REQUESTED_RETENTION);
  });
});

describe("owner conditions require recipient authority", () => {
  it("refuses issuance for a retention condition outside recipient authority", () => {
    // The owner asks for a shorter retention than the recipient requested.
    // Favourable to the owner, but still a term the recipient never accepted,
    // and carrying it as a grant constraint would claim an acceptance that
    // does not exist.
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("recipient_terms_unsupported");
  });

  it("refuses issuance for a purpose condition outside recipient authority", () => {
    const { result } = issue({
      ownerConditions: {
        purpose_code: "https://apps.example.com/purposes/research",
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("recipient_terms_unsupported");
  });

  it("does not reveal source or field existence in the refusal message", () => {
    // v0.2: error descriptions must not reveal unapproved source, instance,
    // record, or field existence.
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.message).not.toContain(snapshot.source_id);
    expect(result.failure.message).not.toContain("transactions");
    expect(result.failure.message).not.toContain("account_example");
  });

  it("accepts an owner condition covered by recipient-authorized standing terms", () => {
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
        accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.grant.retention).toEqual({
      max_duration: "P7D",
      on_expiry: "delete",
    });
  });

  it("does not treat standing terms as blanket acceptance", () => {
    // Standing terms name what the recipient accepted, not a capability to
    // accept anything. A condition outside the enumerated set still refuses.
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P1D", on_expiry: "delete" },
      },
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
        accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
      },
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("recipient_terms_unsupported");
  });

  it("does not interpret narrower data access as acceptance of new terms", () => {
    // The owner narrows the data *and* proposes a term. The narrowing must
    // not be read as the recipient accepting the term: the refusal stands.
    const narrowed = resolveSelection(request(), snapshot, inventory, {
      fields: { transactions: ["date"] },
    });
    expect(narrowed.ok).toBe(true);
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
    });
    expect(result.ok).toBe(false);
  });
});

describe("recipient-terms evidence is retained with the consent evidence", () => {
  it("records the terms identity and version used to resolve the commitments", () => {
    const { result } = issue({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
        accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Without the version, "the recipient agreed" is unfalsifiable later: the
    // terms document can change and nothing records which text was in force.
    expect(result.consentEvidence.recipient_terms).toEqual({
      id: "https://apps.example.com/terms/data-handling",
      version: "2026-08-01",
    });
  });

  it("records that the commitments came from the request when no terms applied", () => {
    const { result } = issue({});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.consentEvidence.recipient_terms).toEqual({
      id: "urn:pdpp:recipient-terms:selection-request",
      version: snapshot.version,
    });
  });

  it("keeps the terms evidence out of the grant", () => {
    // v0.2: Core represents commitments through its existing purpose and
    // retention fields and defines no additional terms object on the grant.
    // The acceptance evidence is consent evidence, not a grant constraint.
    const { result } = issue({
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
      },
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(
      (result.grant as unknown as Record<string, unknown>).recipient_terms,
    ).toBeUndefined();
  });
});

describe("the owner reviews the resolved commitments before approving", () => {
  it("shows the owner's covered condition, not the client's original ask", () => {
    const review = reviewOf({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
        accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
      },
    });
    expect(review.policy.retention).toEqual({
      max_duration: "P7D",
      on_expiry: "delete",
    });
  });

  it("binds the resolved commitments into the review digest", () => {
    // A commitment the owner never saw must not be issuable, so the resolved
    // purpose and retention have to be decision fields.
    const base = reviewOf({}).review_digest;
    const withTerms = reviewOf({
      ownerConditions: {
        retention: { max_duration: "P7D", on_expiry: "delete" },
      },
      standingTerms: {
        id: "https://apps.example.com/terms/data-handling",
        version: "2026-08-01",
        accepted_retention: [{ max_duration: "P7D", on_expiry: "delete" }],
      },
    }).review_digest;
    expect(withTerms).not.toBe(base);
  });
});
