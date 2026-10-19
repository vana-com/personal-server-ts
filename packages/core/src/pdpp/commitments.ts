/**
 * PDPP v0.2 recipient commitments: resolving purpose and retention before the
 * owner approves.
 *
 * The section this implements exists because of one asymmetry. An owner
 * narrowing what they share is acting entirely within their own authority —
 * nobody else has to agree to receive less. An owner *changing the terms of
 * use* is proposing an obligation the recipient has to carry, and no amount of
 * owner authority makes the recipient agree to it. v0.2 keeps those two apart
 * deliberately: "The AS MUST NOT interpret narrower access as recipient
 * acceptance of a new purpose or retention obligation."
 *
 * So commitments resolve from exactly two places — the client's own request,
 * or standing terms the recipient authorized — and an owner condition covered
 * by neither refuses issuance rather than being carried as though agreed.
 *
 * The important non-obvious case: a condition *favourable* to the owner is
 * still a condition. An owner asking for a 7-day retention when the client
 * requested 30 is asking for less, but it is still a term the recipient never
 * accepted, and recording it as a grant constraint would claim an acceptance
 * that does not exist. PDPP carries commitments; it cannot enforce the
 * recipient's behavior after disclosure, which is exactly why the record of
 * what they actually agreed to has to be honest.
 */

import type {
  OwnerConditions,
  RecipientTerms,
  Retention,
  SelectionRequest,
} from "./types.js";

/**
 * Sentinel terms identity for commitments that came from the selection request
 * itself.
 *
 * The request *is* recipient authority — the client wrote it — so this is a
 * real answer rather than a missing one. Recording it explicitly, rather than
 * leaving the evidence absent, is what makes "no terms were consulted"
 * distinguishable from "the evidence was never written".
 */
export const REQUEST_TERMS_ID = "urn:pdpp:recipient-terms:selection-request";

/** The commitments that will be shown to the owner and written into the grant. */
export interface ResolvedCommitments {
  purpose_code: string;
  purpose_description?: string;
  retention?: Retention;
  /** Identity and version of the authority these came from. */
  evidence: { id: string; version: string };
}

export interface CommitmentsFailure {
  code: "recipient_terms_unsupported";
  message: string;
}

export type CommitmentsResult =
  | { ok: true; commitments: ResolvedCommitments }
  | { ok: false; failure: CommitmentsFailure };

function sameRetention(a: Retention, b: Retention): boolean {
  return a.max_duration === b.max_duration && a.on_expiry === b.on_expiry;
}

export interface ResolveCommitmentsInput {
  request: SelectionRequest;
  /** Conditions the owner attached to their approval. */
  ownerConditions?: OwnerConditions;
  /** Standing terms the recipient authorized, when the deployment tracks them. */
  standingTerms?: RecipientTerms;
  /** The declaration revision, used as the request's own evidence version. */
  declarationVersion: string;
}

/**
 * Resolve purpose and retention from the request or applicable standing terms.
 *
 * Runs before the owner approves, never after: v0.2 requires the owner to see
 * the resolved commitments in the final review, so a commitment resolved at
 * issuance time would be one the owner never saw.
 */
export function resolveCommitments(
  input: ResolveCommitmentsInput,
): CommitmentsResult {
  const { request, ownerConditions, standingTerms } = input;

  // Absent any owner condition, the request's own terms stand and the client
  // is self-evidently the authority for them.
  let evidence = {
    id: REQUEST_TERMS_ID,
    version: input.declarationVersion,
  };
  let purposeCode = request.purpose_code;
  let retention = request.retention;

  // Error text is deliberately generic. v0.2: "Error descriptions MUST NOT
  // reveal unapproved source, instance, record, or field existence." A
  // rejection is a fine place to leak an inventory if the message names what
  // the request touched, so this one names only the term class.
  const refuse = (what: string): CommitmentsResult => ({
    ok: false,
    failure: {
      code: "recipient_terms_unsupported",
      message: `the requested ${what} is not covered by the recipient's applicable authority`,
    },
  });

  if (ownerConditions?.purpose_code !== undefined) {
    const proposed = ownerConditions.purpose_code;
    const covered =
      proposed === request.purpose_code ||
      standingTerms?.accepted_purpose_codes?.includes(proposed) === true;
    if (!covered) return refuse("purpose");
    purposeCode = proposed;
    // A purpose description authored for the client's own purpose code does
    // not describe a different one. Dropping it is the honest outcome; the
    // surface falls back to the code or its registry entry.
    if (proposed !== request.purpose_code) {
      evidence = termsEvidence(standingTerms, evidence);
    }
  }

  if (ownerConditions?.retention !== undefined) {
    const proposed = ownerConditions.retention;
    const covered =
      (request.retention !== undefined &&
        sameRetention(proposed, request.retention)) ||
      standingTerms?.accepted_retention?.some((accepted) =>
        sameRetention(proposed, accepted),
      ) === true;
    if (!covered) return refuse("retention term");
    retention = proposed;
    if (
      request.retention === undefined ||
      !sameRetention(proposed, request.retention)
    ) {
      evidence = termsEvidence(standingTerms, evidence);
    }
  }

  const purposeDescription =
    purposeCode === request.purpose_code
      ? request.purpose_description
      : undefined;

  return {
    ok: true,
    commitments: {
      purpose_code: purposeCode,
      ...(purposeDescription !== undefined && {
        purpose_description: purposeDescription,
      }),
      ...(retention !== undefined && { retention }),
      evidence,
    },
  };
}

function termsEvidence(
  standingTerms: RecipientTerms | undefined,
  fallback: { id: string; version: string },
): { id: string; version: string } {
  if (!standingTerms) return fallback;
  return { id: standingTerms.id, version: standingTerms.version };
}
