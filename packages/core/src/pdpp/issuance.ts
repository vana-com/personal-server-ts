/**
 * PDPP Core §7 grant issuance.
 *
 * Issuance is the moment every request-only convenience becomes a frozen fact.
 * The guard that matters most here is staleness: §7 requires the AS to reject
 * approval if instance eligibility or the reviewed revision changed between
 * the owner seeing the review surface and the approval landing.
 *
 * We enforce that by recomputing the review digest from what we are about to
 * issue and comparing it to the digest the owner approved. Any drift — a newly
 * connected instance changing an auto-resolved handle, a re-fetched
 * declaration, an edited field list — moves the digest and kills the approval.
 * This is a re-derivation, not a stored-value comparison, so it catches drift
 * in inputs that were never persisted alongside the approval.
 */

import { randomBytes } from "node:crypto";
import {
  buildConsentReview,
  computeReviewDigest,
  normalizeClientClaims,
  type RequesterIdentity,
} from "./review.js";
import {
  resolveSelection,
  type InstanceInventory,
  type OwnerChoices,
} from "./resolve.js";
import {
  AI_TRAINING_PURPOSE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION,
  PDPP_GRANT_VERSION_V02,
  type DeclarationSnapshot,
  type Grant,
  type SelectionRequest,
} from "./types.js";

export type IssuanceFailureCode =
  /** The reviewed revision or instance eligibility moved before approval. */
  | "stale_approval"
  /** purpose/ai_training without explicit affirmative consent. */
  | "ai_training_consent_required"
  | "resolution_failed"
  | "access_denied";

export interface IssuanceFailure {
  code: IssuanceFailureCode;
  message: string;
}

export type IssuanceResult =
  | { ok: true; grant: Grant; consentEvidence: ConsentEvidence }
  | { ok: false; failure: IssuanceFailure };

/**
 * Retained consent evidence. §6 requires the normalized exact client claims,
 * with attribution, to be bound into the final approval artifact and preserved
 * here — while staying outside the grant, introspection, and RS enforcement.
 * Keeping them in a separate structure from `Grant` is what makes that
 * separation structural rather than a convention someone can forget.
 */
export interface ConsentEvidence {
  review_digest: string;
  approved_at: string;
  /** The exact snapshot identity consent was given against. */
  declaration: { source_id: string; version: string; digest: string };
  client_claims?: { attributed_to: string; commitments: string[] };
  /** Recorded only for purpose codes that require it. */
  explicit_ai_training_consent?: boolean;
}

export interface IssueGrantInput {
  subjectId: string;
  request: SelectionRequest;
  /** The retained snapshot — the same one validation and review ran against. */
  snapshot: DeclarationSnapshot;
  /** Instance inventory as of *now*, re-read at approval time on purpose. */
  inventory: InstanceInventory;
  /**
   * v0.2 owner narrowing. Ignored for a v0.1 request, and bound into the
   * review digest either way, so an approval cannot carry a narrowing the
   * owner never reviewed.
   */
  ownerChoices?: OwnerChoices;
  requester: RequesterIdentity;
  /** The digest the owner actually approved. */
  approvedReviewDigest: string;
  /**
   * Explicit affirmative consent for `purpose/ai_training`. Required only for
   * that code (§6 AI training consent); ignored otherwise.
   */
  explicitAiTrainingConsent?: boolean;
  /** AS-policy grant expiry. Absent means the grant never expires. */
  expiresAt?: string;
  streamDescriptions?: Record<string, string>;
  now?: Date;
}

function newGrantId(): string {
  return `grt_${randomBytes(12).toString("hex")}`;
}

/**
 * Resolve, re-verify the approval, and issue.
 *
 * Deliberately re-runs resolution against the *current* inventory rather than
 * trusting the streams captured at review time. If the owner connected or
 * disconnected an instance while the consent screen was open, resolution now
 * produces different handles, the recomputed digest diverges, and we reject.
 * Trusting the review-time streams would issue a grant the owner never saw.
 */
export function issueGrant(input: IssueGrantInput): IssuanceResult {
  const now = input.now ?? new Date();

  if (
    input.request.purpose_code === AI_TRAINING_PURPOSE &&
    input.explicitAiTrainingConsent !== true
  ) {
    return {
      ok: false,
      failure: {
        code: "ai_training_consent_required",
        message:
          "purpose/ai_training requires explicit affirmative consent before a grant may be issued",
      },
    };
  }

  const resolution = resolveSelection(
    input.request,
    input.snapshot,
    input.inventory,
    input.ownerChoices,
  );
  if (!resolution.ok) {
    // v0.2 splits these deliberately. An unsatisfiable required minimum, a
    // declined required stream, or an empty approval is a *refusal* — the
    // request was well-formed and the owner decided; the two are simply
    // incompatible, and the OAuth binding reports it as `access_denied`. Every
    // other resolution failure is drift the owner can recover from by
    // re-reviewing, and stays `resolution_failed`.
    const refused =
      resolution.failure.code === "minimum_not_met" ||
      resolution.failure.code === "required_stream_declined" ||
      resolution.failure.code === "no_streams_approved";
    return {
      ok: false,
      failure: {
        code: refused ? "access_denied" : "resolution_failed",
        message: resolution.failure.message,
      },
    };
  }

  // Re-derive the review the owner would see from what we are about to issue.
  const review = buildConsentReview({
    subjectId: input.subjectId,
    request: input.request,
    snapshot: input.snapshot,
    resolvedStreams: resolution.streams,
    omittedStreams: resolution.omittedStreams,
    requester: input.requester,
    expiresAt: input.expiresAt,
    streamDescriptions: input.streamDescriptions,
  });

  if (review.review_digest !== input.approvedReviewDigest) {
    return {
      ok: false,
      failure: {
        code: "stale_approval",
        message:
          "the reviewed selection or instance eligibility changed before approval; a new review is required",
      },
    };
  }

  const isV02 = input.request.type === PDPP_DATA_ACCESS_TYPE_V02;

  const grant: Grant = {
    version: isV02 ? PDPP_GRANT_VERSION_V02 : PDPP_GRANT_VERSION,
    grant_id: newGrantId(),
    issued_at: now.toISOString(),
    subject: { id: input.subjectId },
    client: {
      client_id: input.requester.client_id,
      // §7: retained client_display is the AS-resolved identity, not raw
      // inline input. `requester.display` already went through resolution.
      ...(input.requester.display && {
        client_display: input.requester.display,
      }),
    },
    // Provenance comes from the accepted declaration, never from the request.
    source: { kind: input.snapshot.source_kind, id: input.snapshot.source_id },
    source_declaration: { version: input.snapshot.version },
    purpose_code: input.request.purpose_code,
    ...(input.request.purpose_description && {
      purpose_description: input.request.purpose_description,
    }),
    access_mode: input.request.access_mode,
    streams: resolution.streams,
    ...(input.request.selection_preset && {
      selection_preset: input.request.selection_preset,
    }),
    ...(input.request.retention && { retention: input.request.retention }),
    ...(input.expiresAt && { expires_at: input.expiresAt }),
    // v0.2: what was asked for, beside what was approved. The client must be
    // able to work from the owner's actual approval *including* any narrowing,
    // and §7 forbids it reconstructing that from its own copy of the request.
    ...(isV02 &&
      resolution.requestedStreams && {
        requested: {
          streams: resolution.requestedStreams,
          ...(resolution.omittedStreams && {
            omitted_streams: resolution.omittedStreams,
          }),
        },
      }),
  };

  const normalizedClaims = normalizeClientClaims(input.request.client_claims);
  const consentEvidence: ConsentEvidence = {
    review_digest: review.review_digest,
    approved_at: now.toISOString(),
    declaration: {
      source_id: input.snapshot.source_id,
      version: input.snapshot.version,
      digest: input.snapshot.digest,
    },
    ...(normalizedClaims && {
      client_claims: {
        attributed_to: input.requester.display_name,
        commitments: normalizedClaims,
      },
    }),
    ...(input.request.purpose_code === AI_TRAINING_PURPOSE && {
      explicit_ai_training_consent: true,
    }),
  };

  return { ok: true, grant, consentEvidence };
}

/** Re-export so callers get the digest helper from the issuance seam. */
export { computeReviewDigest };
