/**
 * PDPP Core §6/§7 consent review model and immutable review digest.
 *
 * Two jobs here, and they are related:
 *
 * 1. Build the review model Account/Web renders. §6 forbids flattening the
 *    consent surface: requester identity, declaration-authored data
 *    descriptions, structured policy declarations, and attributed client
 *    claims are four distinct categories, and a client claim must never be
 *    rendered in the same register as a protocol-enforced term. The model
 *    below keeps them in four separate fields so a renderer cannot
 *    accidentally merge them.
 *
 * 2. Compute a digest over the decision fields. §7 requires the approval
 *    mutation to bind to an immutable review revision or digest, and to reject
 *    approval if eligibility or the reviewed revision changed in the meantime.
 *    That is what stops a resolved-then-widened race: the owner approves a
 *    digest, and issuance re-derives the digest from what it is about to issue.
 *    If they differ, the approval is stale and dies.
 *
 * The digest covers exactly the decision fields §7 enumerates, plus the
 * normalized client claims when they were rendered. It deliberately does NOT
 * cover `issued_at` or `grant_id`, which do not exist yet at review time.
 */

import { createHash } from "node:crypto";
import {
  AI_TRAINING_PURPOSE,
  type ClientClaims,
  type ClientDisplay,
  type DeclarationSnapshot,
  type Retention,
  type SelectionRequest,
  type StreamGrant,
} from "./types.js";

/** How the AS resolved requester identity, and how much it actually knows. */
export interface RequesterIdentity {
  client_id: string;
  /** Resolved per §6 precedence. Falls back to `client_id` when nothing else exists. */
  display_name: string;
  display?: ClientDisplay;
  /**
   * §6 obligation 5: verified domain control is named, never presented as an
   * unqualified "verified app". Absent means no positive trust signal, and the
   * surface must show an unverified indicator.
   */
  verified_domain?: string;
  /** True only for a local registration or trust-registry admission decision. */
  app_approved: boolean;
}

/** One stream row as the owner reviews it, with declaration-authored copy. */
export interface ReviewStream {
  name: string;
  /** Declaration-authored description. Its own category — not a client claim. */
  description?: string;
  instance_ids: string[];
  fields: string[];
  time_constraint?: { field: string; since?: string; until?: string };
  resources?: string[];
}

/**
 * The four semantic categories §6 requires a conformant consent surface to
 * keep distinct. A renderer that wants to flatten them has to do so
 * deliberately; it cannot do so by accident.
 */
export interface ConsentReviewModel {
  /** Category 1: who is asking. */
  requester: RequesterIdentity;
  /** Category 2: declaration-authored data descriptions + protocol-enforced terms. */
  data: {
    source: { kind: string; id: string };
    source_declaration_version: string;
    access_mode: "single_use" | "continuous";
    streams: ReviewStream[];
    expires_at?: string;
  };
  /** Category 3: structured policy declarations. */
  policy: {
    purpose_code: string;
    purpose_description?: string;
    /**
     * True when the code is absent from the PDPP registry. §9 AS item 6:
     * this drives *rendering* (show the description or raw URI), never
     * rejection.
     */
    purpose_unregistered: boolean;
    retention?: Retention;
    /**
     * §6: the sole purpose code with a protocol-level consent requirement.
     * The surface must collect explicit affirmative consent when this is set.
     */
    requires_explicit_ai_training_consent: boolean;
  };
  /** Category 4: attributed, unverifiable, non-enforceable client claims. */
  client_claims?: {
    /** Always rendered as "<name> says:" — never as a protocol term. */
    attributed_to: string;
    commitments: string[];
  };
  /** Digest over the decision fields. The approval must carry this back. */
  review_digest: string;
}

/**
 * Purpose codes in the Appendix A initial registry. Membership drives display
 * only. An unrecognized code is displayed from its description or raw URI and
 * is never a rejection reason on its own (§9 AS item 6).
 */
const REGISTERED_PURPOSE_CODES = new Set([
  "https://pdpp.dev/purpose/personalization",
  "https://pdpp.dev/purpose/analytics",
  "https://pdpp.dev/purpose/research",
  "https://pdpp.dev/purpose/portability",
  "https://pdpp.dev/purpose/ai_training",
]);

export function isRegisteredPurposeCode(code: string): boolean {
  return REGISTERED_PURPOSE_CODES.has(code);
}

/**
 * Normalize client claims before binding. §6 requires the *normalized exact*
 * claims to be bound into the approval artifact, so the digest has to be
 * computed over a canonical form — otherwise re-rendering with different
 * whitespace would spuriously invalidate an approval.
 */
export function normalizeClientClaims(
  claims: ClientClaims | undefined,
): string[] | undefined {
  const commitments = claims?.commitments;
  if (!commitments || commitments.length === 0) return undefined;
  const normalized = commitments
    .map((c) => c.trim().replace(/\s+/g, " "))
    .filter((c) => c.length > 0);
  return normalized.length > 0 ? normalized : undefined;
}

/**
 * The exact set of fields the digest covers. Kept as its own type so that
 * adding a decision field to the grant without adding it here is a visible
 * omission rather than a silent hole in the binding.
 */
interface ReviewDecisionFields {
  subject_id: string;
  client_id: string;
  source_id: string;
  source_kind: string;
  source_declaration_version: string;
  /** The digest of the retained snapshot, so a re-fetched declaration cannot pass. */
  declaration_digest: string;
  purpose_code: string;
  purpose_description?: string;
  access_mode: string;
  streams: StreamGrant[];
  retention?: Retention;
  expires_at?: string;
  /** Bound with attribution when rendered; stays outside the grant regardless. */
  client_claims?: { attributed_to: string; commitments: string[] };
}

/**
 * Deterministic serialization. `JSON.stringify` preserves insertion order, so
 * we sort keys explicitly — two structurally identical decisions must produce
 * one digest regardless of how the objects were built.
 */
function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    // Array order is meaningful (a field list's order is part of the decision
    // the owner saw), so we do not sort array members.
    return `[${value.map(canonicalize).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries
    .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`)
    .join(",")}}`;
}

export function computeReviewDigest(fields: ReviewDecisionFields): string {
  return createHash("sha256")
    .update(canonicalize(fields), "utf8")
    .digest("hex");
}

export interface BuildReviewInput {
  subjectId: string;
  request: SelectionRequest;
  snapshot: DeclarationSnapshot;
  /** The output of `resolveSelection` — fully concrete. */
  resolvedStreams: StreamGrant[];
  requester: RequesterIdentity;
  /** AS-policy grant expiry, when the deployment sets one. */
  expiresAt?: string;
  /** Declaration-authored stream descriptions, keyed by stream name. */
  streamDescriptions?: Record<string, string>;
}

/**
 * Build the review model and its binding digest.
 *
 * The digest is computed from the same resolved streams that will be issued.
 * `issueGrant` recomputes it and refuses to issue if it moved — see
 * `issuance.ts`.
 */
export function buildConsentReview(
  input: BuildReviewInput,
): ConsentReviewModel {
  const { request, snapshot, resolvedStreams, requester } = input;

  const normalizedClaims = normalizeClientClaims(request.client_claims);
  const boundClaims = normalizedClaims
    ? { attributed_to: requester.display_name, commitments: normalizedClaims }
    : undefined;

  const review_digest = computeReviewDigest({
    subject_id: input.subjectId,
    client_id: requester.client_id,
    source_id: snapshot.source_id,
    source_kind: snapshot.source_kind,
    source_declaration_version: snapshot.version,
    declaration_digest: snapshot.digest,
    purpose_code: request.purpose_code,
    purpose_description: request.purpose_description,
    access_mode: request.access_mode,
    streams: resolvedStreams,
    retention: request.retention,
    expires_at: input.expiresAt,
    client_claims: boundClaims,
  });

  return {
    requester,
    data: {
      source: { kind: snapshot.source_kind, id: snapshot.source_id },
      source_declaration_version: snapshot.version,
      access_mode: request.access_mode,
      streams: resolvedStreams.map((s) => ({
        name: s.name,
        ...(input.streamDescriptions?.[s.name] && {
          description: input.streamDescriptions[s.name],
        }),
        instance_ids: s.instance_ids,
        fields: s.fields,
        ...(s.time_constraint && { time_constraint: s.time_constraint }),
        ...(s.resources && { resources: s.resources }),
      })),
      ...(input.expiresAt && { expires_at: input.expiresAt }),
    },
    policy: {
      purpose_code: request.purpose_code,
      ...(request.purpose_description && {
        purpose_description: request.purpose_description,
      }),
      purpose_unregistered: !isRegisteredPurposeCode(request.purpose_code),
      ...(request.retention && { retention: request.retention }),
      requires_explicit_ai_training_consent:
        request.purpose_code === AI_TRAINING_PURPOSE,
    },
    ...(boundClaims && { client_claims: boundClaims }),
    review_digest,
  };
}
