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
  resolveCommitments,
  type ResolvedCommitments,
} from "./commitments.js";
import {
  AI_TRAINING_PURPOSE,
  type ClientClaims,
  type ClientDisplay,
  type DeclarationSnapshot,
  type OwnerConditions,
  type RecipientTerms,
  type RequestedStream,
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
  /**
   * §5 stream `display.label` — the short consent-card name for this stream,
   * e.g. "Who you follow" rather than `following_accounts`.
   *
   * Read from the retained declaration snapshot, never from the request. §5
   * forbids the requesting client from authoring or supplementing it, and the
   * AS is the only role that can hold that line, because the renderer cannot
   * tell from one payload which member the client wrote.
   */
  display_label?: string;
  /**
   * §5 stream `display.detail` — what the data includes and, where relevant,
   * what it EXCLUDES. Same provenance rule as `display_label`.
   */
  display_detail?: string;
  instance_ids: string[];
  fields: string[];
  time_constraint?: { field: string; since?: string; until?: string };
  resources?: string[];
  /**
   * v0.2 consent-flow control. `optional` means the owner may remove this
   * stream; the surface must not present it as compulsory.
   */
  necessity?: "required" | "optional";
  /**
   * v0.2: the fields and window the client asked for, before the owner's
   * narrowing. The surface needs both ends to render a narrowing control at
   * all — `fields` above is the current proposal, this is its ceiling.
   */
  requested_fields?: string[];
  requested_time_range?: { since?: string; until?: string };
  /**
   * v0.2: the floor. A surface that lets the owner narrow below this is
   * offering a choice that will refuse issuance, so it needs to know where
   * the floor is in order to stop short of it — or to say why it cannot.
   */
  minimum?: {
    fields?: string[];
    time_range?: { since: string; until: string };
  };
}

/**
 * An already-active grant this same client holds for this owner, so the
 * consent surface can say what is already shared. Deliberately excludes
 * tokens, consent evidence, and the review digest — informational only, never
 * an authority the RS or AS re-derives from.
 */
export interface ExistingGrant {
  grant_id: string;
  issued_at: string;
  expires_at?: string;
  access_mode: "single_use" | "continuous";
  purpose_code: string;
  streams: Array<{ name: string; fields: string[] }>;
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
    /**
     * `display_name` is §5's top-level `display.name` — the human name for the
     * source. It accompanies `id` rather than replacing it: `id` is the
     * protocol-enforced fact and the one 6.1-5 requires the owner to be able
     * to see, so a surface that showed only the friendly name would hide which
     * source was actually resolved.
     */
    source: { kind: string; id: string; display_name?: string };
    source_declaration_version: string;
    access_mode: "single_use" | "continuous";
    streams: ReviewStream[];
    /**
     * v0.2: optional streams the owner's current choices have removed, so the
     * surface can keep showing them as declined rather than making them
     * vanish. v0.2 forbids presenting optional selections as compulsory; a
     * declined stream that disappears from the review is the mirror failure —
     * the owner cannot see what they turned off, or turn it back on.
     */
    omitted_streams?: string[];
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
  /**
   * This client's other active grants for this owner, newest first. Absent
   * when there are none — kept out of the digest since it is informational,
   * not a decision field, and can change between requests without staling
   * the review.
   */
  existing_grants?: ExistingGrant[];
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
  /**
   * v0.2: optional streams the owner's choices removed.
   *
   * This has to be a decision field, not just presentation. Two owners
   * narrowing the same request to the same retained streams by different
   * routes — one declining an optional stream, one narrowing it below its
   * minimum — reach the same `streams` but reviewed different screens. More
   * importantly, without it an approval could carry a narrowing the owner
   * never saw whenever that narrowing only *removed* a stream, since removal
   * leaves the surviving streams byte-identical.
   */
  omitted_streams?: string[];
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
  /** v0.2: `resolveSelection`'s `omittedStreams`, bound into the digest. */
  omittedStreams?: string[];
  /**
   * v0.2: `resolveSelection`'s `requestedStreams`, the ceiling each retained
   * stream was narrowed from. Rendering only — the resolved streams stay
   * authoritative, and this stays out of the digest since it is a restatement
   * of the request the session already pins, not a decision the owner makes.
   */
  requestedStreams?: RequestedStream[];
  /**
   * v0.2: conditions the owner attached beyond narrowing the data, and the
   * standing terms that may cover them.
   *
   * Resolution happens here rather than in the caller so the review and the
   * digest cannot disagree about which commitments were shown. A condition
   * outside the recipient's authority makes the whole review unavailable —
   * there is nothing valid to show the owner — so `buildConsentReview` throws
   * the same `CommitmentsFailure` the issuance path reports. Callers that can
   * present a failure to the owner call `resolveCommitments` first.
   */
  ownerConditions?: OwnerConditions;
  standingTerms?: RecipientTerms;
  /**
   * Pre-resolved commitments, when the caller already ran
   * `resolveCommitments` (issuance does, so it can report a refusal rather
   * than throw). Takes precedence over the two members above.
   */
  commitments?: ResolvedCommitments;
  requester: RequesterIdentity;
  /** AS-policy grant expiry, when the deployment sets one. */
  expiresAt?: string;
  /** Declaration-authored stream descriptions, keyed by stream name. */
  streamDescriptions?: Record<string, string>;
  /** This client's other active grants for this owner, newest first. */
  existingGrants?: ExistingGrant[];
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

  // The commitments the owner will see, resolved from the request or the
  // recipient's standing terms. These are decision fields: a commitment the
  // owner never reviewed must not be issuable, so they go into the digest.
  const commitments =
    input.commitments ?? resolveOrThrowCommitments(input);

  const review_digest = computeReviewDigest({
    subject_id: input.subjectId,
    client_id: requester.client_id,
    source_id: snapshot.source_id,
    source_kind: snapshot.source_kind,
    source_declaration_version: snapshot.version,
    declaration_digest: snapshot.digest,
    purpose_code: commitments.purpose_code,
    purpose_description: commitments.purpose_description,
    access_mode: request.access_mode,
    streams: resolvedStreams,
    ...(input.omittedStreams &&
      input.omittedStreams.length > 0 && {
        omitted_streams: input.omittedStreams,
      }),
    retention: commitments.retention,
    expires_at: input.expiresAt,
    client_claims: boundClaims,
  });

  return {
    requester,
    data: {
      source: {
        kind: snapshot.source_kind,
        id: snapshot.source_id,
        ...(snapshot.display?.name && {
          display_name: snapshot.display.name,
        }),
      },
      source_declaration_version: snapshot.version,
      access_mode: request.access_mode,
      streams: resolvedStreams.map((s) => {
        const asked = input.requestedStreams?.find((r) => r.name === s.name);
        // §5 consent copy, read from the RETAINED SNAPSHOT. `request` is
        // deliberately not consulted: that is the whole provenance guarantee.
        const declared = snapshot.streams.find((d) => d.name === s.name);
        return {
          name: s.name,
          // The deployment-supplied map still wins where a caller set it, so
          // this adds a source of copy without removing the existing one.
          ...((input.streamDescriptions?.[s.name] ?? declared?.description) && {
            description:
              input.streamDescriptions?.[s.name] ?? declared?.description,
          }),
          ...(declared?.display?.label && {
            display_label: declared.display.label,
          }),
          ...(declared?.display?.detail && {
            display_detail: declared.display.detail,
          }),
          instance_ids: s.instance_ids,
          fields: s.fields,
          ...(s.time_constraint && { time_constraint: s.time_constraint }),
          ...(s.resources && { resources: s.resources }),
          ...(asked && {
            necessity: asked.necessity,
            requested_fields: asked.fields,
            ...(asked.time_range && { requested_time_range: asked.time_range }),
            ...(asked.minimum && { minimum: asked.minimum }),
          }),
        };
      }),
      ...(input.omittedStreams &&
        input.omittedStreams.length > 0 && {
          omitted_streams: input.omittedStreams,
        }),
      ...(input.expiresAt && { expires_at: input.expiresAt }),
    },
    policy: {
      purpose_code: commitments.purpose_code,
      ...(commitments.purpose_description && {
        purpose_description: commitments.purpose_description,
      }),
      purpose_unregistered: !isRegisteredPurposeCode(commitments.purpose_code),
      ...(commitments.retention && { retention: commitments.retention }),
      requires_explicit_ai_training_consent:
        commitments.purpose_code === AI_TRAINING_PURPOSE,
    },
    ...(boundClaims && { client_claims: boundClaims }),
    review_digest,
    ...(input.existingGrants &&
      input.existingGrants.length > 0 && {
        existing_grants: input.existingGrants,
      }),
  };
}

/**
 * Resolve commitments for a caller that cannot present a refusal.
 *
 * A condition outside the recipient's authority means there is no valid review
 * to build — showing the owner the *unrefused* terms would be showing them a
 * decision they cannot make. Throwing rather than silently falling back is
 * what stops that: the issuance path resolves first and reports a refusal, and
 * anything else fails loudly instead of rendering a lie.
 */
function resolveOrThrowCommitments(
  input: BuildReviewInput,
): ResolvedCommitments {
  const resolved = resolveCommitments({
    request: input.request,
    ownerConditions: input.ownerConditions,
    standingTerms: input.standingTerms,
    declarationVersion: input.snapshot.version,
  });
  if (!resolved.ok) throw new Error(resolved.failure.message);
  return resolved.commitments;
}
