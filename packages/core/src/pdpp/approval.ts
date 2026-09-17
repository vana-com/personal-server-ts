/**
 * Authorization sessions and authenticated owner approval.
 *
 * This is the module that decides whether a consent decision is real. The
 * threat it exists to stop is an approval that looks right — correct session,
 * correct review digest, arriving from the first-party consent UI — but that
 * no authenticated owner actually made.
 *
 * The rule: **affiliation is not authentication.** The AS does not accept an
 * approval because it came from an allowlisted origin, a first-party console,
 * a shared UI/server secret, or a signed assertion from the consent broker
 * saying "the owner agreed". Each of those authenticates a *channel* or
 * delegates the decision to a browser-reachable component; compromise it and
 * it mints approvals for any subject. Instead, the owner authenticates to the
 * PS itself, and the resulting owner token — resolved through the same token
 * service the RS uses — is what authorizes the decision. The consent UI
 * forwards that token; it can never substitute for it.
 *
 * Two independent checks must both pass, and neither implies the other:
 *
 *   1. The caller presents an active token with `pdpp_token_kind: "owner"`
 *      whose `subject_id` equals the session's subject. Possession of the
 *      session id is not authority over it.
 *   2. The presented `review_digest` matches a re-derivation over what is
 *      about to be issued (§7 staleness). Authenticating the owner does not
 *      excuse approving something other than what they reviewed.
 */

import { randomBytes } from "node:crypto";
import {
  buildConsentReview,
  type ConsentReviewModel,
  type RequesterIdentity,
} from "./review.js";
import { issueGrant, type ConsentEvidence } from "./issuance.js";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
import type { PdppTokenService } from "./tokens.js";
import type { DeclarationSnapshot, Grant, SelectionRequest } from "./types.js";

/** How long an owner has to act on a consent screen before it goes stale. */
export const REVIEW_SESSION_TTL_SECONDS = 10 * 60;

export type SessionState = "pending" | "approved" | "denied";

export interface AuthorizationSession {
  session_id: string;
  /** The subject this session belongs to. An approval must authenticate as this. */
  subject_id: string;
  request: SelectionRequest;
  snapshot: DeclarationSnapshot;
  requester: RequesterIdentity;
  redirect_uri: string;
  state_param?: string;
  expires_at: string;
  status: SessionState;
  /** AS-policy grant expiry carried into issuance. */
  grant_expires_at?: string;
  stream_descriptions?: Record<string, string>;
}

export type ApprovalFailureCode =
  /** No owner token, an inactive one, a client token, or the wrong subject. */
  | "unauthorized"
  | "session_not_found"
  | "stale_review"
  | "ai_training_consent_required"
  | "access_denied"
  | "invalid_request";

export interface ApprovalFailure {
  code: ApprovalFailureCode;
  message: string;
}

export type ApprovalResult =
  | { ok: true; grant: Grant; consentEvidence: ConsentEvidence }
  | { ok: false; failure: ApprovalFailure };

/**
 * In-memory pending-session store. Sessions are short-lived and pre-decision,
 * so they hold no issued authority — losing them on restart costs an owner a
 * re-click, not a grant. Issued grants and tokens go to SQLite, where
 * durability actually matters.
 */
export class AuthorizationSessionStore {
  private readonly sessions = new Map<string, AuthorizationSession>();

  create(input: {
    subjectId: string;
    request: SelectionRequest;
    snapshot: DeclarationSnapshot;
    requester: RequesterIdentity;
    redirectUri: string;
    stateParam?: string;
    grantExpiresAt?: string;
    streamDescriptions?: Record<string, string>;
    now?: Date;
  }): AuthorizationSession {
    const now = input.now ?? new Date();
    const session: AuthorizationSession = {
      session_id: `as_${randomBytes(16).toString("hex")}`,
      subject_id: input.subjectId,
      request: input.request,
      snapshot: input.snapshot,
      requester: input.requester,
      redirect_uri: input.redirectUri,
      ...(input.stateParam && { state_param: input.stateParam }),
      expires_at: new Date(
        now.getTime() + REVIEW_SESSION_TTL_SECONDS * 1000,
      ).toISOString(),
      status: "pending",
      ...(input.grantExpiresAt && { grant_expires_at: input.grantExpiresAt }),
      ...(input.streamDescriptions && {
        stream_descriptions: input.streamDescriptions,
      }),
    };
    this.sessions.set(session.session_id, session);
    return session;
  }

  get(sessionId: string): AuthorizationSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  setStatus(sessionId: string, status: SessionState): void {
    const session = this.sessions.get(sessionId);
    if (session) session.status = status;
  }
}

/**
 * Authenticate the caller as the owner of a session.
 *
 * Returns the session only when the token is an active *owner* token for that
 * exact subject. Every failure collapses to `session_not_found` rather than a
 * distinguishable "wrong owner" — otherwise a caller holding any valid owner
 * token could probe session ids to learn which ones exist and whose they are.
 */
function authenticateOwner(
  sessions: AuthorizationSessionStore,
  tokens: PdppTokenService,
  sessionId: string,
  ownerToken: string | undefined,
  now: Date,
):
  | { ok: true; session: AuthorizationSession }
  | { ok: false; failure: ApprovalFailure } {
  if (!ownerToken) {
    return {
      ok: false,
      failure: {
        code: "unauthorized",
        message:
          "an authenticated owner session is required to decide an authorization",
      },
    };
  }

  const context = tokens.resolveToken(ownerToken, now);
  // A client token must never approve a grant — that would let the requesting
  // application authorize itself.
  if (!context.active || context.tokenKind !== "owner" || !context.subjectId) {
    return {
      ok: false,
      failure: {
        code: "unauthorized",
        message: "owner token is missing, inactive, or not an owner token",
      },
    };
  }

  const session = sessions.get(sessionId);
  if (!session) {
    return {
      ok: false,
      failure: {
        code: "session_not_found",
        message: "authorization session not found",
      },
    };
  }

  // The binding that matters: this owner must be *this session's* owner.
  if (session.subject_id !== context.subjectId) {
    return {
      ok: false,
      failure: {
        code: "session_not_found",
        message: "authorization session not found",
      },
    };
  }

  if (Date.parse(session.expires_at) <= now.getTime()) {
    return {
      ok: false,
      failure: {
        code: "session_not_found",
        message: "authorization session has expired",
      },
    };
  }

  return { ok: true, session };
}

/**
 * A stream the owner must pick an instance for before the review can resolve.
 *
 * §6 is strict that omitting `instance_ids` never means fan-in, so a stream
 * with several eligible handles and none named is a decision only the owner
 * can make. Surfacing the candidates as first-class review data is what turns
 * that from a dead-end resolution failure into a consent step: the UI renders
 * the choice, the owner picks, and the pick flows back through
 * `instanceChoices` on the next review fetch and on approval.
 */
export interface InstanceChoice {
  stream: string;
  candidates: string[];
}

export interface ReviewFetchResult {
  session_id: string;
  /** Present only once every stream resolves. Absent while a choice is pending. */
  review?: ConsentReviewModel;
  /**
   * Non-empty when the owner must choose instance handles before there is a
   * decision to review. The UI collects these and re-fetches with the picks.
   */
  instance_choice_required?: InstanceChoice[];
  expires_at: string;
}

/**
 * Overlay the owner's explicit instance picks onto the inventory.
 *
 * A pick narrows the eligible set for that stream to exactly what the owner
 * chose — it never widens it. Intersecting with the real inventory is what
 * stops a caller from "choosing" a handle the owner has not connected, so an
 * owner choice cannot become an escalation path.
 */
function withInstanceChoices(
  inventory: InstanceInventory,
  choices: Record<string, string[]> | undefined,
): InstanceInventory {
  if (!choices) return inventory;
  return {
    eligibleFor(streamName: string): string[] {
      const eligible = inventory.eligibleFor(streamName);
      const chosen = choices[streamName];
      if (!chosen || chosen.length === 0) return eligible;
      return chosen.filter((handle) => eligible.includes(handle));
    },
  };
}

/**
 * Find every stream that needs an owner choice, rather than stopping at the
 * first. A UI that asked about one stream at a time would make the owner
 * approve a moving target across several round trips.
 */
function pendingInstanceChoices(
  session: AuthorizationSession,
  inventory: InstanceInventory,
): InstanceChoice[] {
  const choices: InstanceChoice[] = [];
  const streams = session.request.streams ?? [];
  const wildcard = streams.find((s) => s.name === "*");

  const names = wildcard
    ? session.snapshot.streams.map((s) => s.name)
    : streams.map((s) => s.name);

  for (const name of names) {
    const requested = wildcard ?? streams.find((s) => s.name === name);
    // An explicitly named handle set is already a decision; no choice needed.
    if (requested?.instance_ids && requested.instance_ids.length > 0) continue;
    const eligible = inventory.eligibleFor(name);
    if (eligible.length > 1) {
      choices.push({ stream: name, candidates: eligible });
    }
  }
  return choices;
}

/**
 * Build the review an authenticated owner sees.
 *
 * Resolution runs here against current inventory, so the digest the owner is
 * handed reflects the world as it is right now. If it changes before they
 * approve, `approveAuthorization` will re-derive a different digest and reject.
 */
export function fetchReview(input: {
  sessions: AuthorizationSessionStore;
  tokens: PdppTokenService;
  sessionId: string;
  ownerToken: string | undefined;
  inventory: InstanceInventory;
  /** The owner's instance picks, keyed by stream, from a prior choice step. */
  instanceChoices?: Record<string, string[]>;
  now?: Date;
}):
  | { ok: true; result: ReviewFetchResult }
  | { ok: false; failure: ApprovalFailure } {
  const now = input.now ?? new Date();
  const auth = authenticateOwner(
    input.sessions,
    input.tokens,
    input.sessionId,
    input.ownerToken,
    now,
  );
  if (!auth.ok) return auth;

  const { session } = auth;
  if (session.status !== "pending") {
    return {
      ok: false,
      failure: {
        code: "access_denied",
        message: "authorization session is already decided",
      },
    };
  }

  const inventory = withInstanceChoices(input.inventory, input.instanceChoices);

  // Surface outstanding choices before attempting resolution: an unresolvable
  // instance is a consent step, not an error the owner can do nothing about.
  const choices = pendingInstanceChoices(session, inventory);
  if (choices.length > 0) {
    return {
      ok: true,
      result: {
        session_id: session.session_id,
        instance_choice_required: choices,
        expires_at: session.expires_at,
      },
    };
  }

  const resolution = resolveSelection(
    session.request,
    session.snapshot,
    inventory,
  );
  if (!resolution.ok) {
    return {
      ok: false,
      failure: {
        code: "invalid_request",
        message: resolution.failure.message,
      },
    };
  }

  const review = buildConsentReview({
    subjectId: session.subject_id,
    request: session.request,
    snapshot: session.snapshot,
    resolvedStreams: resolution.streams,
    requester: session.requester,
    expiresAt: session.grant_expires_at,
    streamDescriptions: session.stream_descriptions,
  });

  return {
    ok: true,
    result: {
      session_id: session.session_id,
      review,
      expires_at: session.expires_at,
    },
  };
}

/**
 * Approve an authorization: authenticate the owner, then issue.
 *
 * Order is deliberate. Authentication runs before anything else, so an
 * unauthenticated caller cannot learn from the error whether their digest was
 * fresh — a spoofed approval with a perfectly valid digest gets the same
 * `unauthorized` as one with a garbage digest.
 */
export function approveAuthorization(input: {
  sessions: AuthorizationSessionStore;
  tokens: PdppTokenService;
  sessionId: string;
  ownerToken: string | undefined;
  reviewDigest: string;
  inventory: InstanceInventory;
  /**
   * The owner's instance picks, which must match the ones the review was
   * rendered with. They feed resolution, so they land inside the recomputed
   * digest — a different pick than the owner reviewed fails as stale rather
   * than silently issuing a grant over another instance.
   */
  instanceChoices?: Record<string, string[]>;
  explicitAiTrainingConsent?: boolean;
  now?: Date;
}): ApprovalResult {
  const now = input.now ?? new Date();

  const auth = authenticateOwner(
    input.sessions,
    input.tokens,
    input.sessionId,
    input.ownerToken,
    now,
  );
  if (!auth.ok) return auth;

  const { session } = auth;
  if (session.status !== "pending") {
    return {
      ok: false,
      failure: {
        code: "access_denied",
        message: "authorization session is already decided",
      },
    };
  }

  if (!input.reviewDigest) {
    return {
      ok: false,
      failure: {
        code: "invalid_request",
        message: "review_digest is required",
      },
    };
  }

  const issuance = issueGrant({
    subjectId: session.subject_id,
    request: session.request,
    snapshot: session.snapshot,
    inventory: withInstanceChoices(input.inventory, input.instanceChoices),
    requester: session.requester,
    approvedReviewDigest: input.reviewDigest,
    explicitAiTrainingConsent: input.explicitAiTrainingConsent,
    expiresAt: session.grant_expires_at,
    streamDescriptions: session.stream_descriptions,
    now,
  });

  if (!issuance.ok) {
    const code: ApprovalFailureCode =
      issuance.failure.code === "stale_approval"
        ? "stale_review"
        : issuance.failure.code === "ai_training_consent_required"
          ? "ai_training_consent_required"
          : "invalid_request";
    return { ok: false, failure: { code, message: issuance.failure.message } };
  }

  input.sessions.setStatus(session.session_id, "approved");
  return {
    ok: true,
    grant: issuance.grant,
    consentEvidence: issuance.consentEvidence,
  };
}

/**
 * Deny an authorization. Terminal, and retains no consent evidence — there is
 * nothing the owner consented to, so there is nothing to hold evidence of.
 */
export function denyAuthorization(input: {
  sessions: AuthorizationSessionStore;
  tokens: PdppTokenService;
  sessionId: string;
  ownerToken: string | undefined;
  now?: Date;
}): { ok: true } | { ok: false; failure: ApprovalFailure } {
  const now = input.now ?? new Date();
  const auth = authenticateOwner(
    input.sessions,
    input.tokens,
    input.sessionId,
    input.ownerToken,
    now,
  );
  if (!auth.ok) return auth;

  if (auth.session.status !== "pending") {
    return {
      ok: false,
      failure: {
        code: "access_denied",
        message: "authorization session is already decided",
      },
    };
  }

  input.sessions.setStatus(auth.session.session_id, "denied");
  return { ok: true };
}
