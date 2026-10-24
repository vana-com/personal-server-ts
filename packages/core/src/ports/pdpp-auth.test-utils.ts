import type {
  LocalPdppAuthorizationService,
  PdppTokenContext,
} from "./pdpp-auth.js";
import { issueGrant } from "../pdpp/issuance.js";
import { parseDeclaration } from "../pdpp/declaration.js";
import { buildConsentReview, type RequesterIdentity } from "../pdpp/review.js";
import {
  resolveSelection,
  type InstanceInventory,
  type OwnerChoices,
} from "../pdpp/resolve.js";
import type {
  OwnerConditions,
  RecipientTerms,
  SelectionRequest,
} from "../pdpp/types.js";
import type { PdppAuthStore } from "../pdpp/store.js";

/** Issue and persist a grant using the same resolve, review, and approval path as the AS. */
export function issueAndStoreTestGrant(input: {
  store: PdppAuthStore;
  subjectId: string;
  declarationDocument: string;
  request: SelectionRequest;
  requester: RequesterIdentity;
  inventory: InstanceInventory;
  ownerChoices?: OwnerChoices;
  ownerConditions?: OwnerConditions;
  standingTerms?: RecipientTerms;
  explicitAiTrainingConsent?: boolean;
  expiresAt?: string;
  now?: Date;
}) {
  const parsed = parseDeclaration(
    input.declarationDocument,
    input.request.source.id,
  );
  if (!parsed.ok) {
    throw new Error(`invalid test declaration: ${parsed.failure.code}`);
  }
  const snapshot = parsed.snapshot;
  const resolution = resolveSelection(
    input.request,
    snapshot,
    input.inventory,
    input.ownerChoices,
  );
  if (!resolution.ok) {
    throw new Error(`unresolvable test grant: ${resolution.failure.code}`);
  }
  const review = buildConsentReview({
    subjectId: input.subjectId,
    request: input.request,
    snapshot,
    resolvedStreams: resolution.streams,
    omittedStreams: resolution.omittedStreams,
    requestedStreams: resolution.requestedStreams,
    requester: input.requester,
    ownerConditions: input.ownerConditions,
    standingTerms: input.standingTerms,
    expiresAt: input.expiresAt,
  });
  const issuance = issueGrant({
    subjectId: input.subjectId,
    request: input.request,
    snapshot,
    inventory: input.inventory,
    ownerChoices: input.ownerChoices,
    ownerConditions: input.ownerConditions,
    standingTerms: input.standingTerms,
    explicitAiTrainingConsent: input.explicitAiTrainingConsent,
    requester: input.requester,
    approvedReviewDigest: review.review_digest,
    expiresAt: input.expiresAt,
    now: input.now,
  });
  if (!issuance.ok) {
    throw new Error(`test grant issuance failed: ${issuance.failure.code}`);
  }
  input.store.retainDeclaration(snapshot, input.declarationDocument);
  input.store.insertGrant({
    grant: issuance.grant,
    subjectId: input.subjectId,
    reviewDigest: issuance.consentEvidence.review_digest,
    consentEvidence: issuance.consentEvidence,
  });
  return {
    ...issuance,
    snapshot,
    declarationDocument: input.declarationDocument,
  };
}

/**
 * Deterministic fixture PdppAuthorizationService for this lane's own route
 * tests. NOT a real AS integration — maps fixed token strings to fixed
 * PdppTokenContext values. When the AS lane's real implementation exists,
 * this is what gets swapped, not the PdppAuthorizationService interface.
 */
export function createFixtureAuthorizationService(
  tokens: Record<string, PdppTokenContext>,
): LocalPdppAuthorizationService {
  const resolveTokenNow = (accessToken: string): PdppTokenContext =>
    tokens[accessToken] ?? {
      active: false,
      tokenKind: "client",
      subjectId: "",
    };
  return {
    locality: "local",
    resolveTokenNow,
    async resolveToken(accessToken: string): Promise<PdppTokenContext> {
      return resolveTokenNow(accessToken);
    },
  };
}
