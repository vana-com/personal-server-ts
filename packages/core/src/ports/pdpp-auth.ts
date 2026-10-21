/** AS → RS authorization seam. Temporal authority reuses the canonical AS type. */
export type PdppTokenKind = "owner" | "client";
export type AccessMode = "single_use" | "continuous";
export type SourceKind = "connector" | "provider_native";

export type { TimeConstraint } from "../pdpp/types.js";
import type { TimeConstraint } from "../pdpp/types.js";
import { withinTimeRange } from "../pdpp/time.js";

export interface StreamGrant {
  name: string;
  instance_ids: string[];
  fields: string[];
  time_constraint?: TimeConstraint;
  /** Canonical key strings. Absent means all records. */
  resources?: string[];
  /**
   * Candidate grants only: the schema-required fields frozen from the
   * retained declaration at issuance, a subset of `fields`. The RS takes its
   * sparse-read floor from this set, never from a later declaration.
   */
  required_fields?: string[];
}

export interface ClientDisplay {
  name?: string;
  [key: string]: unknown;
}

export interface Grant {
  /** `0.1.0` for a v0.1 grant, `0.2.0` for v0.2. */
  version: string;
  grant_id: string;
  issued_at: string;
  subject: { id: string };
  client: { client_id: string; client_display?: ClientDisplay };
  source: { kind: SourceKind; id: string };
  source_declaration: { version: string };
  purpose_code: string;
  purpose_description?: string;
  access_mode: AccessMode;
  streams: StreamGrant[];
  selection_preset?: string;
  retention?: { max_duration: string; on_expiry: "delete" | "anonymize" };
  expires_at?: string;
}

/**
 * The grant schema version a v0.2 grant carries. Mirrors the AS lane's
 * `PDPP_GRANT_VERSION_V02` (`packages/core/src/pdpp/types.ts`); kept as a
 * literal here for the same reason the rest of this file is a mirror.
 */
export const GRANT_VERSION_V02 = "0.2.0";

/**
 * True for a grant issued under the v0.2 detail type.
 *
 * The RS needs this because the two revisions disclose DIFFERENT record
 * shapes from the same grant members. Under v0.1 a stream's schema-required
 * fields are added to every projection (the per-stream consent floor); under
 * v0.2 that is forbidden — the disclosed members are exactly those the grant
 * approved, and nothing is added because a schema requires it. Enforcing one
 * rule for both would either undo the AS's v0.2 narrowing or silently shrink
 * what an already-consented v0.1 grant discloses.
 *
 * The Core candidate also retains its floor inside the frozen grant.
 * No profile adds fields that the grant does not name.
 */
export function grantIsV02(grant: Grant | undefined): boolean {
  return grant?.version === GRANT_VERSION_V02;
}

export type PdppInactiveReason =
  "unknown" | "expired" | "revoked" | "grant_revoked" | "grant_expired";

export interface PdppTokenContext {
  active: boolean;
  /**
   * Optional to match the real AS lane's type exactly (`feat/pdpp-as-grants`,
   * `packages/core/src/pdpp/types.ts`): an inactive token's context may omit
   * this entirely. Route code must not assume it is present without also
   * checking `active`.
   */
  tokenKind?: PdppTokenKind;
  subjectId?: string;
  /** Owner tokens only. The RS enforces this persisted scope directly. */
  instanceIds?: string[];
  /** Owner tokens only. Limits the token to one source's connections. */
  sourceId?: string;
  /** Client tokens only. */
  grant?: Grant;
  clientId?: string;
  expiresAt?: string;
  inactiveReason?: PdppInactiveReason;
}

/**
 * The single call this lane's route layer makes per request. A co-located
 * AS+RS deployment resolves this locally (Core §8 permits this); a separated
 * deployment would call RFC 7662 introspection instead — that wire path is
 * the AS lane's concern, not this lane's.
 */
/**
 * The PDPP authorization server, as the resource server sees it. Which kind
 * it is decides how a read's delivery lease re-checks the bearer at release
 * (see `pdppBearerReadLease`), so it is explicit:
 */
export type PdppAuthorizationService =
  LocalPdppAuthorizationService | RemotePdppAuthorizationService;

/**
 * An AS whose token and grant store is in this process (co-located). It must
 * resolve synchronously: the lease's last check uses `resolveTokenNow`, so a
 * revocation, expiry or family revocation takes effect at release, with
 * nothing awaited between that check and the release.
 */
export interface LocalPdppAuthorizationService {
  readonly locality: "local";
  resolveToken(accessToken: string): Promise<PdppTokenContext>;
  resolveTokenNow(accessToken: string): PdppTokenContext;
}

/**
 * An AS reached over the network (token introspection). Its answer is remote
 * evidence: the lease asks again once it is older than
 * `REMOTE_GRANT_REVERIFY_AFTER_MS` (30 s), and checks the answer and its
 * carried token expiry locally at release. A revocation at such an AS takes
 * effect within 30 s, under the documented remote-staleness policy.
 */
export interface RemotePdppAuthorizationService {
  readonly locality: "remote";
  resolveToken(accessToken: string): Promise<PdppTokenContext>;
}

/** Looks up the StreamGrant entry for a stream name, or undefined if not granted. */
export function findStreamGrant(
  grant: Grant,
  stream: string,
): StreamGrant | undefined {
  return grant.streams.find((s) => s.name === stream);
}

/**
 * Evaluates a TimeConstraint against a record's field value. `since` is
 * inclusive; `until` is EXCLUSIVE per the AS contract (not `<=`).
 */
export function withinTimeConstraint(
  value: string | undefined,
  constraint: TimeConstraint | undefined,
): boolean {
  return !constraint || withinTimeRange(value, constraint);
}
