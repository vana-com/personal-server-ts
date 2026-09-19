/**
 * PDPP AS -> RS seam types, MIRRORED from `pdpp-ps-auth-v2-0917`'s published
 * contract (`~/code/pdpp/local/conformance-fleet-0917/ps-auth-contract.md`,
 * branch `feat/pdpp-as-grants`), not authored here.
 *
 * The AS lane owns `packages/core/src/pdpp/**` on its own branch. That branch
 * is not merged as of this lane's implementation, so these types are a local
 * mirror this lane's route/enforcement layer codes against now. When the AS
 * branch merges, this file should be deleted and its imports repointed at
 * `@opendatalabs/personal-server-ts-core/pdpp` — the shapes below are meant
 * to be identical, not a superset or a simplification.
 *
 * DO NOT widen these beyond the AS contract. In particular:
 * - `TimeConstraint.until` is EXCLUSIVE (`record[field] < until`), not `<=`.
 * - Field projection, instance scoping, and time constraint are PER STREAM
 *   (`StreamGrant`), not grant-wide.
 */

export type PdppTokenKind = "owner" | "client";
export type AccessMode = "single_use" | "continuous";
export type SourceKind = "connector" | "provider_native";

export interface TimeConstraint {
  /** Frozen declaration field the bounds are evaluated against. */
  field: string;
  /** Inclusive lower bound (record[field] >= since). ISO 8601. */
  since?: string;
  /** Exclusive upper bound (record[field] < until). ISO 8601. */
  until?: string;
}

export interface StreamGrant {
  name: string;
  instance_ids: string[];
  fields: string[];
  time_constraint?: TimeConstraint;
  /** Canonical key strings. Absent means all records. */
  resources?: string[];
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
 * An unrecognized version reads as v0.1: the conservative direction is to
 * keep the floor, which discloses no field the grant does not name.
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
export interface PdppAuthorizationService {
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
  if (!constraint) return true;
  if (value === undefined) return false;
  if (constraint.since !== undefined && value < constraint.since) return false;
  if (constraint.until !== undefined && value >= constraint.until) return false;
  return true;
}
