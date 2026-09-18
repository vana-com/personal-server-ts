/**
 * PDPP Core v0.1.0 authorization types.
 *
 * These mirror the normative field tables in PDPP Core §6 (Selection Request)
 * and §7 (Grant). Where this file and the spec disagree, the spec wins — §7
 * says so explicitly about its own TypeScript mirror.
 *
 * The PDPP grant model is deliberately separate from the Vana chain grant in
 * `../grants/`. That one is an EIP-712 payload binding a builder address to
 * dot-scopes; this one is an RFC 9396 consent artifact binding an OAuth client
 * to declaration-resolved streams. They are different authorities over
 * different data and must not be conflated.
 */

/** The RFC 9396 `type` value that marks an authorization detail as PDPP. */
export const PDPP_DATA_ACCESS_TYPE = "https://pdpp.dev/data-access";

/**
 * The v0.2 RFC 9396 `type`.
 *
 * v0.2 is deliberately a *separate* detail type rather than a compatible
 * extension of v0.1. The revision changes authorization resolution (explicit
 * minima) and disclosed-record semantics (a schema's `required` array is no
 * longer a consent floor), so the two are not wire-compatible: the same
 * request body resolves to a different grant under each. An AS implementing
 * both MUST resolve each under its own revision, which is why every rule below
 * branches on this constant rather than on the presence of a v0.2-only member.
 *
 * A client MUST NOT retry a rejected v0.2 request under the v0.1 type without
 * a new authorization decision; nothing here silently downgrades one.
 */
export const PDPP_DATA_ACCESS_TYPE_V02 = "https://pdpp.dev/data-access/0.2";

/** The v0.1 grant schema version. */
export const PDPP_GRANT_VERSION = "0.1.0";

/** The v0.2 grant schema version, issued for `PDPP_DATA_ACCESS_TYPE_V02`. */
export const PDPP_GRANT_VERSION_V02 = "0.2.0";

/**
 * The PDPP HTTP API contract version, sent and echoed in the `PDPP-Version`
 * header. Normative value from Core §8 "API versioning".
 *
 * §7 "Version layering" is explicit that the three version axes MUST NOT be
 * conflated, and this is the one that is easiest to get wrong: it is the HTTP
 * *contract* version, not `PDPP_GRANT_VERSION` (the grant schema, `0.1.0`) and
 * not `source_declaration.version` (an opaque declaration revision). This
 * previously carried the grant schema version, which meant a client pinning
 * the spec's own header value was rejected by the AS while the RS accepted it —
 * a client could reach only half the server.
 *
 * Both the AS and RS surfaces import this one constant so they cannot drift
 * apart again.
 */
export const PDPP_API_VERSION = "2026-04-06";

/**
 * The one purpose code Core gives a protocol-level consent requirement
 * (§6 "AI training consent"). Every other code is a structured policy
 * declaration the AS displays but does not gate on.
 */
export const AI_TRAINING_PURPOSE = "https://pdpp.dev/purpose/ai_training";

export type AccessMode = "single_use" | "continuous";

/**
 * Provenance class. A selection request never carries this — the AS derives it
 * from the declaration it accepted for `source.id` (§6 "Source kinds").
 */
export type SourceKind = "connector" | "provider_native";

/** RFC 7591-aligned inline client metadata, minus the redundant `client_` prefix. */
export interface ClientDisplay {
  name: string;
  uri?: string;
  logo_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
}

// ---------------------------------------------------------------------------
// Selection request (§6)
// ---------------------------------------------------------------------------

export interface TimeRange {
  /** Inclusive lower bound (>=). */
  since?: string;
  /** Exclusive upper bound (<). */
  until?: string;
}

/**
 * A v0.2 explicit authorization minimum: the floor below which the owner's
 * narrowing cannot go without failing issuance for this stream.
 *
 * This describes *permission*, never data. A satisfied minimum says the grant
 * permits those fields and that window; it asserts nothing about whether
 * records exist in it, how fresh they are, or whether they suit the client's
 * task. The client evaluates application sufficiency separately.
 */
export interface StreamMinimum {
  /** Non-empty; declared top-level field names drawn from the expanded request. */
  fields?: string[];
  /** Both bounds finite, `since < until`; must sit inside the requested window. */
  time_range?: { since: string; until: string };
}

export interface StreamRequest {
  /** Stream name, or `*` for every stream in the retained declaration. */
  name: string;
  /** `required` (default) or `optional`; optional streams become owner choices. */
  necessity?: "required" | "optional";
  instance_ids?: string[];
  time_range?: TimeRange;
  /** Named AS view. Mutually exclusive with `fields`. */
  view?: string;
  /** Field allowlist, top-level names only. Mutually exclusive with `view`. */
  fields?: string[];
  /** Canonical key strings for specific records. */
  resources?: string[];
  /**
   * v0.2 only. The AS recognizes exactly `fields` and `time_range` here and
   * rejects anything else — an unknown member would otherwise read as a
   * satisfied condition the client believes it imposed.
   */
  minimum?: StreamMinimum;
}

/**
 * Client-authored, unverifiable statements about this specific request.
 * Request-scoped, not entity-scoped. These never enter the resolved grant.
 */
export interface ClientClaims {
  commitments?: string[];
}

export interface Retention {
  /** ISO 8601 duration. */
  max_duration: string;
  /** `archive` is not supported in v0.1. */
  on_expiry: "delete" | "anonymize";
}

/**
 * Standing terms the recipient has already authorized, as the AS knows them.
 *
 * v0.2 draws a line the protocol cannot enforce after disclosure but can
 * enforce before it: changing the *data selection* is the owner's to do, while
 * changing the *terms of use* requires the recipient's authority. An owner can
 * narrow what they share freely; an owner asking the recipient to hold it for
 * a week instead of a month is proposing a different obligation, and PDPP must
 * not record that as agreed when nobody agreed to it.
 *
 * The accepted lists are enumerations, not capabilities. A recipient that
 * accepts a 7-day retention has accepted 7 days — not "whatever the owner
 * asks, up to 7 days", and not "the ability to accept retention terms". v0.2
 * is explicit that a capability advertisement alone is not acceptance.
 */
export interface RecipientTerms {
  /** Identifies the terms. Retained with the consent evidence. */
  id: string;
  /**
   * The version in force. Retained too: "the recipient agreed" is
   * unfalsifiable later if the document can change and nothing records which
   * text was in force at approval.
   */
  version: string;
  /** Retention terms the recipient has accepted, exactly. */
  accepted_retention?: Retention[];
  /** Purpose codes the recipient has accepted, exactly. */
  accepted_purpose_codes?: string[];
}

/**
 * Conditions the owner attached to their approval, beyond narrowing the data.
 *
 * These are *proposals*, not decisions: each must be covered by the request or
 * by recipient-authorized standing terms before it can become a commitment.
 */
export interface OwnerConditions {
  retention?: Retention;
  purpose_code?: string;
}

/** One RFC 9396 `authorization_details` entry of PDPP type. */
export interface SelectionRequest {
  type: typeof PDPP_DATA_ACCESS_TYPE | typeof PDPP_DATA_ACCESS_TYPE_V02;
  /** A request carries `id` alone; provenance is derived, never asserted. */
  source: { id: string };
  purpose_code: string;
  purpose_description?: string;
  access_mode: AccessMode;
  retention?: Retention;
  /** Required unless `selection_preset` is used. Exactly one of the two. */
  streams?: StreamRequest[];
  /** Alternative to explicit streams. Exactly one of the two. */
  selection_preset?: string;
  client_claims?: ClientClaims;
}

// ---------------------------------------------------------------------------
// Grant (§7)
// ---------------------------------------------------------------------------

export interface TimeConstraint {
  /** Frozen `consent_time_field` from the retained declaration. */
  field: string;
  /** Inclusive (>=). */
  since?: string;
  /** Exclusive (<). A hard cap: applies to future records as well as past. */
  until?: string;
}

export interface StreamGrant {
  /** Always concrete. Issued grants never contain wildcards. */
  name: string;
  /** Unique, non-empty. Fan-in only when more than one handle is listed. */
  instance_ids: string[];
  /** Unique, non-empty, resolved. Authoritative for RS enforcement. */
  fields: string[];
  time_constraint?: TimeConstraint;
  /** Canonical key strings. Absent means all records in the stream. */
  resources?: string[];
}

/**
 * What the client asked for on one stream, as the grant records it alongside
 * what was approved.
 *
 * v0.2 requires the grant to be the client's source of truth for the outcome,
 * including any narrowing the owner applied. Without this the client cannot
 * tell a narrowed grant from the request it sent — the approved `StreamGrant`
 * alone is indistinguishable from an unnarrowed one, so a client would have to
 * diff against its own memory of the request, which §7 forbids it from
 * treating as authority.
 */
export interface RequestedStream {
  name: string;
  necessity: "required" | "optional";
  /** The upper field limit as expanded from the request, before owner choices. */
  fields: string[];
  time_range?: TimeRange;
  minimum?: StreamMinimum;
}

/** The v0.2 requested-vs-approved record. Absent on v0.1 grants. */
export interface RequestedSelection {
  streams: RequestedStream[];
  /** Requested stream names the owner declined. Only optional streams can appear. */
  omitted_streams?: string[];
}

export interface Grant {
  /** `0.1.0` for v0.1 grants, `0.2.0` for v0.2. */
  version: string;
  grant_id: string;
  issued_at: string;
  subject: { id: string };
  client: { client_id: string; client_display?: ClientDisplay };
  /** Retained verbatim from the accepted declaration. */
  source: { kind: SourceKind; id: string };
  /** Opaque revision of the exact snapshot used, not a live lookup authority. */
  source_declaration: { version: string };
  purpose_code: string;
  purpose_description?: string;
  access_mode: AccessMode;
  streams: StreamGrant[];
  /** Informational; the resolved streams stay authoritative. */
  selection_preset?: string;
  retention?: Retention;
  /** Absent means no expiry. */
  expires_at?: string;
  /**
   * v0.2: what the client requested, beside the approved `streams` above.
   * Absent on v0.1 grants, whose contract has no such member.
   */
  requested?: RequestedSelection;
}

/** True for a grant issued under the v0.2 detail type. */
export function isV02Grant(grant: Grant): boolean {
  return grant.version === PDPP_GRANT_VERSION_V02;
}

// ---------------------------------------------------------------------------
// Source declaration snapshot (§5, only the parts §6/§7 resolution needs)
// ---------------------------------------------------------------------------

export interface DeclaredStream {
  name: string;
  /**
   * How records in this stream behave over time (§5).
   *
   * `mutable_state` records are upserted by key and carry version history;
   * `append_only` records are immutable, so a duplicate key is a no-op rather
   * than an update. Optional, defaulting to `mutable_state`, so declarations
   * written before this field existed keep their current meaning exactly.
   *
   * Before this existed the RS hardcoded `mutable_state` for every stream,
   * which made an `append_only` declaration silently coerced and the field
   * unfalsifiable for an ingesting producer.
   */
  semantics?: "mutable_state" | "append_only";
  /** Top-level field names the stream's schema defines. */
  fields: string[];
  /**
   * Fields a record of this stream cannot be valid without. Always included in
   * a resolved field set regardless of the requested allowlist — the per-stream
   * consent floor (§6 "Note on `fields`").
   */
  required_fields: string[];
  /**
   * Presence is the authoritative signal that the stream is time-range-capable
   * (§6 "Note on `time_range`").
   */
  consent_time_field?: string;
  /** Arity of the primary key; `resources` entries are validated against it. */
  primary_key: string[];
  /** The stream's JSON Schema from a normative §5 declaration, when present. */
  schema?: Record<string, unknown>;
  /** Declared selection capabilities, e.g. `{ fields: true, resources: false }`. */
  selection?: Record<string, unknown>;
}

export interface DeclaredView {
  name: string;
  fields: string[];
}

export interface DeclaredPreset {
  name: string;
  streams: StreamRequest[];
}

/**
 * The exact declaration snapshot retained through validation, consent,
 * issuance, and consent evidence. A later current declaration never
 * substitutes for it (§9 AS item 16).
 */
export interface DeclarationSnapshot {
  source_id: string;
  source_kind: SourceKind;
  /** Opaque revision identifier recorded into the grant. */
  version: string;
  /** Digest over the retrieved document, verified before the snapshot is trusted. */
  digest: string;
  streams: DeclaredStream[];
  views?: DeclaredView[];
  selection_presets?: DeclaredPreset[];
}

// ---------------------------------------------------------------------------
// Introspection (§8)
// ---------------------------------------------------------------------------

export type PdppTokenKind = "owner" | "client";

export interface PdppAuthorizationDetail {
  type: typeof PDPP_DATA_ACCESS_TYPE;
  source: { kind: SourceKind; id: string };
  purpose_code: string;
  purpose_description?: string;
  access_mode: AccessMode;
  streams: StreamGrant[];
}

/**
 * The v0.2 client-visible authorization result: `{ type, grant }` carrying the
 * complete immutable grant.
 *
 * v0.2 forbids substituting the original selection request or a lossy summary.
 * The v0.1 detail above is exactly such a summary — it drops `retention`,
 * `expires_at`, the resolved client identity, and (under v0.2) the
 * requested-vs-approved record — so v0.2 carries the whole grant instead of a
 * projection of it. Both shapes coexist: a token covering a v0.1 grant still
 * returns the v0.1 detail, so an existing client sees no change.
 */
export interface PdppAuthorizationResultV02 {
  type: typeof PDPP_DATA_ACCESS_TYPE_V02;
  grant: Grant;
}

/** Either revision's element, as it appears in `authorization_details`. */
export type PdppAuthorizationEntry =
  | PdppAuthorizationDetail
  | PdppAuthorizationResultV02;

/**
 * RFC 7662 introspection response with the PDPP extension members. An inactive
 * token returns exactly `{ active: false }` — RFC 7662 §2.2 forbids leaking
 * anything else about a token that is revoked, expired, or simply unknown.
 */
export interface PdppIntrospectionResponse {
  active: boolean;
  pdpp_token_kind?: PdppTokenKind;
  subject_id?: string;
  grant_id?: string;
  client_id?: string;
  /** Unix epoch seconds. Omitted when the token never expires. */
  exp?: number;
  /**
   * One element per covered grant, in that grant's own revision shape. v0.2
   * requires the AS to return the same resolved grant facts to the client and
   * to an authenticated RS apart from token-specific active-state and expiry,
   * which is why this is the same projection the token response uses.
   */
  authorization_details?: PdppAuthorizationEntry[];
}

/** Why a token did not resolve. Drives the RS error; never echoed to the client. */
export type InactiveReason =
  "unknown" | "expired" | "revoked" | "grant_revoked" | "grant_expired";

/**
 * The co-located equivalent of an introspection call. The RS resolves a token
 * through this one path and enforces only from the result (§8 "Grant
 * enforcement"): no second authority, no live declaration lookup.
 */
export interface PdppTokenContext {
  active: boolean;
  tokenKind?: PdppTokenKind;
  subjectId?: string;
  /** Client tokens only. An owner token carries no grant. */
  grant?: Grant;
  clientId?: string;
  expiresAt?: string;
  inactiveReason?: InactiveReason;
}

export type GrantStatus = "active" | "expired" | "revoked";
