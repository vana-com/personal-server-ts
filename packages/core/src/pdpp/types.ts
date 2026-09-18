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

/** The grant schema version this implementation issues and accepts. */
export const PDPP_GRANT_VERSION = "0.1.0";

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

/** One RFC 9396 `authorization_details` entry of PDPP type. */
export interface SelectionRequest {
  type: typeof PDPP_DATA_ACCESS_TYPE;
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

export interface Grant {
  /** This contract requires exactly `0.1.0`. */
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
  authorization_details?: PdppAuthorizationDetail[];
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
