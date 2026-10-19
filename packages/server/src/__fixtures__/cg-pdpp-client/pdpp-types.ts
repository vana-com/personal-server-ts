/**
 * PDPP Core §8 (Resource Server Interface) request/response types.
 *
 * Cited against `PDP-Connect/pdpp` `apps/site/content/docs/spec-core.md`
 * section 8 (`#resource-server-interface`) as of 2026-09-17. This module is
 * intentionally the *only* place that names PDPP wire shapes for the Client
 * role — do not redeclare `PdppRecord`/`PdppListRecordsResponse`/etc. inline
 * at a call site.
 *
 * PS's actual §8 endpoints have not landed yet (no PR in
 * vana-com/personal-server-ts implements them as of this writing; see
 * `local/conformance-fleet-0917/scope-lanes.md` Lane B/C in the pdpp repo).
 * These types are derived directly from the spec text, not from PS's
 * implementation — per that same plan's warning against reverse-engineering
 * a vendor's behavior instead of the normative document.
 */

/** Spec §8 "Errors": every non-2xx response has this envelope. */
export interface PdppErrorBody {
  error: {
    type: PdppErrorType;
    code: PdppErrorCode;
    message: string;
    param?: string;
    request_id?: string;
  };
}

export type PdppErrorType =
  | "invalid_request_error"
  | "authentication_error"
  | "permission_error"
  | "not_found_error"
  | "gone_error"
  | "rate_limit_error"
  | "api_error";

/** Spec §8 error table, `#errors`. */
export type PdppErrorCode =
  | "invalid_cursor"
  | "invalid_request"
  | "invalid_record"
  | "invalid_record_identity"
  | "invalid_expand"
  | "unknown_field"
  | "unsupported_version"
  | "authentication_error"
  | "field_not_granted"
  | "insufficient_scope"
  | "grant_stream_not_allowed"
  | "grant_time_range_exceeded"
  | "grant_expired"
  | "grant_revoked"
  | "grant_invalid"
  | "blob_not_found"
  | "not_found"
  | "cursor_expired"
  | "rate_limit_exceeded"
  | "api_error";

export interface PdppFreshness {
  captured_at: string | null;
  status: "current" | "stale" | "unknown";
  last_attempted_at: string | null;
}

/** Spec §8 "List streams". */
export interface PdppStreamListItem {
  object: "stream";
  name: string;
  record_count: number;
  last_updated: string;
  freshness?: PdppFreshness;
}

export interface PdppListStreamsResponse {
  object: "list";
  data: PdppStreamListItem[];
}

/** Spec §8 "Get stream metadata". Not grant-projected. */
export interface PdppStreamMetadata {
  object: "stream_metadata";
  name: string;
  schema: Record<string, unknown>;
  primary_key: string[];
  cursor_field: string;
  consent_time_field: string;
  selection: { fields: boolean; resources: boolean };
  query?: {
    range_filters?: Record<string, Array<"gte" | "gt" | "lte" | "lt">>;
    expand?: Array<{ name: string; default_limit: number; max_limit: number }>;
  };
  freshness?: PdppFreshness;
  views?: Array<{ id: string; label: string; fields: string[] }>;
  relationships?: Array<{
    name: string;
    stream: string;
    foreign_key: string;
    cardinality: "has_one" | "has_many";
  }>;
}

/** Spec §4 "The RECORD envelope" / §8 list-records response item. */
export interface PdppRecord {
  object: "record";
  id: string;
  stream: string;
  data: Record<string, unknown>;
  emitted_at: string;
  expanded?: Record<string, PdppRecord[] | PdppRecord>;
}

/** Spec §4 "Tombstones": present in `changes_since` responses for deletions. */
export interface PdppTombstone {
  object: "tombstone";
  id: string;
  stream: string;
  deleted_at: string;
}

/** Spec §8 "Non-fatal warnings", `meta.warnings[]`. */
export interface PdppWarning {
  code: string;
  message: string;
}

/** Spec §8 "List records" query parameters — the durable v0.1 base surface. */
export interface PdppListRecordsParams {
  limit?: number;
  cursor?: string;
  order?: "asc" | "desc";
  /** `filter[{field}]` and `filter[{field}][gte|gt|lte|lt]`, keyed by field name. */
  filter?: Record<
    string,
    string | Partial<Record<"gte" | "gt" | "lte" | "lt", string>>
  >;
  view?: string;
  fields?: string[];
  expand?: string[];
  expand_limit?: Record<string, number>;
  /** Opaque incremental-sync token — a distinct token space from `cursor`. */
  changes_since?: string;
}

export interface PdppListRecordsResponse {
  object: "list";
  url: string;
  has_more: boolean;
  next_cursor?: string;
  /** Present only on the terminal page of a `changes_since` request. */
  next_changes_since?: string;
  freshness?: PdppFreshness;
  data: Array<PdppRecord | PdppTombstone>;
  meta?: { warnings?: PdppWarning[] };
}

export interface PdppGetRecordParams {
  expand?: string[];
}

/** Spec §8 API versioning: request/response header name and stable value used by this client. */
export const PDPP_VERSION_HEADER = "PDPP-Version";
export const PDPP_VERSION = "2026-04-06";
export const PDPP_REQUEST_ID_HEADER = "Request-Id";
