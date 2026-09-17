/**
 * PDPP error catalog, spec-core.md Section 8 "Errors". This is a NEW,
 * separate catalog — it does NOT replace `./catalog.ts`, which serves the
 * existing non-PDPP Vana/DPP callers.
 *
 * Error shape is fixed by the spec:
 *   { error: { type, code, message, param?, request_id } }
 */

export type PdppErrorType =
  | "invalid_request_error"
  | "authentication_error"
  | "permission_error"
  | "not_found_error"
  | "gone_error"
  | "rate_limit_error"
  | "api_error";

export type PdppErrorCode =
  | "invalid_cursor"
  | "invalid_request"
  | "invalid_expand"
  | "unknown_field"
  | "unsupported_version"
  | "authentication_error"
  | "authorization_state.unsupported_legacy_shape"
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

const STATUS_BY_CODE: Record<PdppErrorCode, number> = {
  invalid_cursor: 400,
  invalid_request: 400,
  invalid_expand: 400,
  unknown_field: 400,
  unsupported_version: 400,
  authentication_error: 401,
  "authorization_state.unsupported_legacy_shape": 401,
  field_not_granted: 403,
  insufficient_scope: 403,
  grant_stream_not_allowed: 403,
  grant_time_range_exceeded: 403,
  grant_expired: 403,
  grant_revoked: 403,
  grant_invalid: 403,
  blob_not_found: 404,
  not_found: 404,
  cursor_expired: 410,
  rate_limit_exceeded: 429,
  api_error: 500,
};

const TYPE_BY_CODE: Record<PdppErrorCode, PdppErrorType> = {
  invalid_cursor: "invalid_request_error",
  invalid_request: "invalid_request_error",
  invalid_expand: "invalid_request_error",
  unknown_field: "invalid_request_error",
  unsupported_version: "invalid_request_error",
  authentication_error: "authentication_error",
  "authorization_state.unsupported_legacy_shape": "authentication_error",
  field_not_granted: "permission_error",
  insufficient_scope: "permission_error",
  grant_stream_not_allowed: "permission_error",
  grant_time_range_exceeded: "permission_error",
  grant_expired: "permission_error",
  grant_revoked: "permission_error",
  grant_invalid: "permission_error",
  blob_not_found: "not_found_error",
  not_found: "not_found_error",
  cursor_expired: "gone_error",
  rate_limit_exceeded: "rate_limit_error",
  api_error: "api_error",
};

export interface PdppErrorBody {
  error: {
    type: PdppErrorType;
    code: PdppErrorCode;
    message: string;
    param?: string;
    request_id: string;
  };
}

/**
 * A PDPP §8 error. `status` is derived from `code` per the spec's Errors
 * table; callers should not need to pass it explicitly, but MAY override for
 * a future code this catalog doesn't yet know (fails loudly instead of
 * silently defaulting to 500 for a real, known code).
 */
export class PdppError extends Error {
  public readonly status: number;
  public readonly code: PdppErrorCode;
  public readonly type: PdppErrorType;
  public readonly param?: string;

  constructor(
    code: PdppErrorCode,
    message: string,
    options?: { param?: string },
  ) {
    super(message);
    this.name = "PdppError";
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.type = TYPE_BY_CODE[code];
    this.param = options?.param;
  }

  toJSON(requestId: string): PdppErrorBody {
    return {
      error: {
        type: this.type,
        code: this.code,
        message: this.message,
        ...(this.param !== undefined && { param: this.param }),
        request_id: requestId,
      },
    };
  }
}
