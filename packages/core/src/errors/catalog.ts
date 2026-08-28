/**
 * Typed error catalog mapping to Vana Data Portability Protocol spec §8.2.
 */

export class ProtocolError extends Error {
  constructor(
    public readonly code: number,
    public readonly errorCode: string,
    message: string,
    public readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = this.constructor.name;
  }

  toJSON(): Record<string, unknown> {
    return {
      error: {
        code: this.code,
        errorCode: this.errorCode,
        message: this.message,
        ...(this.details !== undefined && { details: this.details }),
      },
    };
  }
}

// 401 — Authentication errors

export class MissingAuthError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(401, "MISSING_AUTH", "Missing authentication", details);
  }
}

export class InvalidSignatureError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(401, "INVALID_SIGNATURE", "Invalid signature", details);
  }
}

export class UnregisteredBuilderError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(401, "UNREGISTERED_BUILDER", "Unregistered builder", details);
  }
}

export class NotOwnerError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(401, "NOT_OWNER", "Not the owner", details);
  }
}

export class ExpiredTokenError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(401, "EXPIRED_TOKEN", "Token has expired", details);
  }
}

// 403 — Authorization/grant errors

export class GrantRequiredError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(403, "GRANT_REQUIRED", "Grant required", details);
  }
}

export class GrantExpiredError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(403, "GRANT_EXPIRED", "Grant has expired", details);
  }
}

export class GrantRevokedError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(403, "GRANT_REVOKED", "Grant has been revoked", details);
  }
}

export class ScopeMismatchError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(403, "SCOPE_MISMATCH", "Scope not granted", details);
  }
}

export class GrantOwnerMismatchError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      403,
      "GRANT_OWNER_MISMATCH",
      "Grant was not issued by this server's owner",
      details,
    );
  }
}

export class FeeRequiredError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(403, "FEE_REQUIRED", "Required fee has not been paid", details);
  }
}

export class PsUnavailableError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      503,
      "PS_UNAVAILABLE",
      "Personal Server runtime unavailable",
      details,
    );
  }
}

export class ServerNotConfiguredError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(500, "SERVER_NOT_CONFIGURED", "Server is not configured", details);
  }
}

// 413 — Payload errors

export class ContentTooLargeError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(413, "CONTENT_TOO_LARGE", "Content too large", details);
  }
}

// Derivative data / lineage (see docs/derivative-data-api.md)

export class LineageInvalidError extends ProtocolError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(400, "LINEAGE_INVALID", message, details);
  }
}

export class LineageScopeUnderSourcePrefixError extends ProtocolError {
  constructor(details: { scope: string; sourceScope: string }) {
    super(
      400,
      "LINEAGE_SCOPE_UNDER_SOURCE_PREFIX",
      `Derived scope "${details.scope}" shares its first segment with source scope "${details.sourceScope}"; a wildcard grant on that namespace would read both. Name derivatives under their own namespace.`,
      details,
    );
  }
}

export class LineageSourceUnknownError extends ProtocolError {
  constructor(details: { unknown: string[] }) {
    super(
      422,
      "LINEAGE_SOURCE_UNKNOWN",
      "One or more lineage sources are not data points of this owner",
      details,
    );
  }
}

export class LineageSourceLookupFailedError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      502,
      "LINEAGE_SOURCE_LOOKUP_FAILED",
      "Could not resolve a lineage source at the gateway",
      details,
    );
  }
}

export class LineageUnavailableError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      503,
      "LINEAGE_UNAVAILABLE",
      "This server is not configured to reach the gateway lineage graph (gateway URL or server signing key missing)",
      details,
    );
  }
}

export class LineageGatewayError extends ProtocolError {
  constructor(details: { status: number; body: unknown }) {
    super(
      502,
      "LINEAGE_GATEWAY_ERROR",
      `Gateway lineage request failed with status ${details.status}`,
      details,
    );
  }
}

export class LineageCascadeUnavailableError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      501,
      "LINEAGE_CASCADE_UNAVAILABLE",
      "DELETE ?cascade=lineage is specified but not implemented yet: the lineage walk that finds every derivative is missing. Delete scopes one at a time; each single-scope delete is durable.",
      details,
    );
  }
}

export class InvalidCascadeError extends ProtocolError {
  constructor(details: { cascade: string }) {
    super(
      400,
      "INVALID_CASCADE",
      'Unsupported cascade mode; the only supported value is "lineage"',
      details,
    );
  }
}

// 502 - Upstream (gateway) errors

export class DeleteTombstoneFailedError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      502,
      "DELETE_TOMBSTONE_FAILED",
      "Gateway did not acknowledge the deletion tombstone; nothing was deleted",
      details,
    );
  }
}

// 410 - Deleted resources

export class DataDeletedError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(410, "DATA_DELETED", "Data point has been deleted", details);
  }
}

// Derivative compute (see docs/derivative-data-api.md, "Compute")

export class DerivativeQuestionInvalidError extends ProtocolError {
  constructor(message: string, details?: Record<string, unknown>) {
    super(400, "DERIVATIVE_QUESTION_INVALID", message, details);
  }
}

export class DerivativeQuestionNotFoundError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(404, "DERIVATIVE_QUESTION_NOT_FOUND", "Question not found", details);
  }
}

export class DerivativeCycleError extends ProtocolError {
  constructor(details: { derivedScope: string; path: string[] }) {
    super(
      409,
      "DERIVATIVE_CYCLE",
      `Registering this question would make "${details.derivedScope}" a transitive source of itself; recompute would never settle`,
      details,
    );
  }
}

export class DerivativeSourceNotGrantedError extends ProtocolError {
  constructor(details: { scopes: string[] }) {
    super(
      403,
      "DERIVATIVE_SOURCE_NOT_GRANTED",
      "The builder's grant does not cover reading every source scope of this question",
      details,
    );
  }
}

export class DerivativeComputeUnavailableError extends ProtocolError {
  constructor(details?: Record<string, unknown>) {
    super(
      503,
      "DERIVATIVE_COMPUTE_UNAVAILABLE",
      "This server has no derivative compute configured",
      details,
    );
  }
}
