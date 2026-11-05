/**
 * Typed failures. Every error carries a stable `code` so callers in another
 * bundle can switch on it without `instanceof`.
 */

export type StreamSyncErrorCode =
  | "invalid-primary-key"
  | "invalid-record"
  | "invalid-observation-time"
  | "invalid-order-field"
  | "missing-key-field"
  | "non-canonical-value"
  | "invalid-part-size"
  | "malformed-head"
  | "unsupported-format-version"
  | "part-integrity"
  | "invalid-name"
  | "hash-unavailable"
  | "host-contract";

export class StreamSyncError extends Error {
  readonly code: StreamSyncErrorCode;

  constructor(
    code: StreamSyncErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

export class InvalidPrimaryKeyError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-primary-key", message);
  }
}

export class InvalidRecordError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-record", message);
  }
}

/** An observation time is not a non-negative safe integer (milliseconds). */
export class InvalidObservationTimeError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-observation-time", message);
  }
}

export class InvalidOrderFieldError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-order-field", message);
  }
}

/** A record has no value for one of the declared key fields. */
export class MissingKeyFieldError extends StreamSyncError {
  readonly source: "base" | "run";
  readonly index: number;
  readonly field: string;

  constructor(source: "base" | "run", index: number, field: string) {
    super(
      "missing-key-field",
      `${source} record ${index} has no value for key field "${field}"`,
    );
    this.source = source;
    this.index = index;
    this.field = field;
  }
}

/** A value outside the JSON model (undefined, NaN, Date, cycles, ...). */
export class NonCanonicalValueError extends StreamSyncError {
  constructor(message: string) {
    super("non-canonical-value", message);
  }
}

export class InvalidPartSizeError extends StreamSyncError {
  constructor(value: unknown) {
    super(
      "invalid-part-size",
      `part size must be a positive safe integer, got ${String(value)}`,
    );
  }
}

export class MalformedHeadError extends StreamSyncError {
  constructor(message: string) {
    super("malformed-head", message);
  }
}

export class UnsupportedFormatVersionError extends StreamSyncError {
  readonly format: unknown;

  constructor(format: unknown) {
    super(
      "unsupported-format-version",
      `unsupported head format version: ${String(format)}`,
    );
    this.format = format;
  }
}

export type PartIntegrityReason =
  "missing" | "length" | "hash" | "malformed" | "record-count" | "identity";

/** A fetched part, or the assembled result, does not match its head. */
export class PartIntegrityError extends StreamSyncError {
  readonly reason: PartIntegrityReason;
  readonly hash: string | undefined;

  constructor(
    reason: PartIntegrityReason,
    message: string,
    hash?: string,
    options?: ErrorOptions,
  ) {
    super("part-integrity", message, options);
    this.reason = reason;
    this.hash = hash;
  }
}

export class InvalidNameError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-name", message);
  }
}

export class HashUnavailableError extends StreamSyncError {
  constructor() {
    super(
      "hash-unavailable",
      "no SHA-256 implementation: inject a Sha256 port",
    );
  }
}

/** A host broke a documented port contract (reference host only). */
export class HostContractError extends StreamSyncError {
  constructor(message: string) {
    super("host-contract", message);
  }
}
