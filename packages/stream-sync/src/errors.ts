/**
 * Typed failures. Every error carries a stable `code` so callers in another
 * bundle can switch on it without `instanceof`.
 *
 * Errors are for inputs a caller must never pass (a malformed name, a value
 * outside JSON). Expected outcomes of the protocol (`key_mismatch`,
 * `record_too_large`, `unsupported_format`, ...) are returned as values.
 */

export type StreamSyncErrorCode =
  | "non-canonical-value"
  | "invalid-name"
  | "invalid-record"
  | "missing-key-field"
  | "invalid-line"
  | "invalid-part"
  | "invalid-argument";

export class StreamSyncError extends Error {
  readonly code: StreamSyncErrorCode;

  constructor(code: StreamSyncErrorCode, message: string) {
    super(message);
    this.name = new.target.name;
    this.code = code;
  }
}

/** A value outside the JSON model (undefined, NaN, Date, cycles, ...). */
export class NonCanonicalValueError extends StreamSyncError {
  constructor(message: string) {
    super("non-canonical-value", message);
  }
}

/** A name cannot be built: a permanent error, never retried. */
export class InvalidNameError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-name", message);
  }
}

export class InvalidRecordError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-record", message);
  }
}

/** A record has no own property for one of the primary-key fields. */
export class MissingKeyFieldError extends StreamSyncError {
  readonly field: string;

  constructor(field: string) {
    super("missing-key-field", `record has no value for key field "${field}"`);
    this.field = field;
  }
}

/** A part line is not `{"o":<ms>,"r":"<runId>","v":<record>}` in canonical form. */
export class InvalidLineError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-line", message);
  }
}

/** Part bytes do not match their head entry, or break the part grammar. */
export class InvalidPartError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-part", message);
  }
}

export class InvalidArgumentError extends StreamSyncError {
  constructor(message: string) {
    super("invalid-argument", message);
  }
}
