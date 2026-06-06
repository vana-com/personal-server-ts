const DATA_BLOCK_CURSOR_VERSION = 1;

export interface DataBlockCursor {
  version: 1;
  scope: string;
  collectedAt: string;
  blockIndex: number;
  intraBlockOffset?: number;
}

export interface EncodeDataBlockCursorInput {
  scope: string;
  collectedAt: string;
  blockIndex: number;
  intraBlockOffset?: number;
}

export type DataBlockCursorErrorCode =
  | "cursor_malformed"
  | "cursor_unsupported_version"
  | "cursor_scope_mismatch"
  | "cursor_collected_at_mismatch";

export interface DataBlockCursorError {
  code: DataBlockCursorErrorCode;
  message: string;
}

export type DecodeDataBlockCursorResult =
  | { ok: true; cursor: DataBlockCursor }
  | { ok: false; error: DataBlockCursorError };

export type ValidateDataBlockCursorResult = DecodeDataBlockCursorResult;

type SerializedDataBlockCursor = Record<string, unknown>;

export function encodeDataBlockCursor(
  input: EncodeDataBlockCursorInput,
): string {
  assertNonEmptyString(input.scope, "scope");
  assertNonEmptyString(input.collectedAt, "collectedAt");
  assertNonNegativeInteger(input.blockIndex, "blockIndex");
  if (input.intraBlockOffset !== undefined) {
    assertNonNegativeInteger(input.intraBlockOffset, "intraBlockOffset");
  }

  return encodeBase64Url(
    JSON.stringify({
      v: DATA_BLOCK_CURSOR_VERSION,
      scope: input.scope,
      collectedAt: input.collectedAt,
      blockIndex: input.blockIndex,
      ...(input.intraBlockOffset === undefined
        ? {}
        : { intraBlockOffset: input.intraBlockOffset }),
    }),
  );
}

export function decodeDataBlockCursor(
  cursor: string,
): DecodeDataBlockCursorResult {
  if (!cursor) {
    return malformedCursor("Cursor is required");
  }

  const decoded = decodeBase64Url(cursor);
  if (decoded === null) {
    return malformedCursor("Cursor is not valid base64url");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    return malformedCursor("Cursor payload is not valid JSON");
  }

  if (!isObject(parsed)) {
    return malformedCursor("Cursor payload must be an object");
  }

  const candidate = parsed as SerializedDataBlockCursor;
  if (candidate.v !== DATA_BLOCK_CURSOR_VERSION) {
    return {
      ok: false,
      error: {
        code: "cursor_unsupported_version",
        message:
          typeof candidate.v === "number"
            ? `Unsupported cursor version: ${candidate.v}`
            : "Cursor version is missing or invalid",
      },
    };
  }

  if (
    typeof candidate.scope !== "string" ||
    candidate.scope.length === 0 ||
    typeof candidate.collectedAt !== "string" ||
    candidate.collectedAt.length === 0 ||
    !isNonNegativeInteger(candidate.blockIndex) ||
    (candidate.intraBlockOffset !== undefined &&
      !isNonNegativeInteger(candidate.intraBlockOffset))
  ) {
    return malformedCursor("Cursor payload has invalid fields");
  }

  return {
    ok: true,
    cursor: {
      version: DATA_BLOCK_CURSOR_VERSION,
      scope: candidate.scope,
      collectedAt: candidate.collectedAt,
      blockIndex: candidate.blockIndex,
      ...(candidate.intraBlockOffset === undefined
        ? {}
        : { intraBlockOffset: candidate.intraBlockOffset }),
    },
  };
}

export function validateDataBlockCursor(
  cursor: string,
  expected: { scope: string; collectedAt: string },
): ValidateDataBlockCursorResult {
  const decoded = decodeDataBlockCursor(cursor);
  if (!decoded.ok) return decoded;

  if (decoded.cursor.scope !== expected.scope) {
    return {
      ok: false,
      error: {
        code: "cursor_scope_mismatch",
        message: "Cursor scope does not match requested scope",
      },
    };
  }

  if (decoded.cursor.collectedAt !== expected.collectedAt) {
    return {
      ok: false,
      error: {
        code: "cursor_collected_at_mismatch",
        message: "Cursor collectedAt does not match requested collectedAt",
      },
    };
  }

  return decoded;
}

function encodeBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeBase64Url(value: string): string | null {
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(
      base64.length + ((4 - (base64.length % 4)) % 4),
      "=",
    );
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function malformedCursor(message: string): DecodeDataBlockCursorResult {
  return {
    ok: false,
    error: {
      code: "cursor_malformed",
      message,
    },
  };
}

function assertNonEmptyString(value: string, field: string): void {
  if (value.length === 0) {
    throw new Error(`${field} must be a non-empty string`);
  }
}

function assertNonNegativeInteger(value: number, field: string): void {
  if (!isNonNegativeInteger(value)) {
    throw new Error(`${field} must be a non-negative integer`);
  }
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
