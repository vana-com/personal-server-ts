import { describe, expect, it } from "vitest";

import {
  decodeDataBlockCursor,
  encodeDataBlockCursor,
  validateDataBlockCursor,
} from "./cursor.js";

const SCOPE = "instagram.profile";
const COLLECTED_AT = "2026-01-21T10:00:00Z";

function encodeRawCursor(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

describe("data block cursor helpers", () => {
  it("round trips a cursor with an intra-block offset", () => {
    const encoded = encodeDataBlockCursor({
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      blockIndex: 12,
      intraBlockOffset: 34,
    });

    const decoded = validateDataBlockCursor(encoded, {
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
    });

    expect(decoded).toEqual({
      ok: true,
      cursor: {
        version: 1,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        blockIndex: 12,
        intraBlockOffset: 34,
      },
    });
  });

  it("rejects a cursor for the wrong scope", () => {
    const encoded = encodeDataBlockCursor({
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      blockIndex: 1,
    });

    const decoded = validateDataBlockCursor(encoded, {
      scope: "twitter.profile",
      collectedAt: COLLECTED_AT,
    });

    expect(decoded).toEqual({
      ok: false,
      error: {
        code: "cursor_scope_mismatch",
        message: "Cursor scope does not match requested scope",
      },
    });
  });

  it("rejects a cursor for the wrong collectedAt", () => {
    const encoded = encodeDataBlockCursor({
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      blockIndex: 1,
    });

    const decoded = validateDataBlockCursor(encoded, {
      scope: SCOPE,
      collectedAt: "2026-01-22T10:00:00Z",
    });

    expect(decoded).toEqual({
      ok: false,
      error: {
        code: "cursor_collected_at_mismatch",
        message: "Cursor collectedAt does not match requested collectedAt",
      },
    });
  });

  it("rejects a malformed cursor", () => {
    const decoded = decodeDataBlockCursor("not-valid-json");

    expect(decoded).toEqual({
      ok: false,
      error: {
        code: "cursor_malformed",
        message: "Cursor payload is not valid JSON",
      },
    });
  });

  it("rejects a cursor with missing or invalid fields", () => {
    const decoded = decodeDataBlockCursor(
      encodeRawCursor({
        v: 1,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        blockIndex: -1,
      }),
    );

    expect(decoded).toEqual({
      ok: false,
      error: {
        code: "cursor_malformed",
        message: "Cursor payload has invalid fields",
      },
    });
  });

  it("rejects a future or unknown version", () => {
    const decoded = decodeDataBlockCursor(
      encodeRawCursor({
        v: 2,
        scope: SCOPE,
        collectedAt: COLLECTED_AT,
        blockIndex: 1,
      }),
    );

    expect(decoded).toEqual({
      ok: false,
      error: {
        code: "cursor_unsupported_version",
        message: "Unsupported cursor version: 2",
      },
    });
  });
});
