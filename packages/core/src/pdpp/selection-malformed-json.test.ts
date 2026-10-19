/**
 * The independent review's finding 4 repro, widened into a table.
 *
 * The finding: the HTTP body is untrusted JSON, but validation assumed typed
 * members. `minimum.time_range: null`, `streams[].fields: null`, and
 * `streams[].resources: null` each threw a `TypeError` instead of returning a
 * validation failure. Through the AS route that becomes a 500 rather than the
 * required 400 `invalid_authorization_details`/`invalid_request`.
 *
 * Why this is worth more than three assertions. `validateSelectionRequest` is
 * the *first* thing an unauthenticated client's body reaches. Its contract is
 * total: every input is either `{ok: true}` or a typed failure, and a thrown
 * exception is neither. A 500 here is also a worse answer than a wrong error
 * code — it tells a prober they reached an unguarded path, and it gives a
 * client no way to tell "I sent the wrong shape" from "the server is broken".
 *
 * So the table below is deliberately mechanical rather than curated: for each
 * member that validation reads, substitute the JSON values a TypeScript type
 * cannot exclude — `null`, the wrong container, a primitive where an object
 * belongs. The three shapes the reviewer listed are marked; the rest were
 * found by running exactly this substitution and each threw as well.
 *
 * The assertion is the contract, not the code: a typed failure comes back,
 * and nothing throws. Which specific code is asserted only where the spec
 * fixes it.
 */

import { describe, expect, it } from "vitest";
import { validateSelectionRequest } from "./selection.js";
import {
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "b".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount"],
      required_fields: ["date"],
      consent_time_field: "date",
      primary_key: ["date"],
    },
  ],
  selection_presets: [{ name: "basic", streams: [{ name: "transactions" }] }],
};

/**
 * Bodies are built as `unknown` and cast at the call. That cast is the point:
 * these are the shapes a real HTTP client can send and the type system cannot
 * stop, so a test that could not express them would not be testing anything.
 */
function body(overrides: Record<string, unknown>): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE_V02,
    source: { id: snapshot.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    streams: [{ name: "transactions" }],
    ...overrides,
  } as SelectionRequest;
}

function stream(overrides: Record<string, unknown>): SelectionRequest {
  return body({ streams: [{ name: "transactions", ...overrides }] });
}

const malformed: [string, SelectionRequest][] = [
  // The three the review reproduced.
  [
    "minimum.time_range: null (reviewed)",
    stream({ minimum: { time_range: null } }),
  ],
  ["streams[].fields: null (reviewed)", stream({ fields: null })],
  ["streams[].resources: null (reviewed)", stream({ resources: null })],

  // The same substitution applied to every other member validation reads.
  ["streams: an object", body({ streams: {} })],
  ["streams: a string", body({ streams: "transactions" })],
  ["streams: a number", body({ streams: 1 })],
  ["streams[0]: null", body({ streams: [null] })],
  ["streams[0]: a number", body({ streams: [7] })],
  ["streams[].fields: a string", stream({ fields: "date" })],
  ["streams[].fields: an object", stream({ fields: {} })],
  ["streams[].resources: an object", stream({ resources: {} })],
  ["streams[].resources: a string", stream({ resources: "date" })],
  ["streams[].resources[0]: null", stream({ resources: [null] })],
  ["streams[].time_range: null", stream({ time_range: null })],
  ["streams[].time_range: an array", stream({ time_range: [] })],
  ["streams[].time_range: a string", stream({ time_range: "2025" })],
  ["streams[].minimum: null", stream({ minimum: null })],
  ["streams[].minimum: an array", stream({ minimum: [] })],
  ["streams[].minimum: a string", stream({ minimum: "date" })],
  ["minimum.fields: null", stream({ minimum: { fields: null } })],
  ["minimum.fields: a string", stream({ minimum: { fields: "date" } })],
  ["minimum.time_range: an array", stream({ minimum: { time_range: [] } })],
  [
    "minimum.time_range bounds: numbers",
    stream({ minimum: { time_range: { since: 1, until: 2 } } }),
  ],
  ["retention: null", body({ retention: null })],
  ["retention: a string", body({ retention: "delete" })],
  ["source: null", body({ source: null })],
  [
    "selection_preset: null with no streams",
    body({ streams: undefined, selection_preset: null }),
  ],
  ["purpose_code: null", body({ purpose_code: null })],
  ["purpose_code: a number", body({ purpose_code: 42 })],
  ["type: null", body({ type: null })],
];

describe("review finding 4 — malformed JSON is a validation failure, never a throw", () => {
  it.each(malformed)("rejects %s without throwing", (_label, request) => {
    // The whole contract in two assertions: it returns, and it returns a
    // typed failure. A TypeError escaping here is the 500 this file exists
    // to prevent.
    const result = validateSelectionRequest(request, snapshot);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(typeof result.failure.code).toBe("string");
    expect(result.failure.message.length).toBeGreaterThan(0);
  });

  it("still accepts the well-formed body the table is built from", () => {
    // The guards must reject malformed input, not all input. Without this the
    // table above passes against a validator that rejects everything.
    expect(validateSelectionRequest(body({}), snapshot).ok).toBe(true);
  });

  it("still accepts a well-formed minimum, fields, resources and time_range", () => {
    const result = validateSelectionRequest(
      stream({
        fields: ["date", "amount"],
        resources: ["2025-01-01"],
        time_range: { since: "2025-01-01T00:00:00Z" },
        minimum: {
          fields: ["date"],
          time_range: {
            since: "2025-06-01T00:00:00Z",
            until: "2025-07-01T00:00:00Z",
          },
        },
      }),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });
});
