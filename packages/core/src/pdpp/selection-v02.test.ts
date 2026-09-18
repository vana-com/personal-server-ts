/**
 * Oracles for the v0.2 selection-request shape: `necessity` per stream and
 * explicit authorization minima.
 *
 * The anchors are PR #1 spec-core.md "Explicit authorization minima" and the
 * `authorization-disclosure-contract` requirement "Grant lifecycle and
 * disclosure errors SHALL remain ordered" (scenario "Minimum window exceeds
 * request limit"). Each test asserts what the spec says must happen.
 *
 * Two properties are load-bearing across the whole file:
 *
 *   1. A v0.1 request is untouched by any of this. `minimum` is a v0.2 member,
 *      so the same body must keep resolving under v0.1 rules when it carries
 *      the v0.1 type — that is what "an AS implementing both types MUST
 *      resolve each under its own revision" means in practice.
 *   2. A malformed minimum is a *shape* failure, so it lands on
 *      `invalid_authorization_details`, not on the `access_denied` that an
 *      unsatisfiable-but-well-formed minimum produces at issuance. A client
 *      cannot fix the second by retrying; it can fix the first.
 */

import { describe, expect, it } from "vitest";
import { validateSelectionRequest } from "./selection.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  PDPP_DATA_ACCESS_TYPE_V02,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamRequest,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://data.example.com/finance",
  source_kind: "provider_native",
  version: "2026-09-01",
  digest: "e".repeat(64),
  streams: [
    {
      name: "transactions",
      fields: ["date", "amount", "merchant", "private_note"],
      required_fields: ["date"],
      consent_time_field: "date",
      primary_key: ["date"],
    },
    {
      // No consent_time_field: not time-range-capable, so not minimum-window
      // capable either.
      name: "profile",
      fields: ["id", "display_name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};

function v02(streams: StreamRequest[]): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE_V02,
    source: { id: snapshot.source_id },
    purpose_code: "https://apps.example.com/purposes/budget",
    access_mode: "single_use",
    streams,
  };
}

/** The wire example from PR #1's examples.md, as a reusable baseline. */
function transactionsStream(
  overrides: Partial<StreamRequest> = {},
): StreamRequest {
  return {
    name: "transactions",
    necessity: "required",
    fields: ["date", "amount", "merchant"],
    time_range: {
      since: "2025-01-01T00:00:00Z",
      until: "2026-01-01T00:00:00Z",
    },
    minimum: {
      fields: ["date", "amount"],
      time_range: {
        since: "2025-10-01T00:00:00Z",
        until: "2026-01-01T00:00:00Z",
      },
    },
    ...overrides,
  };
}

describe("v0.2 selection request shape", () => {
  it("accepts PR #1's twelve-month-limit, three-month-minimum example", () => {
    const result = validateSelectionRequest(v02([transactionsStream()]), snapshot);
    expect(result.ok).toBe(true);
  });

  it("accepts an optional stream alongside a required one", () => {
    const result = validateSelectionRequest(
      v02([
        transactionsStream(),
        { name: "profile", necessity: "optional", fields: ["display_name"] },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("rejects an unrecognized necessity value", () => {
    const result = validateSelectionRequest(
      v02([{ name: "profile", necessity: "nice_to_have" as never }]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_request");
  });

  // ------------------------------------------------------------------
  // Minima: recognized members only
  // ------------------------------------------------------------------

  it("rejects an empty minimum object", () => {
    const result = validateSelectionRequest(
      v02([{ name: "profile", minimum: {} }]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects an unknown minimum member", () => {
    const result = validateSelectionRequest(
      v02([
        {
          name: "profile",
          fields: ["display_name"],
          minimum: { records: 10 } as never,
        },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects an empty minimum.fields array", () => {
    const result = validateSelectionRequest(
      v02([{ name: "profile", fields: ["display_name"], minimum: { fields: [] } }]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects duplicate minimum field names", () => {
    const result = validateSelectionRequest(
      v02([
        {
          name: "transactions",
          fields: ["date", "amount"],
          minimum: { fields: ["date", "date"] },
        },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum field outside the expanded request", () => {
    // `merchant` is declared by the stream but not requested, so it is not in
    // the expanded request and cannot be a floor under it.
    const result = validateSelectionRequest(
      v02([
        {
          name: "transactions",
          fields: ["date", "amount"],
          minimum: { fields: ["merchant"] },
        },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum field absent from the retained schema", () => {
    const result = validateSelectionRequest(
      v02([{ name: "transactions", minimum: { fields: ["phantom"] } }]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("accepts a minimum field against an omitted field selector", () => {
    // Omitting `fields` asks for all permitted fields, so the expanded request
    // is the declared field set and any declared field is a valid floor.
    const result = validateSelectionRequest(
      v02([{ name: "transactions", minimum: { fields: ["merchant"] } }]),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("accepts a minimum field drawn from a named view", () => {
    const withView: DeclarationSnapshot = {
      ...snapshot,
      views: [{ name: "ledger", fields: ["date", "amount"] }],
    };
    const result = validateSelectionRequest(
      v02([{ name: "transactions", view: "ledger", minimum: { fields: ["amount"] } }]),
      withView,
    );
    expect(result.ok).toBe(true);
  });

  // ------------------------------------------------------------------
  // Minima: time windows
  // ------------------------------------------------------------------

  it("rejects a minimum window with an open bound", () => {
    const result = validateSelectionRequest(
      v02([
        transactionsStream({
          minimum: { time_range: { since: "2025-10-01T00:00:00Z" } as never },
        }),
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum window whose since does not precede its until", () => {
    const result = validateSelectionRequest(
      v02([
        transactionsStream({
          minimum: {
            time_range: {
              since: "2026-01-01T00:00:00Z",
              until: "2026-01-01T00:00:00Z",
            },
          },
        }),
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum window that starts before the requested window", () => {
    // PR #1 scenario "Minimum window exceeds request limit": a request that
    // authorizes only December cannot declare October as its floor.
    const result = validateSelectionRequest(
      v02([
        transactionsStream({
          time_range: {
            since: "2025-12-01T00:00:00Z",
            until: "2026-01-01T00:00:00Z",
          },
          minimum: {
            time_range: {
              since: "2025-10-01T00:00:00Z",
              until: "2026-01-01T00:00:00Z",
            },
          },
        }),
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum window that ends after the requested window", () => {
    const result = validateSelectionRequest(
      v02([
        transactionsStream({
          minimum: {
            time_range: {
              since: "2025-10-01T00:00:00Z",
              until: "2027-01-01T00:00:00Z",
            },
          },
        }),
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("accepts a minimum window inside an unbounded requested window", () => {
    // An omitted request `time_range` is unbounded, so nothing can exceed it.
    const result = validateSelectionRequest(
      v02([
        {
          name: "transactions",
          minimum: {
            time_range: {
              since: "2025-10-01T00:00:00Z",
              until: "2026-01-01T00:00:00Z",
            },
          },
        },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("compares minimum bounds as instants, not as strings", () => {
    // `2025-10-01T00:00:00+02:00` is *earlier* than `2025-10-01T00:00:00Z` as
    // an instant but *later* as a string. A string comparison would wrongly
    // accept this floor as inside the requested window.
    const result = validateSelectionRequest(
      v02([
        transactionsStream({
          time_range: {
            since: "2025-10-01T00:00:00Z",
            until: "2026-01-01T00:00:00Z",
          },
          minimum: {
            time_range: {
              since: "2025-10-01T00:00:00+02:00",
              until: "2026-01-01T00:00:00Z",
            },
          },
        }),
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });

  it("rejects a minimum window on a stream with no consent_time_field", () => {
    const result = validateSelectionRequest(
      v02([
        {
          name: "profile",
          fields: ["display_name"],
          minimum: {
            time_range: {
              since: "2025-10-01T00:00:00Z",
              until: "2026-01-01T00:00:00Z",
            },
          },
        },
      ]),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_minimum");
  });
});

describe("revision isolation", () => {
  it("rejects a minimum carried on a v0.1 request", () => {
    // v0.1 has no `minimum`. Silently ignoring it would be the worst outcome:
    // the client believes it imposed a floor the AS never enforces.
    const result = validateSelectionRequest(
      { ...v02([transactionsStream()]), type: PDPP_DATA_ACCESS_TYPE },
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unsupported_selection_parameter");
  });

  it("still accepts an unchanged v0.1 request", () => {
    const result = validateSelectionRequest(
      {
        type: PDPP_DATA_ACCESS_TYPE,
        source: { id: snapshot.source_id },
        purpose_code: "https://pdpp.dev/purpose/portability",
        access_mode: "single_use",
        streams: [{ name: "transactions", fields: ["date", "amount"] }],
      },
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("rejects an unknown detail type rather than treating it as PDPP", () => {
    const result = validateSelectionRequest(
      { ...v02([transactionsStream()]), type: "https://pdpp.dev/data-access/9.9" as never },
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_request");
  });
});
