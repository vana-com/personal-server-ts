/**
 * Oracles for PDPP Core §6 selection validation and §9 AS conformance items
 * 1, 2, 5, 6, 11, 12. Each test names the requirement it enforces; the
 * assertion is what the spec says must happen, not what the code happens to do.
 */

import { describe, expect, it } from "vitest";
import { validateSelectionRequest } from "./selection.js";
import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";

const snapshot: DeclarationSnapshot = {
  source_id: "https://registry.pdpp.dev/connectors/spotify",
  source_kind: "connector",
  version: "2026-08-11",
  digest: "d".repeat(64),
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres", "popularity", "source_updated_at"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
    {
      // No consent_time_field: deliberately not time-range-capable.
      name: "profile",
      fields: ["id", "display_name", "country"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "play_events",
      fields: ["user_id", "track_id", "played_at"],
      required_fields: ["user_id", "track_id"],
      consent_time_field: "played_at",
      primary_key: ["user_id", "track_id"],
    },
  ],
  views: [
    { name: "public_artist", fields: ["id", "name"] },
    // Names a field no stream declares — §9 AS item 12 material.
    { name: "broken_view", fields: ["id", "not_in_schema"] },
  ],
  selection_presets: [
    {
      name: "social_summary",
      streams: [{ name: "top_artists" }, { name: "profile" }],
    },
  ],
};

function request(overrides: Partial<SelectionRequest> = {}): SelectionRequest {
  return {
    type: PDPP_DATA_ACCESS_TYPE,
    source: { id: snapshot.source_id },
    purpose_code: "https://pdpp.dev/purpose/personalization",
    access_mode: "single_use",
    streams: [{ name: "top_artists" }],
    ...overrides,
  };
}

describe("§9 AS item 1 — RFC 9396 envelope", () => {
  it("accepts the PDPP data-access type", () => {
    expect(validateSelectionRequest(request(), snapshot).ok).toBe(true);
  });

  it("rejects a non-PDPP authorization detail type", () => {
    const result = validateSelectionRequest(
      { ...request(), type: "https://example.com/other" as never },
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});

describe("§9 AS item 5 — streams/selection_preset is exactly-one", () => {
  // The spec calls this a Source validation failure and requires it to fail
  // neutrally: both and neither must produce the same code, so a probing
  // client cannot learn which half the server accepted.
  it("fails when both are present", () => {
    const result = validateSelectionRequest(
      request({
        streams: [{ name: "top_artists" }],
        selection_preset: "social_summary",
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("source_validation_failed");
  });

  it("fails when neither is present", () => {
    const result = validateSelectionRequest(
      request({ streams: undefined, selection_preset: undefined }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("source_validation_failed");
  });

  it("produces an identical failure for both and neither", () => {
    const both = validateSelectionRequest(
      request({
        streams: [{ name: "top_artists" }],
        selection_preset: "social_summary",
      }),
      snapshot,
    );
    const neither = validateSelectionRequest(
      request({ streams: undefined, selection_preset: undefined }),
      snapshot,
    );
    expect(both.ok).toBe(false);
    expect(neither.ok).toBe(false);
    if (both.ok || neither.ok) return;
    // Neutrality: same code AND same message, no distinguishing detail.
    expect(both.failure).toEqual(neither.failure);
  });
});

describe("§9 AS item 2 — validate against the retained snapshot", () => {
  it("rejects a stream the snapshot does not declare", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "not_a_stream" }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_stream");
  });

  it("rejects an unrecognized selection preset", () => {
    const result = validateSelectionRequest(
      request({ streams: undefined, selection_preset: "no_such_preset" }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_preset");
  });

  it("rejects time_range on a stream with no consent_time_field", () => {
    // §6: the declaration's consent_time_field is the authoritative signal
    // that a stream is time-range-capable.
    const result = validateSelectionRequest(
      request({
        streams: [
          { name: "profile", time_range: { since: "2026-01-01T00:00:00Z" } },
        ],
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unsupported_selection_parameter");
  });

  it("accepts time_range on a stream that declares consent_time_field", () => {
    const result = validateSelectionRequest(
      request({
        streams: [
          {
            name: "top_artists",
            time_range: { since: "2026-01-01T00:00:00Z" },
          },
        ],
      }),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a request whose source.id does not match the snapshot", () => {
    const result = validateSelectionRequest(
      request({ source: { id: "https://registry.pdpp.dev/connectors/other" } }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});

describe("§9 AS item 6 — purpose codes", () => {
  it("accepts an unregistered but syntactically valid absolute URI", () => {
    // The spec forbids rejecting a purpose code solely for being unregistered.
    const result = validateSelectionRequest(
      request({ purpose_code: "https://vendor.example/purpose/custom-thing" }),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a relative purpose code", () => {
    const result = validateSelectionRequest(
      request({ purpose_code: "personalization" }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});

describe("§6 / §9 AS item 12 — views and fields", () => {
  it("rejects a view naming fields absent from the retained schema", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "top_artists", view: "broken_view" }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_field");
  });

  it("rejects an unknown view name", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "top_artists", view: "ghost" }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_view");
  });

  it("rejects view and fields together (§6: mutually exclusive)", () => {
    const result = validateSelectionRequest(
      request({
        streams: [
          { name: "top_artists", view: "public_artist", fields: ["id"] },
        ],
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_request");
  });

  it("rejects requested fields absent from the retained schema", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "top_artists", fields: ["id", "ghost"] }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_field");
  });
});

describe("§6 — wildcard rules", () => {
  it("accepts a lone wildcard entry", () => {
    expect(
      validateSelectionRequest(request({ streams: [{ name: "*" }] }), snapshot)
        .ok,
    ).toBe(true);
  });

  it("rejects a wildcard combined with another entry", () => {
    // §6: "A wildcard entry MUST be the only entry in streams."
    const result = validateSelectionRequest(
      request({ streams: [{ name: "*" }, { name: "profile" }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects duplicate stream names", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "profile" }, { name: "profile" }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});

describe("§9 AS item 11 — resource key shape", () => {
  it("accepts a simple key string for a single-column primary key", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "top_artists", resources: ["artist-1"] }] }),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("accepts a minified JSON array for a compound primary key", () => {
    const result = validateSelectionRequest(
      request({
        streams: [{ name: "play_events", resources: ['["u1","t1"]'] }],
      }),
      snapshot,
    );
    expect(result.ok).toBe(true);
  });

  it("rejects a compound key with the wrong arity", () => {
    // play_events has a 2-part primary key; a 3-part key can never match.
    const result = validateSelectionRequest(
      request({
        streams: [{ name: "play_events", resources: ['["u1","t1","x"]'] }],
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_resource_key");
  });

  it("rejects a simple string where a compound key is declared", () => {
    const result = validateSelectionRequest(
      request({ streams: [{ name: "play_events", resources: ["u1"] }] }),
      snapshot,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_resource_key");
  });
});

describe("§6 — time_range bounds", () => {
  it("rejects since >= until", () => {
    const result = validateSelectionRequest(
      request({
        streams: [
          {
            name: "top_artists",
            time_range: {
              since: "2026-06-01T00:00:00Z",
              until: "2026-01-01T00:00:00Z",
            },
          },
        ],
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a non-ISO instant", () => {
    const result = validateSelectionRequest(
      request({
        streams: [
          { name: "top_artists", time_range: { since: "last tuesday" } },
        ],
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});

describe("§7 — retention", () => {
  it("rejects on_expiry: archive (dropped in v0.1)", () => {
    const result = validateSelectionRequest(
      request({
        retention: { max_duration: "P6M", on_expiry: "archive" as never },
      }),
      snapshot,
    );
    expect(result.ok).toBe(false);
  });
});
