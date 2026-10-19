/**
 * Oracles for PDPP Core §6→§7 axis resolution (§9 AS items 3, 4, 13, 15).
 *
 * The property under test throughout: an issued grant contains no request-only
 * conveniences. No wildcards, no view names, no omitted field lists, no
 * omitted instance handles. §7 says these "are not continuing authority in the
 * grant", which means the RS must never face one.
 */

import { describe, expect, it } from "vitest";
import { resolveSelection, type InstanceInventory } from "./resolve.js";
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
      required_fields: ["id", "source_updated_at"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
    {
      name: "profile",
      fields: ["id", "display_name", "country"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
  views: [{ name: "public_artist", fields: ["id", "name"] }],
  selection_presets: [
    {
      name: "social_summary",
      streams: [{ name: "top_artists" }, { name: "profile" }],
    },
  ],
};

/** One eligible instance per stream — the auto-resolvable case. */
const singleInstance: InstanceInventory = {
  eligibleFor: () => ["spotify-account-a"],
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

describe("§9 AS item 4 — wildcards expand to explicit streams", () => {
  it("expands '*' into every declared stream", () => {
    const result = resolveSelection(
      request({ streams: [{ name: "*" }] }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name).sort()).toEqual([
      "profile",
      "top_artists",
    ]);
    // The grant must carry no wildcard.
    expect(result.streams.some((s) => s.name === "*")).toBe(false);
  });

  it("drops time_range for streams that cannot accept one when expanding '*'", () => {
    // profile has no consent_time_field; top_artists does. A wildcard carrying
    // a time_range must not invent a time constraint for profile.
    const result = resolveSelection(
      request({
        streams: [{ name: "*", time_range: { since: "2026-01-01T00:00:00Z" } }],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const profile = result.streams.find((s) => s.name === "profile");
    const artists = result.streams.find((s) => s.name === "top_artists");
    expect(profile?.time_constraint).toBeUndefined();
    expect(artists?.time_constraint).toEqual({
      field: "source_updated_at",
      since: "2026-01-01T00:00:00Z",
    });
  });

  it("expands a selection preset into explicit streams", () => {
    const result = resolveSelection(
      request({ streams: undefined, selection_preset: "social_summary" }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams.map((s) => s.name).sort()).toEqual([
      "profile",
      "top_artists",
    ]);
  });
});

describe("§9 AS item 13 / §6 — fields resolve to explicit lists", () => {
  it("resolves a view name to its field list", () => {
    const result = resolveSelection(
      request({ streams: [{ name: "top_artists", view: "public_artist" }] }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // public_artist is {id, name}; required_fields adds source_updated_at.
    expect(result.streams[0].fields.sort()).toEqual([
      "id",
      "name",
      "source_updated_at",
    ]);
  });

  it("always includes schema-required fields, even when not requested", () => {
    // §6: "schema-required fields are always included in the resolved field
    // set, regardless of the requested field list". The client asked for
    // `name` only; `id` and `source_updated_at` are the consent floor.
    const result = resolveSelection(
      request({ streams: [{ name: "top_artists", fields: ["name"] }] }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields).toContain("id");
    expect(result.streams[0].fields).toContain("source_updated_at");
    expect(result.streams[0].fields).toContain("name");
  });

  it("resolves omitted fields to the declaration's full field set", () => {
    const result = resolveSelection(request(), snapshot, singleInstance);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].fields.sort()).toEqual(
      [...snapshot.streams[0].fields].sort(),
    );
  });

  it("never emits an empty field list", () => {
    // The RS contract promises a non-empty `fields` on every stream.
    const result = resolveSelection(
      request({ streams: [{ name: "*" }] }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    for (const stream of result.streams) {
      expect(stream.fields.length).toBeGreaterThan(0);
    }
  });

  it("deduplicates fields", () => {
    const result = resolveSelection(
      request({
        streams: [{ name: "top_artists", fields: ["id", "id", "name"] }],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(new Set(result.streams[0].fields).size).toBe(
      result.streams[0].fields.length,
    );
  });
});

describe("§6 / §9 AS item 15 — instance handle resolution", () => {
  it("auto-resolves when exactly one instance is eligible", () => {
    const result = resolveSelection(request(), snapshot, singleInstance);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].instance_ids).toEqual(["spotify-account-a"]);
  });

  it("requires an owner choice when several are eligible and none was named", () => {
    // §6: "Omission never means fan-in." Two connected accounts and no named
    // handle is a decision the owner has to make, not one the AS may infer.
    const twoInstances: InstanceInventory = {
      eligibleFor: () => ["account-a", "account-b"],
    };
    const result = resolveSelection(request(), snapshot, twoInstances);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("instance_choice_required");
    expect(result.failure.candidates).toEqual(["account-a", "account-b"]);
  });

  it("allows explicit fan-in when several handles are named", () => {
    const twoInstances: InstanceInventory = {
      eligibleFor: () => ["account-a", "account-b"],
    };
    const result = resolveSelection(
      request({
        streams: [
          { name: "top_artists", instance_ids: ["account-a", "account-b"] },
        ],
      }),
      snapshot,
      twoInstances,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].instance_ids).toEqual(["account-a", "account-b"]);
  });

  it("rejects an instance handle that is not eligible", () => {
    const result = resolveSelection(
      request({
        streams: [
          { name: "top_artists", instance_ids: ["someone-elses-account"] },
        ],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_instance");
  });

  it("fails when no instance is connected", () => {
    const none: InstanceInventory = { eligibleFor: () => [] };
    const result = resolveSelection(request(), snapshot, none);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("no_eligible_instance");
  });

  it("verifies wildcard-carried handles against every expanded stream", () => {
    // §6: a wildcard's instance_ids apply to every expanded stream and each
    // handle must be eligible for that stream. Here the handle is eligible for
    // top_artists but not profile, so resolution must fail rather than
    // authorizing a handle the owner never connected for profile.
    const perStream: InstanceInventory = {
      eligibleFor: (stream) =>
        stream === "top_artists" ? ["account-a"] : ["account-b"],
    };
    const result = resolveSelection(
      request({ streams: [{ name: "*", instance_ids: ["account-a"] }] }),
      snapshot,
      perStream,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("unknown_instance");
  });
});

describe("§7 — time constraints freeze", () => {
  it("freezes the declaration's consent_time_field with the bounds", () => {
    const result = resolveSelection(
      request({
        streams: [
          {
            name: "top_artists",
            time_range: {
              since: "2025-09-28T00:00:00Z",
              until: "2026-09-28T00:00:00Z",
            },
          },
        ],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toEqual({
      field: "source_updated_at",
      since: "2025-09-28T00:00:00Z",
      until: "2026-09-28T00:00:00Z",
    });
  });

  it("omits time_constraint when no time_range was requested", () => {
    const result = resolveSelection(request(), snapshot, singleInstance);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint).toBeUndefined();
  });

  it("freezes against the snapshot's field name, not a later declaration's", () => {
    // The guarantee: a declaration that later renames its time field cannot
    // re-scope an issued grant, because the grant carries the frozen name.
    const result = resolveSelection(
      request({
        streams: [
          {
            name: "top_artists",
            time_range: { since: "2026-01-01T00:00:00Z" },
          },
        ],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].time_constraint?.field).toBe(
      snapshot.streams[0].consent_time_field,
    );
  });
});

describe("§7 — resources pass through as canonical keys", () => {
  it("carries requested resources onto the stream grant", () => {
    const result = resolveSelection(
      request({
        streams: [{ name: "top_artists", resources: ["artist-1", "artist-2"] }],
      }),
      snapshot,
      singleInstance,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].resources).toEqual(["artist-1", "artist-2"]);
  });

  it("omits resources when unconstrained (absent means all records)", () => {
    const result = resolveSelection(request(), snapshot, singleInstance);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.streams[0].resources).toBeUndefined();
  });
});
