import { describe, it, expect } from "vitest";
import {
  findStreamGrant,
  withinTimeConstraint,
  type Grant,
} from "./pdpp-auth.js";

describe("findStreamGrant", () => {
  it("finds the StreamGrant entry matching a stream name", () => {
    const grant = {
      streams: [
        { name: "messages", instance_ids: ["i1"], fields: ["id"] },
        { name: "playlists", instance_ids: ["i1"], fields: ["id", "name"] },
      ],
    } as unknown as Grant;
    expect(findStreamGrant(grant, "playlists")?.fields).toEqual(["id", "name"]);
  });

  it("returns undefined for a stream not in the grant", () => {
    const grant = {
      streams: [{ name: "messages", instance_ids: [], fields: [] }],
    } as unknown as Grant;
    expect(findStreamGrant(grant, "playlists")).toBeUndefined();
  });
});

describe("withinTimeConstraint", () => {
  it("returns true when there is no constraint", () => {
    expect(withinTimeConstraint("2026-01-01", undefined)).toBe(true);
  });

  it("includes a value exactly at `since` (inclusive lower bound)", () => {
    expect(
      withinTimeConstraint("2026-01-01T00:00:00Z", {
        field: "source_created_at",
        since: "2026-01-01T00:00:00Z",
      }),
    ).toBe(true);
  });

  it("excludes a value exactly at `until` (exclusive upper bound)", () => {
    expect(
      withinTimeConstraint("2026-01-01T00:00:00Z", {
        field: "source_created_at",
        until: "2026-01-01T00:00:00Z",
      }),
    ).toBe(false);
  });

  it("includes a value strictly before `until`", () => {
    expect(
      withinTimeConstraint("2025-12-31T23:59:59Z", {
        field: "source_created_at",
        until: "2026-01-01T00:00:00Z",
      }),
    ).toBe(true);
  });

  it("excludes a value missing when a constraint is present", () => {
    expect(
      withinTimeConstraint(undefined, {
        field: "source_created_at",
        since: "2026-01-01",
      }),
    ).toBe(false);
  });
});
