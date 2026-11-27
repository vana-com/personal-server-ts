import { describe, it, expect } from "vitest";
import {
  GRANT_VERSION_V02,
  PdppAuthorizationUnavailableError,
  findStreamGrant,
  grantIsV02,
  withinTimeConstraint,
  type Grant,
} from "./pdpp-auth.js";

describe("grantIsV02", () => {
  it("distinguishes the two published grant versions", () => {
    expect(grantIsV02({ version: "0.2.0" } as Grant)).toBe(true);
    expect(grantIsV02({ version: "0.1.0" } as Grant)).toBe(false);
  });

  it("does not describe a missing grant as version 0.2", () => {
    expect(grantIsV02(undefined)).toBe(false);
  });
});

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

  const catalogueGrant: Grant = {
    version: "0.2.0",
    grant_id: "sample-grant",
    issued_at: "2026-06-01T00:00:00Z",
    subject: { id: "sample-subject" },
    client: { client_id: "sample-client" },
    source: { kind: "connector", id: "sample-source" },
    source_declaration: { version: "0.1.0" },
    purpose_code: "sample-purpose",
    access_mode: "continuous",
    streams: [
      { name: "playlist", instance_ids: ["sample-connection"], fields: ["id"] },
      {
        name: "playlists",
        instance_ids: ["sample-connection"],
        fields: ["id", "label"],
      },
    ],
  };

  it("returns the original typed entry for the exact name, even with a similar earlier name", () => {
    expect(findStreamGrant(catalogueGrant, "playlists")).toBe(
      catalogueGrant.streams[1],
    );
  });

  it("returns no entry for an empty stream list", () => {
    expect(
      findStreamGrant({ ...catalogueGrant, streams: [] }, "playlists"),
    ).toBeUndefined();
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

describe("GRANT_VERSION_V02", () => {
  it("is the published v0.2 grant version string", () => {
    expect(GRANT_VERSION_V02).toBe("0.2.0");
  });

  it("is the version grantIsV02 recognises", () => {
    expect(grantIsV02({ version: GRANT_VERSION_V02 } as Grant)).toBe(true);
  });

  it("does not recognise an unknown future version as v0.2", () => {
    expect(grantIsV02({ version: "0.3.0" } as Grant)).toBe(false);
  });
});

describe("PdppAuthorizationUnavailableError", () => {
  it("carries the authorization-server-unreachable message and a 5s retry hint", () => {
    const error = new PdppAuthorizationUnavailableError();
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("PdppAuthorizationUnavailableError");
    expect(error.message).toBe(
      "Authorization server could not be reached or validated",
    );
    expect(error.retryAfterSeconds).toBe(5);
  });
});

describe("withinTimeConstraint range edges", () => {
  it("excludes a value before `since`", () => {
    expect(
      withinTimeConstraint("2025-12-31T23:59:59Z", {
        field: "source_created_at",
        since: "2026-01-01T00:00:00Z",
      }),
    ).toBe(false);
  });

  it("excludes a value after `until`", () => {
    expect(
      withinTimeConstraint("2026-01-02T00:00:00Z", {
        field: "source_created_at",
        until: "2026-01-01T00:00:00Z",
      }),
    ).toBe(false);
  });

  it("includes a value inside a bounded [since, until) window", () => {
    expect(
      withinTimeConstraint("2026-06-15T12:00:00Z", {
        field: "source_created_at",
        since: "2026-01-01T00:00:00Z",
        until: "2027-01-01T00:00:00Z",
      }),
    ).toBe(true);
  });

  it("returns true for a missing value when there is no constraint", () => {
    expect(withinTimeConstraint(undefined, undefined)).toBe(true);
  });
});
