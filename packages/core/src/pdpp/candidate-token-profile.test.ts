import { expect, it } from "vitest";
import { toAuthorizationEntry } from "./tokens.js";
import { PDPP_DATA_ACCESS_TYPE_CANDIDATE, type Grant } from "./types.js";

it("preserves the explicit candidate profile in token and introspection authorization details", () => {
  const grant: Grant = {
    version: "0.1.0-candidate",
    grant_id: "g",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "s" },
    client: { client_id: "c" },
    source: { kind: "connector", id: "src" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "events",
        instance_ids: ["i"],
        fields: ["id"],
        required_fields: ["id"],
        time_constraint: { field: "at", type: "date", since: "2026-01-01" },
      },
    ],
  };
  const entry = toAuthorizationEntry(grant);
  expect(entry.type).toBe(PDPP_DATA_ACCESS_TYPE_CANDIDATE);
  // AS item 32: the complete grant, never a projection (spec-core L1415).
  expect("grant" in entry && entry.grant).toEqual(grant);
});
