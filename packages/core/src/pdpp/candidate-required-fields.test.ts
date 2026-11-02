/**
 * The candidate freezes each stream's schema-required fields in the grant
 * (`StreamGrant.required_fields`), and the RS takes the sparse-read floor from
 * that frozen set, never from a later declaration (request-resolution audit F3).
 */
import { expect, it } from "vitest";
import { resolveSelection } from "./resolve.js";
import {
  PDPP_DATA_ACCESS_TYPE_CANDIDATE,
  PDPP_DATA_ACCESS_TYPE_V02,
  PDPP_GRANT_VERSION_CANDIDATE,
  type DeclarationSnapshot,
  type SelectionRequest,
} from "./types.js";
import { resolveReadScope } from "../storage/pdpp-records/enforcement.js";
import type { StreamDeclaration } from "../storage/pdpp-records/stream-declaration.js";
import type { Grant } from "../ports/pdpp-auth.js";

const snapshot: DeclarationSnapshot = {
  source_id: "s",
  source_kind: "connector",
  version: "D1",
  digest: "d",
  streams: [
    {
      name: "contacts",
      fields: ["id", "name", "secret"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
};
const request = (type: string): SelectionRequest =>
  ({
    type,
    source: { id: "s" },
    purpose_code: "https://pdpp.dev/purpose/analytics",
    access_mode: "continuous",
    streams: [
      { name: "contacts", necessity: "required", fields: ["name", "secret"] },
    ],
  }) as SelectionRequest;

it("issues the candidate grant with its frozen required-field floor", () => {
  const resolved = resolveSelection(
    request(PDPP_DATA_ACCESS_TYPE_CANDIDATE),
    snapshot,
    { eligibleFor: () => ["i"] },
  );
  expect(resolved.ok).toBe(true);
  if (!resolved.ok) return;
  expect(resolved.streams[0]).toMatchObject({
    fields: ["name", "secret", "id"],
    required_fields: ["id"],
  });
});

it("leaves current and private-v0.2 grants without the candidate member", () => {
  const resolved = resolveSelection(
    request(PDPP_DATA_ACCESS_TYPE_V02),
    snapshot,
    { eligibleFor: () => ["i"] },
  );
  expect(resolved.ok && resolved.streams[0]).not.toHaveProperty(
    "required_fields",
  );
});

// D2: the current declaration now also requires `secret`.
const d2: StreamDeclaration = {
  name: "contacts",
  semantics: "mutable_state",
  primaryKey: ["id"],
  requiredFields: ["id", "secret"],
  declaredFields: ["id", "name", "secret"],
};
const candidateGrant = (stream: Record<string, unknown>): Grant => ({
  version: PDPP_GRANT_VERSION_CANDIDATE,
  grant_id: "g",
  issued_at: "2026-01-01T00:00:00Z",
  subject: { id: "sub" },
  client: { client_id: "c" },
  source: { kind: "connector", id: "s" },
  source_declaration: { version: "D1" },
  purpose_code: "https://pdpp.dev/purpose/test",
  access_mode: "continuous",
  streams: [
    {
      name: "contacts",
      instance_ids: ["i"],
      fields: ["id", "name", "secret"],
      ...stream,
    } as Grant["streams"][number],
  ],
});
const read = (grant: Grant, fields?: string[]) =>
  resolveReadScope(
    { active: true, tokenKind: "client", subjectId: "sub", grant },
    "contacts",
    d2,
    fields,
  );

it("takes a candidate sparse-read floor from the grant, not a newer declaration", () => {
  expect(
    read(candidateGrant({ required_fields: ["id"] }), ["name"]).fields,
  ).toEqual(["name", "id"]);
});

it("refuses a candidate grant that froze no required-field floor", () => {
  expect(() => read(candidateGrant({}), ["name"])).toThrow(
    expect.objectContaining({ code: "grant_invalid" }),
  );
});
