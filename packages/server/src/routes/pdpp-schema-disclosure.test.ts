import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";

// GET /streams/:stream for a client token must describe only granted fields.
// Every schema keyword outside the granted properties can name or constrain an
// ungranted field, so none of them may pass through.
const SECRET = "private_note";

const schema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  title: `Rows with ${SECRET}`,
  type: "object",
  required: ["id", SECRET],
  properties: {
    id: { type: "string", examples: ["t1"] },
    amount: { $ref: "#/$defs/money" },
    [SECRET]: { type: "string" },
  },
  $defs: { money: { type: "number" }, hidden: { const: SECRET } },
  allOf: [{ properties: { [SECRET]: { minLength: 3 } } }],
  dependentSchemas: { id: { required: [SECRET] } },
  dependentRequired: { id: [SECRET] },
  examples: [{ id: "t1", [SECRET]: "the owner's diary" }],
  if: { properties: { id: { const: "t1" } } },
  then: { required: [SECRET] },
};

describe("F3 grant-closed stream metadata", () => {
  it("returns a schema built from granted properties only", async () => {
    const grant: Grant = {
      version: "0.1.0",
      grant_id: "g",
      issued_at: "2026-01-01T00:00:00Z",
      subject: { id: "s" },
      client: { client_id: "c" },
      source: { kind: "connector", id: "src" },
      source_declaration: { version: "1" },
      purpose_code: "test",
      access_mode: "continuous",
      streams: [
        { name: "transactions", instance_ids: ["i"], fields: ["id", "amount"] },
      ],
    };
    const app = pdppRecordsRoutes({
      store: createMemoryRecordStore(),
      auth: createFixtureAuthorizationService({
        t: { active: true, tokenKind: "client", subjectId: "s", grant },
      }),
      declarations: createStreamDeclarationRegistry([
        {
          name: "transactions",
          semantics: "mutable_state",
          primaryKey: ["id"],
          requiredFields: ["id"],
          cursorField: "emitted_at",
          schema,
        },
      ]),
    });
    const response = await app.request("/streams/transactions", {
      headers: { Authorization: "Bearer t" },
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(JSON.stringify(body)).not.toContain(SECRET);
    expect(JSON.stringify(body)).not.toContain("diary");
    expect(body.schema).toEqual({
      $schema: schema.$schema,
      type: "object",
      properties: {
        id: { type: "string", examples: ["t1"] },
        // A reference cannot be followed without the definitions it names.
        amount: {},
      },
      required: ["id"],
    });
  });
});
