/**
 * v0.2 disclosed projection on the read path (PR #1 §"Full records and
 * disclosed projections").
 *
 * Inventory rows `v0.2-4-1`, `v0.2-4-2`, `v0.2-4-3`, `v0.2-6.1-2`.
 *
 * ## What changed, and why the v0.1 behaviour is now a disclosure bug
 *
 * v0.1 had a per-stream "consent floor": a declaration's `required_fields`
 * were added to every projection regardless of the request, so a record could
 * never be returned in a shape its own schema would reject. v0.2 reverses
 * that: "The RS MUST NOT add a field to a response merely because the schema
 * requires it", and the disclosed `data` is built "from only the top-level
 * members permitted by the grant and the request-time field selection".
 *
 * The reversal is not cosmetic. The AS side of this already moved — a v0.2
 * grant's resolved `fields` deliberately exclude a schema-required field the
 * owner never approved (`pdpp-auth-v02.test.ts`, "does not add a
 * schema-required field to the reviewed projection"). But the RS re-added the
 * declaration's required fields at read time, from the *declaration*, not the
 * grant. So a field the owner was never shown and never approved was disclosed
 * on every read — the AS's narrowing was silently undone one layer down, and
 * the grant the owner consented to was not the grant that was enforced.
 *
 * v0.1 grants keep the floor exactly as it was: a v0.1 grant has no approved
 * projection beyond its streams/fields, and changing what it discloses would
 * be a breaking change to grants already issued and already consented to.
 */

import { describe, it, expect } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const AUTH = { Authorization: "Bearer client-tok" };

const declarations = createStreamDeclarationRegistry([
  {
    name: "transactions",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    // `id` and `private_note` are schema-required. Neither is in the v0.2
    // grant below: the owner did not approve them.
    requiredFields: ["id", "private_note"],
    schema: {
      type: "object",
      required: ["id", "private_note"],
      properties: {
        id: { type: "string" },
        date: { type: "string" },
        amount: { type: "number" },
        private_note: { type: "string" },
      },
    },
  },
]);

/** A v0.2 grant approving exactly `date` and `amount`. */
function grantV02(fields = ["date", "amount"]): Grant {
  return {
    version: "0.2.0",
    grant_id: "grant_v02",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: "client_1" },
    source: { kind: "provider_native", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [{ name: "transactions", instance_ids: ["inst_1"], fields }],
  };
}

/** The same approval expressed as a v0.1 grant. */
function grantV01(fields = ["date", "amount"]): Grant {
  return { ...grantV02(fields), version: "0.1.0", grant_id: "grant_v01" };
}

function buildApp(grant: Grant) {
  const store = createMemoryRecordStore();
  const tokens: Record<string, PdppTokenContext> = {
    "client-tok": {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      clientId: "client_1",
      grant,
    },
  };
  store.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "transactions",
        key: "t1",
        data: {
          id: "t1",
          date: "2026-01-02",
          amount: 12,
          private_note: "the owner never approved this",
        },
        emitted_at: "2026-01-02T00:00:00Z",
        op: "upsert",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
  return {
    store,
    app: pdppRecordsRoutes({
      store,
      auth: createFixtureAuthorizationService(tokens),
      declarations,
      instancesForSubject: () => ["inst_1"],
    }),
  };
}

async function listData(app: ReturnType<typeof buildApp>["app"], qs = "") {
  const res = await app.request(`/streams/transactions/records${qs}`, {
    headers: AUTH,
  });
  expect(res.status).toBe(200);
  const body = (await res.json()) as {
    data: Array<{ data: Record<string, unknown> }>;
  };
  return body.data[0].data;
}

describe("v0.2: disclosed data is built from the approved projection only", () => {
  it("does not add a schema-required field the grant did not approve", async () => {
    // `v0.2-4-1`. `private_note` is schema-required and NOT in the grant.
    const { app } = buildApp(grantV02());
    const data = await listData(app);
    expect(Object.keys(data).sort()).toEqual(["amount", "date"]);
    expect(data).not.toHaveProperty("private_note");
    expect(data).not.toHaveProperty("id");
  });

  it("does not add a schema-required field on a single-record read", async () => {
    const { app } = buildApp(grantV02());
    const res = await app.request("/streams/transactions/records/t1", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: Record<string, unknown> };
    expect(Object.keys(body.data).sort()).toEqual(["amount", "date"]);
  });

  it("intersects the request-time `fields` with the grant, adding nothing back", async () => {
    // `v0.2-4-2`: only members permitted by the grant AND the request-time
    // selection. A sparse request must not be re-widened by the schema floor.
    const { app } = buildApp(grantV02());
    const data = await listData(app, "?fields=date");
    expect(Object.keys(data)).toEqual(["date"]);
  });

  it("does not insert a null or placeholder for a withheld member", async () => {
    // `v0.2-4-3`. Absence, not `null`: a null is a disclosure that the member
    // exists and is empty, which is a different (and false) statement.
    const { app } = buildApp(grantV02());
    const data = await listData(app);
    expect("private_note" in data).toBe(false);
    expect("id" in data).toBe(false);
  });

  it("keeps a v0.1 grant's schema-required floor unchanged", async () => {
    // A v0.1 grant has no approved projection beyond its streams/fields, and
    // its consent was given under the floor. Removing it here would change
    // what an already-issued grant discloses.
    const { app } = buildApp(grantV01());
    const data = await listData(app);
    expect(Object.keys(data).sort()).toEqual([
      "amount",
      "date",
      "id",
      "private_note",
    ]);
  });

  it("keeps the v0.1 floor under a sparse v0.1 request", async () => {
    const { app } = buildApp(grantV01());
    const data = await listData(app, "?fields=date");
    expect(Object.keys(data).sort()).toEqual(["date", "id", "private_note"]);
  });
});

describe("v0.2: stream metadata reflects the approved projection", () => {
  it("omits a schema-required field the grant did not approve", async () => {
    // `v0.2-struct-11` / `v0.2-8.7-2`: the client-token metadata projection is
    // derived from the resolved authorization context, so a field outside the
    // grant must not become visible here either — otherwise the client learns
    // the member exists even though no read will ever disclose it.
    const { app } = buildApp(grantV02());
    const res = await app.request("/streams/transactions", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      schema: { properties: Record<string, unknown>; required: string[] };
    };
    expect(Object.keys(body.schema.properties).sort()).toEqual([
      "amount",
      "date",
    ]);
    expect(body.schema.required).toEqual([]);
  });
});
