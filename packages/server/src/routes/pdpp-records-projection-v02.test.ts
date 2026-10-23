/**
 * Frozen field disclosure on the current, candidate and private-v0.2 read paths.
 * Core resolves schema-required fields at issuance; a later declaration cannot
 * add authority. Sparse Core reads retain only required fields already in the
 * grant. The private-v0.2 proposal also permits withholding that sparse floor.
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

/** A candidate grant: `required` is the floor frozen at issuance. */
function grantCandidate(
  fields = ["date", "amount"],
  required: string[] = [],
): Grant {
  const grant = grantV02(fields);
  return {
    ...grant,
    version: "0.1.0-candidate",
    grant_id: "grant_candidate",
    streams: grant.streams.map((s) => ({ ...s, required_fields: required })),
  };
}

function buildApp(
  grant: Grant,
  data: Record<string, unknown> = {
    id: "t1",
    date: "2026-01-02",
    amount: 12,
    private_note: "the owner never approved this",
  },
) {
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
        data,
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

  it("keeps current reads inside grant fields when a declaration requires more", async () => {
    const { app } = buildApp(grantV01());
    expect(Object.keys(await listData(app)).sort()).toEqual(["amount", "date"]);
  });

  it("keeps a sparse current read inside the frozen grant", async () => {
    const { app } = buildApp(grantV01());
    expect(Object.keys(await listData(app, "?fields=date")).sort()).toEqual([
      "date",
    ]);
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

it("candidate grant closure survives new schema-required fields on list/detail/sync", async () => {
  const { app } = buildApp(grantCandidate());
  for (const path of [
    "/streams/transactions/records?fields=date",
    "/streams/transactions/records/t1?fields=date",
    "/streams/transactions/records?changes_since=&fields=date",
  ]) {
    const res = await app.request(path, { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();
    const rows = body.object === "list" ? body.data : [body];
    expect(rows).toHaveLength(1);
    expect(rows[0].data).toEqual({ date: "2026-01-02" });
  }
});

it("keeps candidate required fields only when frozen in the grant under sparse reads", async () => {
  const { app } = buildApp(grantCandidate(["id", "date", "amount"], ["id"]));
  const data = await listData(app, "?fields=date");
  expect(Object.keys(data).sort()).toEqual(["date", "id"]);
});

it("candidate sync eligibility uses grant fields even when the response is sparse", async () => {
  const { app, store } = buildApp(grantCandidate());
  const baseline = await app.request(
    "/streams/transactions/records?changes_since=beginning&fields=date",
    { headers: AUTH },
  );
  expect(baseline.status).toBe(200);
  const { next_changes_since: checkpoint } = await baseline.json();
  expect(checkpoint).toBeTruthy();
  store.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "transactions",
        key: "t1",
        data: { id: "t1", date: "2026-01-02", amount: 99 },
        emitted_at: "2026-01-03T00:00:00Z",
        op: "upsert",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
  const res = await app.request(
    `/streams/transactions/records?changes_since=${encodeURIComponent(checkpoint)}&fields=date`,
    { headers: AUTH },
  );
  expect(res.status).toBe(200);
  const body = await res.json();
  expect(body.data).toHaveLength(1);
  expect(body.data[0].data).toEqual({ date: "2026-01-02" });
});

describe("field names are data on the read path", () => {
  // JSON.parse makes `__proto__` an own property, as a stored record does.
  const record = JSON.parse(
    '{"id":"t1","date":"2026-01-02","__proto__":"own proto field","constructor":"own constructor field"}',
  ) as Record<string, unknown>;

  it("discloses a granted field named __proto__ or constructor when the record has it", async () => {
    const { app } = buildApp(
      grantV02(["date", "__proto__", "constructor"]),
      record,
    );
    const data = await listData(app);
    expect(Object.keys(data).sort()).toEqual([
      "__proto__",
      "constructor",
      "date",
    ]);
    expect(Object.getOwnPropertyDescriptor(data, "__proto__")?.value).toBe(
      "own proto field",
    );
    expect(data.constructor).toBe("own constructor field");
  });

  it("does not invent a granted field the record lacks because Object.prototype has it", async () => {
    const { app } = buildApp(
      grantV02(["date", "toString", "hasOwnProperty", "__proto__"]),
      JSON.parse('{"id":"t1","date":"2026-01-02"}'),
    );
    const data = await listData(app);
    expect(Object.keys(data)).toEqual(["date"]);
  });
});
