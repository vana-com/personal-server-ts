/**
 * 403 `disclosure_unavailable` — the refusal that keeps a projection honest.
 *
 * Inventory rows `v0.2-4-7`, `v0.2-4-8`, `v0.2-struct-8`, `v0.2-struct-26`.
 *
 * > "An RS unable to serve a requested projection without changing the meaning
 * > of the disclosed data MUST refuse that read with HTTP 403
 * > `disclosure_unavailable`." … "It MUST NOT repair the projection by
 * > disclosing unauthorized fields."
 *
 * ## When this RS is actually unable
 *
 * Its stores can return any subset of a record's top-level members, so the
 * unservable case is not "this field is expensive" — it is STRUCTURAL: the
 * grant approves a field the retained declaration does not declare.
 *
 * That is not a client error and it is not an empty result. The declaration
 * snapshot is the RS's only authority for what a stream's records mean
 * (§8 "Grant enforcement": enforce from the resolved context, never a live
 * lookup). When the grant names a member the snapshot does not, the RS cannot
 * tell whether the member is absent from every record, renamed, or nested
 * somewhere it must not go looking. Each answer discloses something different:
 *
 *   - omit it silently → the client reads "this record has no such value",
 *     which the RS does not know to be true. That is the meaning change
 *     `v0.2-4-7` names.
 *   - return `null` → `v0.2-4-3` forbids it outright.
 *   - serve whatever the record happens to carry under that key → the RS is
 *     disclosing an undeclared member, i.e. repairing the projection with
 *     unauthorized data, which `v0.2-4-8` forbids.
 *
 * So it refuses, and refuses with the code the spec reserves for exactly this,
 * not with a generic `grant_invalid`: a client that is told
 * `disclosure_unavailable` knows its grant is sound and the RS cannot serve it
 * — a different remedy (re-authorize against the current declaration) from a
 * malformed grant, and one CG already distinguishes.
 *
 * v0.1 grants are unaffected: they carry no approved projection to be unable
 * to serve, and a v0.1 deployment where this arises has always resolved it by
 * projecting what it could.
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
    requiredFields: ["id"],
    // The declaration declares exactly these members. `legacy_note` below is
    // NOT one of them.
    declaredFields: ["id", "date", "amount"],
    schema: {
      type: "object",
      properties: {
        id: { type: "string" },
        date: { type: "string" },
        amount: { type: "number" },
      },
    },
  },
]);

function grant(version: string, fields: string[]): Grant {
  return {
    version,
    grant_id: `grant_${version}`,
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

function buildApp(g: Grant) {
  const store = createMemoryRecordStore();
  const tokens: Record<string, PdppTokenContext> = {
    "client-tok": {
      active: true,
      tokenKind: "client",
      subjectId: "sub_1",
      clientId: "client_1",
      grant: g,
    },
  };
  store.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "transactions",
        key: "t1",
        // The record happens to carry `legacy_note`. The declaration does not
        // declare it, so no grant can authorize disclosing it.
        data: {
          id: "t1",
          date: "2026-01-02",
          amount: 12,
          legacy_note: "SENTINEL_UNDECLARED_VALUE",
        },
        emitted_at: "2026-01-02T00:00:00Z",
        op: "upsert",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
  return pdppRecordsRoutes({
    store,
    auth: createFixtureAuthorizationService(tokens),
    declarations,
    instancesForSubject: () => ["inst_1"],
  });
}

/** A v0.2 grant naming a member the retained declaration does not declare. */
const UNSERVABLE = grant("0.2.0", ["date", "legacy_note"]);
const SERVABLE = grant("0.2.0", ["date", "amount"]);

describe("v0.2: an unservable projection is refused, not repaired", () => {
  it("refuses a list read with 403 disclosure_unavailable", async () => {
    const res = await buildApp(UNSERVABLE).request(
      "/streams/transactions/records",
      { headers: AUTH },
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as {
      error: { code: string; type: string; message: string };
    };
    expect(body.error.code).toBe("disclosure_unavailable");
    expect(body.error.type).toBe("permission_error");
  });

  it("refuses a single-record read with the same code", async () => {
    const res = await buildApp(UNSERVABLE).request(
      "/streams/transactions/records/t1",
      { headers: AUTH },
    );
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "disclosure_unavailable",
    );
  });

  it("refuses stream metadata rather than describing a shape it cannot serve", async () => {
    const res = await buildApp(UNSERVABLE).request("/streams/transactions", {
      headers: AUTH,
    });
    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(
      "disclosure_unavailable",
    );
  });

  it("does not repair the projection by disclosing the undeclared member", async () => {
    // `v0.2-4-8`. The refusal must be total: no 200 carrying a partial body,
    // and nothing in the error that echoes the record's undeclared value.
    const res = await buildApp(UNSERVABLE).request(
      "/streams/transactions/records",
      { headers: AUTH },
    );
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain("SENTINEL_UNDECLARED_VALUE");
  });

  it("names the member it cannot serve, without inventing one", async () => {
    // An operator has to be able to fix this, and the fix is to reissue the
    // grant against the current declaration. A refusal that says only "cannot
    // serve" leaves them diffing a grant against a snapshot by hand.
    const res = await buildApp(UNSERVABLE).request(
      "/streams/transactions/records",
      { headers: AUTH },
    );
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("legacy_note");
  });

  it("serves a projection the declaration does cover", async () => {
    // The guard must not become a blanket refusal: the servable grant is
    // exactly as servable as it was before.
    const res = await buildApp(SERVABLE).request(
      "/streams/transactions/records",
      { headers: AUTH },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: Array<{ data: Record<string, unknown> }>;
    };
    expect(Object.keys(body.data[0].data).sort()).toEqual(["amount", "date"]);
  });

  it("leaves a v0.1 grant serving what it can, as it always has", async () => {
    // A v0.1 grant has no approved projection to be unable to serve, and its
    // deployments have always resolved this by projecting the members they
    // had. Refusing here would break reads that work today.
    const res = await buildApp(grant("0.1.0", ["date", "legacy_note"])).request(
      "/streams/transactions/records",
      { headers: AUTH },
    );
    expect(res.status).toBe(200);
  });
});

describe("v0.2: an empty result is not a permission denial", () => {
  // `v0.2-4-7` sits beside "empty data is not permission denial"
  // (inventory §5, "Resolution SHALL distinguish permission from records").
  // A grant that is perfectly servable and simply matches no record must
  // answer 200 with an empty list -- not 403, and not the new code.
  it("answers 200 with an empty list when the grant matches no record", async () => {
    const empty = grant("0.2.0", ["date", "amount"]);
    empty.streams[0].resources = ["no-such-key"];
    const res = await buildApp(empty).request("/streams/transactions/records", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      object: string;
      data: unknown[];
      has_more: boolean;
    };
    expect(body.object).toBe("list");
    expect(body.data).toEqual([]);
    expect(body.has_more).toBe(false);
  });

  it("answers 200 with an empty list when the time window excludes every record", async () => {
    const empty = grant("0.2.0", ["date", "amount"]);
    empty.streams[0].time_constraint = {
      field: "date",
      since: "2030-01-01",
    };
    const res = await buildApp(empty).request("/streams/transactions/records", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown[] }).data).toEqual([]);
  });
});
