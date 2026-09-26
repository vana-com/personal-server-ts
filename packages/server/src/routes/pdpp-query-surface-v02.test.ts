/**
 * The v0.2 durable client-token query surface, and what falls outside it.
 *
 * Inventory rows `v0.2-8.4-1` … `v0.2-8.4-5`, `v0.2-struct-10`,
 * `v0.2-struct-13`, `v0.2-struct-15`, `v0.2-struct-16`, `v0.2-8.7-1`.
 *
 * > "The durable client-token base query surface in v0.2 is: `limit`,
 * > `cursor`, `order`, `fields`, `changes_since`, and blob fetch."
 *
 * Everything else — `filter[...]` in either its exact or range form, `view`,
 * `expand[]`, `expand_limit[...]` — "MUST be rejected with HTTP 400
 * `invalid_request` **before the RS consults current SourceDeclaration or
 * serving metadata**".
 *
 * ## Why the ordering is the requirement, not a detail
 *
 * A rejection that happens after the declaration lookup is a rejection that
 * can be preceded by a *different* answer. Consult the declaration first and
 * an unsupported `filter[...]` on a stream the grant cannot serve answers 403
 * `disclosure_unavailable`, or on a stream that does not exist answers 404 —
 * so the same malformed request returns three different codes depending on
 * facts about the owner's data. That turns the error code into an oracle: a
 * client can probe which streams exist and which projections are servable
 * using requests it already knows are invalid.
 *
 * So these tests do not merely assert 400. They assert 400 in cases where a
 * later check would confidently answer something else, which is the only way
 * to observe the ordering from outside.
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
    declaredFields: ["id", "date", "amount"],
  },
]);

function grant(fields: string[]): Grant {
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

function buildApp(g: Grant = grant(["date", "amount"])) {
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
        data: { id: "t1", date: "2026-01-02", amount: 12 },
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

/** Every shape v0.2 puts outside the durable client-token query surface. */
const OUTSIDE_THE_SURFACE = [
  ["exact filter", "filter[merchant]=acme"],
  ["range filter", "filter[amount][gte]=5"],
  ["view", "view=basic"],
  ["expand", "expand[]=other"],
  ["expand_limit", "expand_limit[other]=5"],
] as const;

describe("v0.2: the durable client-token query surface", () => {
  for (const [label, qs] of OUTSIDE_THE_SURFACE) {
    it(`rejects a client-token ${label} on a list read with 400 invalid_request`, async () => {
      const res = await buildApp().request(
        `/streams/transactions/records?${qs}`,
        { headers: AUTH },
      );
      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        error: { code: string; param?: string };
      };
      expect(body.error.code).toBe("invalid_request");
      // The offending parameter is named, so a client can fix the request
      // rather than bisecting its own query string.
      expect(body.error.param).toBeDefined();
    });
  }

  for (const [label, qs] of OUTSIDE_THE_SURFACE) {
    it(`rejects a client-token ${label} BEFORE the declaration is consulted`, async () => {
      // The stream does not exist. A declaration lookup that ran first would
      // answer 404 `not_found`; 400 is only reachable if the parameter check
      // ran first.
      const res = await buildApp().request(
        `/streams/nonexistent/records?${qs}`,
        {
          headers: AUTH,
        },
      );
      expect(res.status).toBe(400);
      expect(
        ((await res.json()) as { error: { code: string } }).error.code,
      ).toBe("invalid_request");
    });
  }

  for (const [label, qs] of OUTSIDE_THE_SURFACE) {
    it(`rejects a client-token ${label} BEFORE the projection is resolved`, async () => {
      // This grant is unservable (`legacy_note` is undeclared), so resolving
      // the projection first would answer 403 `disclosure_unavailable` and
      // leak that the grant/declaration pair is mismatched. 400 proves the
      // parameter check wins.
      const res = await buildApp(grant(["date", "legacy_note"])).request(
        `/streams/transactions/records?${qs}`,
        { headers: AUTH },
      );
      expect(res.status).toBe(400);
      expect(
        ((await res.json()) as { error: { code: string } }).error.code,
      ).toBe("invalid_request");
    });
  }

  for (const [label, qs] of OUTSIDE_THE_SURFACE) {
    it(`rejects a client-token ${label} on a single-record read`, async () => {
      const res = await buildApp().request(
        `/streams/transactions/records/t1?${qs}`,
        { headers: AUTH },
      );
      expect(res.status).toBe(400);
    });
  }

  it("still serves every member of the durable surface", async () => {
    // The rejections above must not have narrowed what v0.2 keeps. Each of
    // these is explicitly in `v0.2-8.4-4`.
    for (const qs of [
      "limit=10",
      "order=asc",
      "fields=date",
      // `changes_since` takes an opaque cursor token, not a timestamp; the
      // empty form is a first-ever sync, which is the shape that proves the
      // parameter is still accepted at all.
      "changes_since=",
    ]) {
      const res = await buildApp().request(
        `/streams/transactions/records?${qs}`,
        { headers: AUTH },
      );
      expect(res.status, qs).toBe(200);
    }
  });
});

describe("v0.2: stream metadata declares no capability the grant does not carry", () => {
  it("reports empty query, views, and relationships to a client token", async () => {
    // `v0.2-8.7-1`: current query/view/relationship/filter/expansion/
    // aggregation capabilities MUST NOT appear unless part of a frozen grant
    // vocabulary. Advertising a capability the read path then rejects would
    // invite exactly the requests the rows above make invalid.
    const res = await buildApp().request("/streams/transactions", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      query: Record<string, unknown>;
      views: unknown[];
      relationships: unknown[];
    };
    expect(body.query).toEqual({});
    expect(body.views).toEqual([]);
    expect(body.relationships).toEqual([]);
  });
});

describe("v0.2: a revoked grant denies reads across every surface", () => {
  // The revocation journey. `v0.2-2-3` ("self-contained JWTs ... MUST NOT be
  // the sole revocation mechanism") is what makes this observable: the RS
  // resolves each read through the AS context, so revocation takes effect on
  // the next read rather than at token expiry.
  function revoked() {
    const store = createMemoryRecordStore();
    return pdppRecordsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: false,
          tokenKind: "client",
          subjectId: "sub_1",
          clientId: "client_1",
          inactiveReason: "grant_revoked",
        },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
    });
  }

  for (const path of [
    "/streams",
    "/streams/transactions",
    "/streams/transactions/records",
    "/streams/transactions/records/t1",
  ]) {
    it(`answers 403 grant_revoked on ${path}`, async () => {
      const res = await revoked().request(path, { headers: AUTH });
      expect(res.status).toBe(403);
      expect(
        ((await res.json()) as { error: { code: string } }).error.code,
      ).toBe("grant_revoked");
    });
  }

  it("discloses no record data in the refusal", async () => {
    const res = await revoked().request("/streams/transactions/records", {
      headers: AUTH,
    });
    const body = await res.json();
    expect(body).not.toHaveProperty("data");
  });
});
