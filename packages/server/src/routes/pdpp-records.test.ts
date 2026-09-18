import { describe, it, expect } from "vitest";
import { PDPP_VERSION } from "@opendatalabs/personal-server-ts-core/pdpp-version";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  pdppRecordsRoutes,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";

const declarations = createStreamDeclarationRegistry([
  {
    name: "playlists",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
  {
    name: "messages",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

function clientGrant(overrides: Partial<Grant["streams"][number]> = {}): Grant {
  return {
    version: "0.1.0",
    grant_id: "grant_1",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: "client_1" },
    source: { kind: "provider_native", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "playlists",
        instance_ids: ["inst_1"],
        fields: ["id", "name"],
        ...overrides,
      },
    ],
  };
}

function buildApp(
  tokens: Record<string, PdppTokenContext>,
  deps: Partial<PdppRecordsRouteDeps> = {},
) {
  const store = deps.store ?? createMemoryRecordStore();
  const auth = createFixtureAuthorizationService(tokens);
  return {
    store,
    app: pdppRecordsRoutes({
      store,
      auth,
      declarations,
      instancesForSubject: () => ["inst_1"],
      ...deps,
    }),
  };
}

describe("pdpp records routes: authentication", () => {
  it("returns 401 with WWW-Authenticate + resource_metadata when no token is provided", async () => {
    const { app } = buildApp({});
    const res = await app.request("/streams");
    expect(res.status).toBe(401);
    expect(res.headers.get("WWW-Authenticate")).toContain("resource_metadata=");
    const body = await res.json();
    expect(body.error.code).toBe("authentication_error");
  });

  it("returns 403 grant_stream_not_allowed for a client token missing the requested stream", async () => {
    const { app } = buildApp({
      "client-tok": {
        active: true,
        tokenKind: "client",
        subjectId: "sub_1",
        grant: { ...clientGrant(), streams: [] },
      },
    });
    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe("grant_stream_not_allowed");
  });

  it("maps grant_revoked inactiveReason to 403 grant_revoked", async () => {
    const { app } = buildApp({
      "revoked-tok": {
        active: false,
        tokenKind: "client",
        subjectId: "sub_1",
        inactiveReason: "grant_revoked",
      },
    });
    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer revoked-tok" },
    });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe("grant_revoked");
  });
});

describe("pdpp records routes: 500 observability", () => {
  // An unexpected store fault used to escape `toPdppError` as a rethrow, so
  // the route emitted no PDPP error body of its own and the only record of it
  // was the framework's generic handler — no route, no Request-Id, nothing to
  // correlate with the client's response.
  function appWithExplodingStore() {
    const logged: Record<string, unknown>[] = [];
    const store = createMemoryRecordStore();
    const { app } = buildApp(
      {
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      },
      {
        store: {
          ...store,
          listRecords: () => {
            throw new Error("store exploded");
          },
        } as never,
        logger: {
          error: (payload: Record<string, unknown>) => {
            logged.push(payload);
          },
        } as never,
      },
    );
    return { app, logged };
  }

  it("answers api_error with a Request-Id instead of an unhandled throw", async () => {
    const { app } = appWithExplodingStore();

    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });

    expect(res.status).toBe(500);
    expect(res.headers.get("Request-Id")).toMatch(/^req_/);
    const body = await res.json();
    expect(body.error.code).toBe("api_error");
  });

  it("logs the fault with route and the same request id it answered with", async () => {
    const { app, logged } = appWithExplodingStore();

    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });

    expect(logged).toHaveLength(1);
    expect(logged[0]).toMatchObject({
      route: "GET /v1/streams/:stream/records",
      requestId: res.headers.get("Request-Id"),
      errorCode: "api_error",
    });
    expect(JSON.stringify(logged[0])).toContain("store exploded");
    // No token material in the line.
    expect(JSON.stringify(logged[0])).not.toContain("owner-tok");
  });
});

describe("pdpp records routes: field projection", () => {
  it("never exposes an unprojected field to a client token via list/get", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "visible", secret: "hidden" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      },
      { store },
    );

    const listRes = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer client-tok" },
    });
    const listBody = await listRes.json();
    expect(listBody.data[0].data).not.toHaveProperty("secret");

    const getRes = await app.request(
      `/streams/playlists/records/${encodeURIComponent("pl_1")}`,
      {
        headers: { Authorization: "Bearer client-tok" },
      },
    );
    const getBody = await getRes.json();
    expect(getBody.data).not.toHaveProperty("secret");
  });

  it("rejects filter[...] from a client token before declaration lookup", async () => {
    const { app } = buildApp({
      "client-tok": {
        active: true,
        tokenKind: "client",
        subjectId: "sub_1",
        grant: clientGrant(),
      },
    });
    const res = await app.request("/streams/playlists/records?filter[name]=x", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_request");
  });

  it("owner read succeeds without a filter, then the same request with an unsupported filter[...] is rejected with 400", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "visible" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
        },
      },
      { store },
    );

    const okRes = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(okRes.status).toBe(200);
    const okBody = await okRes.json();
    expect(okBody.data.map((r: { id: string }) => r.id)).toContain("pl_1");

    for (const endpoint of [
      "/streams",
      "/streams/playlists",
      "/streams/playlists/records",
      "/streams/playlists/records/pl_1",
    ]) {
      for (const filter of [
        "filter[name]=visible",
        "filter[captured_at][gte]=2026-01-01",
        "filter=anything",
        "filter[name][bad][shape]=anything",
      ]) {
        const response = await app.request(`${endpoint}?${filter}`, {
          headers: { Authorization: "Bearer owner-tok" },
        });
        expect(response.status).toBe(400);
        expect((await response.json()).error.code).toBe("invalid_request");
      }
    }
  });

  it("filters correctly on time_constraint even when the constraint field is not in the grant's authorized fields (list)", async () => {
    // Regression: field projection must not run before time_constraint
    // filtering. The grant's authorized fields below are ["id", "name"] --
    // deliberately excluding "captured_at", the field the time_constraint
    // is evaluated against. If projection ran first, captured_at would read
    // as undefined by the time the filter checks it, and the filter would
    // misbehave rather than compare against the record's real value.
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_in",
          data: {
            id: "pl_in",
            name: "in range",
            captured_at: "2026-03-01T00:00:00Z",
          },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_out",
          data: {
            id: "pl_out",
            name: "out of range",
            captured_at: "2026-06-01T00:00:00Z",
          },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant({
            fields: ["id", "name"],
            time_constraint: {
              field: "captured_at",
              until: "2026-04-01T00:00:00Z",
            },
          }),
        },
      },
      { store },
    );

    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const keys = body.data.map((r: { id: string }) => r.id);

    // Correct behavior: pl_in (captured_at < until) is included, pl_out
    // (captured_at >= until) is excluded -- proving the filter compared
    // against the real captured_at value, not an already-stripped one.
    expect(keys).toContain("pl_in");
    expect(keys).not.toContain("pl_out");

    // And the ungranted field never reaches the response regardless.
    for (const record of body.data) {
      expect(record.data).not.toHaveProperty("captured_at");
    }
  });

  it("filters correctly on time_constraint even when the constraint field is not in the grant's authorized fields (changes_since)", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_in",
          data: {
            id: "pl_in",
            name: "in range",
            captured_at: "2026-03-01T00:00:00Z",
          },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_out",
          data: {
            id: "pl_out",
            name: "out of range",
            captured_at: "2026-06-01T00:00:00Z",
          },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant({
            fields: ["id", "name"],
            time_constraint: {
              field: "captured_at",
              until: "2026-04-01T00:00:00Z",
            },
          }),
        },
      },
      { store },
    );

    const res = await app.request("/streams/playlists/records?changes_since=", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const keys = body.data.map((r: { id: string }) => r.id);
    expect(keys).toContain("pl_in");
    expect(keys).not.toContain("pl_out");
    for (const record of body.data) {
      expect(record.data).not.toHaveProperty("captured_at");
    }
  });
});

describe("pdpp records routes: changes_since eligibility", () => {
  it("does not surface a record whose only change is outside the client grant's field projection", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1", secret: "s1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      },
      { store },
    );

    const session1 = await app.request(
      "/streams/playlists/records?changes_since=",
      {
        headers: { Authorization: "Bearer client-tok" },
      },
    );
    const session1Body = await session1.json();

    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1", secret: "s2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );

    const session2 = await app.request(
      `/streams/playlists/records?changes_since=${encodeURIComponent(session1Body.next_changes_since)}`,
      { headers: { Authorization: "Bearer client-tok" } },
    );
    const session2Body = await session2.json();
    expect(session2Body.data).toHaveLength(0);
  });
});

describe("pdpp records routes: tombstones", () => {
  it("produces a spec-shaped tombstone on owner DELETE and surfaces it in changes_since", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    const session1 = await app.request(
      "/streams/playlists/records?changes_since=",
      {
        headers: { Authorization: "Bearer owner-tok" },
      },
    );
    const session1Body = await session1.json();

    const deleteRes = await app.request("/streams/playlists/records/pl_1", {
      method: "DELETE",
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(deleteRes.status).toBe(204);

    const session2 = await app.request(
      `/streams/playlists/records?changes_since=${encodeURIComponent(session1Body.next_changes_since)}`,
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    const session2Body = await session2.json();
    expect(session2Body.data).toHaveLength(1);
    expect(session2Body.data[0].deleted).toBe(true);
    expect(session2Body.data[0]).not.toHaveProperty("data");
  });

  it("rejects DELETE from a client token", async () => {
    const { app } = buildApp({
      "client-tok": {
        active: true,
        tokenKind: "client",
        subjectId: "sub_1",
        grant: clientGrant(),
      },
    });
    const res = await app.request("/streams/playlists/records/pl_1", {
      method: "DELETE",
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(401);
  });
});

describe("pdpp records routes: version negotiation", () => {
  it("returns 400 unsupported_version for an unrecognized PDPP-Version header", async () => {
    const { app } = buildApp({
      "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
    });
    const res = await app.request("/streams", {
      headers: {
        Authorization: "Bearer owner-tok",
        "PDPP-Version": "1999-01-01",
      },
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("unsupported_version");
  });

  it("echoes the negotiated PDPP-Version on a normal response", async () => {
    const { app } = buildApp({
      "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
    });
    const res = await app.request("/streams", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.headers.get("PDPP-Version")).toBe(PDPP_VERSION);
    expect(res.headers.get("Request-Id")).toMatch(/^req_/);
  });

  it("accepts the shared PDPP_VERSION constant explicitly (C1 regression seam)", async () => {
    // Regression seam for C1 (AS and RS previously required mutually
    // exclusive PDPP-Version values: RS "2026-04-06" vs AS "0.1.0"). This
    // route now imports PDPP_VERSION from the shared
    // @opendatalabs/personal-server-ts-core/pdpp-version module rather than
    // declaring its own local constant. This test sends that exact shared
    // value and confirms the RS surface accepts it -- the AS lane adopting
    // the same import is the other half of this fix, tracked in this lane's
    // contract file since this lane does not own AS-side files.
    const { app } = buildApp({
      "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
    });
    const res = await app.request("/streams", {
      headers: {
        Authorization: "Bearer owner-tok",
        "PDPP-Version": PDPP_VERSION,
      },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("PDPP-Version")).toBe(PDPP_VERSION);
  });
});

describe("pdpp records routes: pagination limit clamping", () => {
  it("clamps a limit above 100 and reports limit_clamped without erroring", async () => {
    const { app } = buildApp({
      "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
    });
    const res = await app.request("/streams/playlists/records?limit=500", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.meta.warnings).toEqual([
      { code: "limit_clamped", message: expect.any(String) },
    ]);
  });
});

describe("pdpp records routes: cursor/order mismatch", () => {
  it("rejects a next_cursor reused with a different order as invalid_cursor", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_2",
          data: { id: "pl_2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );
    const page1 = await app.request(
      "/streams/playlists/records?limit=1&order=asc",
      {
        headers: { Authorization: "Bearer owner-tok" },
      },
    );
    const page1Body = await page1.json();
    const page2 = await app.request(
      `/streams/playlists/records?limit=1&order=desc&cursor=${encodeURIComponent(page1Body.next_cursor)}`,
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    expect(page2.status).toBe(400);
    const body = await page2.json();
    expect(body.error.code).toBe("invalid_cursor");
  });

  it("paginates correctly across pages for a client token whose fields exclude the time_constraint field", async () => {
    // Regression, cursor half: the sort/cursor key is envelope-level
    // (emitted_at, record_key), never a projected data field, so a grant
    // whose fields exclude an arbitrary data field must not disturb
    // pagination continuity. Three records, `limit=1`, walk every page.
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "a", captured_at: "2026-01-01T00:00:00Z" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_2",
          data: { id: "pl_2", name: "b", captured_at: "2026-01-02T00:00:00Z" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_3",
          data: { id: "pl_3", name: "c", captured_at: "2026-01-03T00:00:00Z" },
          emitted_at: "2026-04-03T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant({ fields: ["id", "name"] }), // excludes captured_at
        },
      },
      { store },
    );

    const seen: string[] = [];
    let cursor: string | undefined;
    for (let i = 0; i < 3; i++) {
      const url = cursor
        ? `/streams/playlists/records?limit=1&order=asc&cursor=${encodeURIComponent(cursor)}`
        : "/streams/playlists/records?limit=1&order=asc";
      const res = await app.request(url, {
        headers: { Authorization: "Bearer client-tok" },
      });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data).toHaveLength(1);
      seen.push(body.data[0].id);
      cursor = body.next_cursor;
    }
    expect(seen).toEqual(["pl_1", "pl_2", "pl_3"]);
  });

  it("scopes an owner-token read to its own subject's instances after the projection-ordering fix", async () => {
    // Regression, owner-scoping half: confirms the fix to fields handling
    // in the store calls did not disturb the separate instance-scoping path
    // owner-token reads use. A record on an instance not returned by
    // instancesForSubject must not appear.
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_mine",
          data: { id: "pl_mine", name: "mine" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_other",
          stream: "playlists",
          key: "pl_not_mine",
          data: { id: "pl_not_mine", name: "not mine" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store, instancesForSubject: () => ["inst_1"] },
    );
    const res = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    const body = await res.json();
    const keys = body.data.map((r: { id: string }) => r.id);
    expect(keys).toContain("pl_mine");
    expect(keys).not.toContain("pl_not_mine");
  });
});

describe("pdpp records routes: unsupported view/expand shapes", () => {
  function ownerStoreWithRecord() {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "visible" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    return store;
  }

  it("owner read succeeds without view/expand, then the same shapes are rejected on both record endpoints", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    const okList = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(okList.status).toBe(200);
    const okListBody = await okList.json();
    expect(okListBody.data.map((r: { id: string }) => r.id)).toContain("pl_1");

    const okGet = await app.request(
      `/streams/playlists/records/${encodeURIComponent("pl_1")}`,
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    expect(okGet.status).toBe(200);

    for (const endpoint of [
      "/streams/playlists/records",
      "/streams/playlists/records/pl_1",
    ]) {
      const expandCases = [
        "expand[]=messages",
        "expand[]=undeclared_relation",
        "expand_limit[messages]=3",
      ];
      for (const q of expandCases) {
        const res = await app.request(`${endpoint}?${q}`, {
          headers: { Authorization: "Bearer owner-tok" },
        });
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_expand");
      }

      const viewCases = ["view=summary", "view=anything"];
      for (const q of viewCases) {
        const res = await app.request(`${endpoint}?${q}`, {
          headers: { Authorization: "Bearer owner-tok" },
        });
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_request");
      }
    }
  });

  it("rejects owner expand/view on metadata and list-streams endpoints as invalid_request", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    for (const endpoint of ["/streams", "/streams/playlists"]) {
      const res1 = await app.request(`${endpoint}?view=summary`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res1.status).toBe(400);
      expect((await res1.json()).error.code).toBe("invalid_request");

      for (const q of ["expand[]=messages", "expand_limit[messages]=3"]) {
        const res = await app.request(`${endpoint}?${q}`, {
          headers: { Authorization: "Bearer owner-tok" },
        });
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_request");
      }
    }
  });

  it("still rejects client-token view/expand/expand_limit as invalid_request without declaration lookup", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      {
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      },
      {
        store,
        declarations: {
          ...declarations,
          get: () => {
            throw new Error("Unexpected declaration lookup");
          },
        },
      },
    );

    for (const endpoint of [
      "/streams/playlists/records",
      "/streams/playlists/records/pl_1",
    ]) {
      for (const q of [
        "view=summary",
        "expand[]=messages",
        "expand_limit[messages]=3",
      ]) {
        const res = await app.request(`${endpoint}?${q}`, {
          headers: { Authorization: "Bearer client-tok" },
        });
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_request");
      }
    }
  });

  it("rejects bare/malformed forms: bare 'expand', bare 'expand_limit', bare 'view'", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    for (const q of ["expand=messages", "expand_limit=3", "view"]) {
      const res = await app.request(`/streams/playlists/records?${q}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(400);
      expect(["invalid_expand", "invalid_request"]).toContain(
        (await res.json()).error.code,
      );
    }
  });

  it("rejects bracketed forms of otherwise-supported base names instead of silently accepting them", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    for (const q of [
      "limit[x]=5",
      "fields[x]=id",
      "order[x]=asc",
      "cursor[x]=abc",
      "changes_since[x]=2026-01-01",
    ]) {
      const res = await app.request(`/streams/playlists/records?${q}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_request");
    }

    const getRes = await app.request(
      "/streams/playlists/records/pl_1?fields[x]=id",
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    expect(getRes.status).toBe(400);
    expect((await getRes.json()).error.code).toBe("invalid_request");
  });

  it("supported limit, order and fields still work for owner reads", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );

    const res = await app.request(
      "/streams/playlists/records?limit=10&order=asc&fields=id,name",
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.data.map((r: { id: string }) => r.id)).toContain("pl_1");

    const changesRes = await app.request(
      "/streams/playlists/records?changes_since=",
      { headers: { Authorization: "Bearer owner-tok" } },
    );
    expect(changesRes.status).toBe(200);
  });

  it("owner stream metadata declares no optional query capabilities", async () => {
    const store = ownerStoreWithRecord();
    const { app } = buildApp(
      { "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" } },
      { store },
    );
    const res = await app.request("/streams/playlists", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.query).toEqual({});
    expect(body.views).toEqual([]);
    expect(body.relationships).toEqual([]);
  });
});
