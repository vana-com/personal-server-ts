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
    expect(res.headers.get("PDPP-Version")).toBe("2026-04-06");
    expect(res.headers.get("Request-Id")).toMatch(/^req_/);
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
});
