import { fixedOwnedAccountStorageMode as explicitLegacyStorageMode } from "@opendatalabs/personal-server-ts-core/test-utils";
/**
 * PDPP Core v0.1.0 §9 Resource Server items, driven over HTTP against both
 * unswitched record-store backends (memory and SQLite): RS 1, 2, 6, 7, 8, 14,
 * 15, 20, 21, 23, 26, 31, 32, 33. Blob items 10, 18, 23 are in
 * `pdpp-blobs.test.ts`.
 */
import Database from "better-sqlite3";
import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { PdppTokenContext } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { PdppBindingError } from "../storage/pdpp-records-sqlite-store.js";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const A = "inst_a";
const B = "inst_b";

function grant(
  streams: Array<Record<string, unknown>>,
  grantId = "g1",
): PdppTokenContext["grant"] {
  return {
    version: "0.1.0",
    grant_id: grantId,
    issued_at: "2026-01-01T00:00:00.000Z",
    subject: { id: "sub" },
    client: { client_id: "c1" },
    source: { kind: "connector", id: "src" },
    source_declaration: { version: "v1" },
    purpose_code: "p",
    access_mode: "continuous",
    streams: streams as never,
  };
}

const twoInstances = {
  name: "s",
  instance_ids: [A, B],
  fields: ["id", "name", "at"],
  required_fields: ["id"],
};

const tokens: Record<string, PdppTokenContext> = {
  client: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant([twoInstances]),
  },
  other: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant([twoInstances], "g2"),
  },
  single: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant([{ ...twoInstances, instance_ids: [A] }], "g3"),
  },
  sorted: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant([{ ...twoInstances, sort_field: "at" }], "g4"),
  },
  windowed: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant(
      [
        {
          ...twoInstances,
          instance_ids: [A],
          time_constraint: {
            field: "at",
            type: "date-time",
            since: "2026-01-01T00:00:00Z",
          },
        },
      ],
      "g5",
    ),
  },
  owner: {
    active: true,
    tokenKind: "owner",
    subjectId: "owner",
    instanceIds: [A, B],
  },
};

type Backend = "memory" | "sqlite";

function setup(backend: Backend, wrap?: (s: PdppRecordStore) => PdppRecordStore) {
  let store: PdppRecordStore;
  if (backend === "memory") store = createMemoryRecordStore();
  else store = createTestBoundRecordStore(new Database(":memory:"));
  const declarations = createStreamDeclarationRegistry([
    {
      name: "s",
      semantics: "mutable_state",
      primaryKey: ["id"],
      cursorField: "at",
      requiredFields: ["id"],
      schema: { properties: { id: {}, name: {}, at: {}, secret: {} } },
      selection: { fields: true },
    },
  ]);
  const ingest = (
    rows: Array<{ instance: string; id: string; [k: string]: unknown }>,
  ) =>
    store.ingestBatch(
      rows.map(({ instance, ...data }) => ({
        instance,
        stream: "s",
        key: data.id,
        data,
        emitted_at: "2026-05-01T00:00:00.000Z",
      })),
      () => "mutable_state",
      () => ["id"],
    );
  const routed = wrap ? wrap(store) : store;
  const app = new Hono();
  app.route(
    "/v1",
    pdppRecordsRoutes({
      accountStorageMode: explicitLegacyStorageMode("unswitched"),
      store: routed,
      auth: createFixtureAuthorizationService(tokens),
      declarations,
      instancesForSubject: () => [A, B],
    }),
  );
  const get = (path: string, token = "client") =>
    app.request(`/v1${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  const del = (path: string, token = "owner") =>
    app.request(`/v1${path}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
  return { app, store, ingest, get, del, declarations };
}

const seed = [
  { instance: A, id: "k2", name: "n", at: "2026-03-01T00:00:00Z", secret: "x" },
  { instance: A, id: "k1", name: "n", at: "2026-05-01T00:00:00Z", secret: "x" },
  { instance: B, id: "k0", name: "n", at: "not-a-time", secret: "x" },
  { instance: B, id: "k3", name: "n", at: "2026-04-01", secret: "x" },
];

async function walk(
  get: (path: string, token?: string) => Promise<Response>,
  path: string,
  token = "client",
) {
  const out: Array<Record<string, unknown>> = [];
  let url = path;
  for (;;) {
    const res = await get(url, token);
    expect(res.status).toBe(200);
    const body = await res.json();
    out.push(...body.data);
    if (!body.has_more) return { records: out, last: body };
    const sep = path.includes("?") ? "&" : "?";
    url = `${path}${sep}cursor=${encodeURIComponent(body.next_cursor)}`;
  }
}

describe.each<Backend>(["memory", "sqlite"])("RS conformance (%s store)", (backend) => {
  it("RS 23/26: client records carry instance_id and no emitted_at; owner records carry both", async () => {
    const { ingest, get } = setup(backend);
    ingest(seed);
    const client = await (await get("/streams/s/records")).json();
    for (const record of client.data) {
      expect(Object.keys(record).sort()).toEqual(
        ["data", "id", "instance_id", "object", "stream"].sort(),
      );
      expect(record.data.secret).toBeUndefined();
    }
    const owner = await (await get("/streams/s/records", "owner")).json();
    for (const record of owner.data) {
      expect(record.instance_id).toMatch(/^inst_/);
      expect(record.emitted_at).toBe("2026-05-01T00:00:00.000Z");
    }
  });

  it("RS 33: a grant without sort_field lists in descending (instance_id, key) order by default", async () => {
    const { ingest, get } = setup(backend);
    ingest(seed);
    const desc = await walk(get, "/streams/s/records?limit=1");
    expect(desc.records.map((r) => `${r.instance_id}/${r.id}`)).toEqual([
      "inst_b/k3",
      "inst_b/k0",
      "inst_a/k2",
      "inst_a/k1",
    ]);
    const asc = await walk(get, "/streams/s/records?limit=1&order=asc");
    expect(asc.records.map((r) => `${r.instance_id}/${r.id}`)).toEqual([
      "inst_a/k1",
      "inst_a/k2",
      "inst_b/k0",
      "inst_b/k3",
    ]);
  });

  it("RS 2/33: a frozen sort_field orders by its instant or date, invalid values last", async () => {
    const { ingest, get } = setup(backend);
    ingest(seed);
    const desc = await walk(get, "/streams/s/records?limit=1", "sorted");
    expect(desc.records.map((r) => r.id)).toEqual(["k1", "k3", "k2", "k0"]);
    const asc = await walk(
      get,
      "/streams/s/records?limit=1&order=asc",
      "sorted",
    );
    expect(asc.records.map((r) => r.id)).toEqual(["k2", "k3", "k1", "k0"]);
  });

  it("RS 21: page cursors are sealed, fresh per issue, and bound to grant and query context", async () => {
    const { ingest, get } = setup(backend);
    ingest(seed);
    const first = await (await get("/streams/s/records?limit=1")).json();
    const again = await (await get("/streams/s/records?limit=1")).json();
    const cursor: string = first.next_cursor;
    expect(cursor).toMatch(/^pc_/);
    expect(cursor).not.toBe(again.next_cursor);
    const opened = Buffer.from(cursor.slice(3), "base64url").toString("latin1");
    for (const leak of ["k3", "inst_b", "2026", "horizon", "sortValue"])
      expect(opened).not.toContain(leak);
    const c = encodeURIComponent(cursor);
    expect((await get(`/streams/s/records?limit=1&cursor=${c}`)).status).toBe(
      200,
    );
    for (const [path, token] of [
      [`/streams/s/records?limit=1&cursor=${c}&fields=id`, "client"],
      [`/streams/s/records?limit=1&cursor=${c}&order=asc`, "client"],
      [`/streams/s/records?limit=1&cursor=${c}`, "other"],
      [`/streams/s/records?limit=1&changes_since=${c}`, "client"],
    ] as const) {
      const res = await get(path, token);
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_cursor");
    }
  });

  it("RS 7/8/21: changes_since starts from beginning, pages carry next_changes_since only at the end, and order is (instance_id, key)", async () => {
    const { ingest, get } = setup(backend);
    ingest(seed);
    const pages = [];
    let url = "/streams/s/records?changes_since=beginning&limit=1";
    for (;;) {
      const body = await (await get(url)).json();
      pages.push(body);
      if (!body.has_more) break;
      expect(body.next_changes_since).toBeUndefined();
      url = `/streams/s/records?changes_since=beginning&limit=1&cursor=${encodeURIComponent(body.next_cursor)}`;
    }
    expect(pages.flatMap((p) => p.data).map((r) => `${r.instance_id}/${r.id}`)).toEqual([
      "inst_a/k1",
      "inst_a/k2",
      "inst_b/k0",
      "inst_b/k3",
    ]);
    const token: string = pages.at(-1).next_changes_since;
    expect(token).toMatch(/^cs_/);
    const next = await (
      await get(`/streams/s/records?changes_since=${encodeURIComponent(token)}`)
    ).json();
    expect(next.data).toEqual([]);
    expect(next.next_changes_since).toMatch(/^cs_/);
    expect(next.next_changes_since).not.toBe(token);

    const owner = await (
      await get("/streams/s/records?changes_since=beginning", "owner")
    ).json();
    expect(owner.data).toHaveLength(4);

    for (const bad of ["not-a-token", "", "cs_AAAA"]) {
      const res = await get(
        `/streams/s/records?changes_since=${encodeURIComponent(bad)}`,
      );
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_cursor");
    }
    // Bound to the grant and the query context.
    for (const [path, tokenName] of [
      [`/streams/s/records?changes_since=${encodeURIComponent(token)}`, "other"],
      [
        `/streams/s/records?changes_since=${encodeURIComponent(token)}&fields=id`,
        "client",
      ],
    ] as const) {
      const res = await get(path, tokenName);
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_cursor");
    }
    // A pre-sealing token this RS issued expires instead (410).
    const legacy = Buffer.from(
      JSON.stringify({ kind: "changes_since", horizon: "1" }),
    ).toString("base64url");
    const expired = await get(`/streams/s/records?changes_since=${legacy}`);
    expect(expired.status).toBe(410);
    expect((await expired.json()).error.code).toBe("cursor_expired");
  });

  it("RS 21: expand on a changes_since request is 400 invalid_request for every token kind", async () => {
    const { get } = setup(backend);
    for (const token of ["client", "owner"]) {
      const res = await get(
        "/streams/s/records?changes_since=beginning&expand[]=x",
        token,
      );
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe("invalid_request");
    }
  });

  it("RS 20: exact client tombstone; owner tombstone adds removal and deletion times; no tombstone for an unseen record", async () => {
    const { ingest, get, del } = setup(backend);
    ingest([seed[0]]);
    const start = async (token: string) =>
      (
        await (
          await get("/streams/s/records?changes_since=beginning", token)
        ).json()
      ).next_changes_since as string;
    const clientToken = await start("client");
    const ownerToken = await start("owner");
    // Visible only between the two horizons: never tombstoned.
    ingest([{ instance: A, id: "brief", name: "n", at: "2026-02-01T00:00:00Z" }]);
    expect(
      (await del(`/streams/s/records/brief?instance_id=${A}`)).status,
    ).toBe(204);
    expect((await del(`/streams/s/records/k2?instance_id=${A}`)).status).toBe(
      204,
    );

    const client = await (
      await get(`/streams/s/records?changes_since=${encodeURIComponent(clientToken)}`)
    ).json();
    expect(client.data).toEqual([
      { object: "record", id: "k2", instance_id: A, stream: "s", deleted: true },
    ]);
    const owner = await (
      await get(
        `/streams/s/records?changes_since=${encodeURIComponent(ownerToken)}`,
        "owner",
      )
    ).json();
    expect(owner.data).toHaveLength(1);
    expect(owner.data[0]).toMatchObject({
      object: "record",
      id: "k2",
      instance_id: A,
      stream: "s",
      deleted: true,
      removal: "deleted",
    });
    expect(typeof owner.data[0].deleted_at).toBe("string");
    expect(typeof owner.data[0].emitted_at).toBe("string");
    // A new owner sync from beginning returns no tombstones at all.
    const fresh = await (
      await get("/streams/s/records?changes_since=beginning", "owner")
    ).json();
    expect(fresh.data.filter((r: { deleted?: boolean }) => r.deleted)).toEqual(
      [],
    );
  });

  it("RS 20: a record leaving the grant's time window yields one exact client tombstone", async () => {
    const { ingest, get } = setup(backend);
    ingest([{ instance: A, id: "w", name: "n", at: "2026-03-01T00:00:00Z" }]);
    const start = await (
      await get("/streams/s/records?changes_since=beginning", "windowed")
    ).json();
    expect(start.data.map((r: { id: string }) => r.id)).toEqual(["w"]);
    ingest([{ instance: A, id: "w", name: "n", at: "2025-03-01T00:00:00Z" }]);
    const next = await (
      await get(
        `/streams/s/records?changes_since=${encodeURIComponent(start.next_changes_since)}`,
        "windowed",
      )
    ).json();
    expect(next.data).toEqual([
      { object: "record", id: "w", instance_id: A, stream: "s", deleted: true },
    ]);
  });

  it("RS 31/32: mixed fields → 403 field_not_granted naming only the ungranted names, identical for a real and an invented name, before any declaration lookup", async () => {
    const { ingest, get, declarations } = setup(backend);
    ingest(seed);
    const lookup = vi.spyOn(declarations, "get");
    const real = await get("/streams/s/records?fields=id,secret,name");
    const invented = await get("/streams/s/records?fields=id,zzzzzz,name");
    expect(lookup).not.toHaveBeenCalled();
    expect(real.status).toBe(403);
    expect(invented.status).toBe(403);
    const a = await real.json();
    const b = await invented.json();
    expect(a.error).toMatchObject({
      type: "permission_error",
      code: "field_not_granted",
      param: "fields",
    });
    expect(a.error.message).toContain("secret");
    expect(a.error.message).not.toMatch(/\bid\b|\bname\b/);
    const strip = (body: { error: Record<string, unknown> }) => ({
      ...body.error,
      request_id: undefined,
      message: String(body.error.message).replace("zzzzzz", "secret"),
    });
    expect(strip(b)).toEqual(strip(a));
    expect(
      [...real.headers.keys()].filter((h) => h !== "request-id").sort(),
    ).toEqual(
      [...invented.headers.keys()].filter((h) => h !== "request-id").sort(),
    );
    // Same rule on a single-record read.
    const one = await get(`/streams/s/records/k1?instance_id=${A}&fields=secret`);
    expect(one.status).toBe(403);
    expect((await one.json()).error.code).toBe("field_not_granted");
    // A granted subset still reads, with the frozen required floor.
    const ok = await (await get("/streams/s/records?fields=name")).json();
    expect(Object.keys(ok.data[0].data).sort()).toEqual(["id", "name"]);
  });

  it("RS 1/2/23: single-record read decodes the path key once and requires instance_id for a multi-instance context", async () => {
    const { ingest, get } = setup(backend);
    ingest([
      { instance: A, id: "100%", name: "pct" },
      { instance: A, id: "a%41", name: "literal" },
      { instance: A, id: "aA", name: "decoded-twice" },
    ]);
    const missing = await get("/streams/s/records/aA");
    expect(missing.status).toBe(400);
    expect((await missing.json()).error).toMatchObject({
      code: "invalid_request",
      param: "instance_id",
    });
    const pct = await get(`/streams/s/records/100%25?instance_id=${A}`);
    expect(pct.status).toBe(200);
    expect((await pct.json()).id).toBe("100%");
    const literal = await (
      await get(`/streams/s/records/a%2541?instance_id=${A}`)
    ).json();
    expect(literal.data.name).toBe("literal");
    expect(literal.instance_id).toBe(A);
    expect(literal.emitted_at).toBeUndefined();
    // Optional when the grant lists one handle.
    expect((await get("/streams/s/records/aA", "single")).status).toBe(200);
    // An instance outside the query context is 404.
    expect(
      (await get("/streams/s/records/aA?instance_id=inst_zz")).status,
    ).toBe(404);
    // Owner context covers two instances too.
    expect((await get("/streams/s/records/aA", "owner")).status).toBe(400);
    const owned = await (
      await get(`/streams/s/records/aA?instance_id=${A}`, "owner")
    ).json();
    expect(owned).toMatchObject({ instance_id: A, id: "aA" });
    expect(typeof owned.emitted_at).toBe("string");
  });

  it("RS 1/23: owner delete takes instance_id and requires it for a multi-instance scope", async () => {
    const { ingest, get, del } = setup(backend);
    ingest([
      { instance: A, id: "same", name: "a" },
      { instance: B, id: "same", name: "b" },
    ]);
    const missing = await del("/streams/s/records/same");
    expect(missing.status).toBe(400);
    expect((await missing.json()).error.param).toBe("instance_id");
    expect((await del(`/streams/s/records/same?instance_id=${B}`)).status).toBe(
      204,
    );
    expect(
      (await get(`/streams/s/records/same?instance_id=${A}`, "owner")).status,
    ).toBe(200);
    expect(
      (await get(`/streams/s/records/same?instance_id=${B}`, "owner")).status,
    ).toBe(404);
    expect(
      (await del("/streams/s/records/same?instance_id=x&extra=1")).status,
    ).toBe(400);
  });

  it("RS 15: client stream metadata is a closed projection of the frozen grant", async () => {
    const { get } = setup(backend);
    const plain = await (await get("/streams/s")).json();
    expect(plain).toEqual({
      object: "stream_metadata",
      name: "s",
      schema: { properties: { id: {}, name: {}, at: {} } },
      query: {},
      views: [],
      relationships: [],
    });
    const sorted = await (await get("/streams/s", "sorted")).json();
    expect(sorted.sort_field).toBe("at");
    expect(sorted.cursor_field).toBeUndefined();
  });

  it("RS 14: owner stream metadata reports the declared cursor_field and real capabilities", async () => {
    const { get } = setup(backend);
    const body = await (await get("/streams/s", "owner")).json();
    expect(body).toMatchObject({
      object: "stream_metadata",
      name: "s",
      primary_key: ["id"],
      cursor_field: "at",
      schema: { properties: { id: {}, name: {}, at: {}, secret: {} } },
      query: {},
      views: [],
      relationships: [],
    });
  });

  it("RS 6: a delete refused by connection state answers the unified error body", async () => {
    const { del } = setup(backend, (store) => ({
      ...store,
      deleteRecord: () => {
        throw new PdppBindingError("connection_deleted");
      },
    }));
    const res = await del(`/streams/s/records/k1?instance_id=${A}`);
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body).toEqual({
      error: {
        type: "invalid_request_error",
        code: "conflict",
        message: "connection_deleted",
        request_id: expect.stringMatching(/^req_/),
      },
    });
  });
});
