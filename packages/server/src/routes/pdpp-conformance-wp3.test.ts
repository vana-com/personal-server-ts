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
import { createReplicaRecordStore } from "../storage/pdpp-replica-canonical-port.js";
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
  refs: {
    active: true,
    tokenKind: "client",
    subjectId: "sub",
    clientId: "c1",
    grant: grant(
      [
        {
          ...twoInstances,
          instance_ids: [A],
          fields: ["id", "name", "target", "media"],
        },
      ],
      "g6",
    ),
  },
};

type Backend = "memory" | "sqlite";

function setup(
  backend: Backend,
  wrap?: (s: PdppRecordStore) => PdppRecordStore,
) {
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
      views: [{ id: "basic", fields: ["id", "name"] }],
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

describe.each<Backend>(["memory", "sqlite"])(
  "RS conformance (%s store)",
  (backend) => {
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
      const opened = Buffer.from(cursor.slice(3), "base64url").toString(
        "latin1",
      );
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
      // Default `order` is descending (spec-core §8 "Stable sort").
      expect(
        pages.flatMap((p) => p.data).map((r) => `${r.instance_id}/${r.id}`),
      ).toEqual(["inst_b/k3", "inst_b/k0", "inst_a/k2", "inst_a/k1"]);
      const ascending = await walk(
        get,
        "/streams/s/records?changes_since=beginning&limit=1&order=asc",
      );
      expect(ascending.records.map((r) => `${r.instance_id}/${r.id}`)).toEqual([
        "inst_a/k1",
        "inst_a/k2",
        "inst_b/k0",
        "inst_b/k3",
      ]);
      const token: string = pages.at(-1).next_changes_since;
      expect(token).toMatch(/^cs_/);
      const next = await (
        await get(
          `/streams/s/records?changes_since=${encodeURIComponent(token)}`,
        )
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
        [
          `/streams/s/records?changes_since=${encodeURIComponent(token)}`,
          "other",
        ],
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
      ingest([
        { instance: A, id: "brief", name: "n", at: "2026-02-01T00:00:00Z" },
      ]);
      expect(
        (await del(`/streams/s/records/brief?instance_id=${A}`)).status,
      ).toBe(204);
      expect((await del(`/streams/s/records/k2?instance_id=${A}`)).status).toBe(
        204,
      );

      const client = await (
        await get(
          `/streams/s/records?changes_since=${encodeURIComponent(clientToken)}`,
        )
      ).json();
      expect(client.data).toEqual([
        {
          object: "record",
          id: "k2",
          instance_id: A,
          stream: "s",
          deleted: true,
        },
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
      expect(
        fresh.data.filter((r: { deleted?: boolean }) => r.deleted),
      ).toEqual([]);
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
        {
          object: "record",
          id: "w",
          instance_id: A,
          stream: "s",
          deleted: true,
        },
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
      const one = await get(
        `/streams/s/records/k1?instance_id=${A}&fields=secret`,
      );
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
      expect(
        (await del(`/streams/s/records/same?instance_id=${B}`)).status,
      ).toBe(204);
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
        views: [{ id: "basic", fields: ["id", "name"] }],
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

    it("RS 23: every resource_ref is served redacted for client and owner, on list, get and changes_since, and the field is kept", async () => {
      const { ingest, get, del } = setup(backend);
      ingest([
        // A target in an ungranted stream, and one in another source.
        {
          instance: A,
          id: "t1",
          name: "n",
          target: { source_id: "src", stream: "other", record_id: "x1" },
        },
        {
          instance: A,
          id: "t2",
          name: "n",
          target: {
            source_id: "elsewhere",
            stream: "s",
            record_id: ["a", "b"],
          },
        },
        // A target inside the grant: still redacted (no resolution here).
        {
          instance: A,
          id: "t3",
          name: "n",
          target: { source_id: "src", stream: "s", record_id: "t1" },
        },
      ]);
      const redacted = (stream: string, source = "src") => ({
        source_id: source,
        stream,
        redacted: true,
      });
      const expected = {
        t1: redacted("other"),
        t2: redacted("s", "elsewhere"),
        t3: redacted("s"),
      };
      for (const token of ["refs", "owner"]) {
        const list = await (await get("/streams/s/records", token)).json();
        for (const record of list.data)
          expect(record.data.target).toEqual(
            expected[record.id as keyof typeof expected],
          );
        const one = await (
          await get(`/streams/s/records/t1?instance_id=${A}`, token)
        ).json();
        expect(one.data.target).toEqual(redacted("other"));
        const sync = await (
          await get("/streams/s/records?changes_since=beginning", token)
        ).json();
        // Assert on the served records only: the body also holds a sealed
        // token, random base64url that can contain any short string.
        for (const record of sync.data)
          expect(JSON.stringify(record.data)).not.toContain("record_id");
      }
      const start = await (
        await get("/streams/s/records?changes_since=beginning", "refs")
      ).json();
      // A target deletion, and a change to the hidden record_id only: neither
      // changes the served form, so neither re-returns the referrer.
      expect((await del(`/streams/s/records/t1?instance_id=${A}`)).status).toBe(
        204,
      );
      ingest([
        {
          instance: A,
          id: "t3",
          name: "n",
          target: { source_id: "src", stream: "s", record_id: "zzz" },
        },
      ]);
      const next = await (
        await get(
          `/streams/s/records?changes_since=${encodeURIComponent(start.next_changes_since)}`,
          "refs",
        )
      ).json();
      expect(next.data).toEqual([
        {
          object: "record",
          id: "t1",
          instance_id: A,
          stream: "s",
          deleted: true,
        },
      ]);
    });

    it("RS 23: references inside arrays and nested objects, and with an invalid record_id, are redacted too", async () => {
      const { ingest, get } = setup(backend);
      const ref = (id: unknown) => ({
        source_id: "src",
        stream: "other",
        record_id: id,
      });
      const redacted = { source_id: "src", stream: "other", redacted: true };
      ingest([
        {
          instance: A,
          id: "deep",
          name: "n",
          target: {
            list: [ref("x1"), { note: "keep", inner: ref(["a", "b"]) }],
            nested: { inner: ref(42) },
            plain: { source_id: "src", stream: "other" },
          },
        },
      ]);
      const start = await (
        await get("/streams/s/records?changes_since=beginning", "refs")
      ).json();
      for (const token of ["refs", "owner"]) {
        for (const path of [
          "/streams/s/records",
          `/streams/s/records/deep?instance_id=${A}`,
          "/streams/s/records?changes_since=beginning",
        ]) {
          const body = await (await get(path, token)).json();
          const record = body.data?.[0] ?? body;
          expect(record.data.target).toEqual({
            list: [redacted, { note: "keep", inner: redacted }],
            nested: { inner: redacted },
            // Not a reference (no record_id): served as stored.
            plain: { source_id: "src", stream: "other" },
          });
          expect(JSON.stringify(record.data)).not.toContain("x1");
        }
      }
      // A change to a nested hidden record_id leaves the served form unchanged,
      // so the referrer is not returned again.
      ingest([
        {
          instance: A,
          id: "deep",
          name: "n",
          target: {
            list: [ref("x2"), { note: "keep", inner: ref(["a", "c"]) }],
            nested: { inner: ref(43) },
            plain: { source_id: "src", stream: "other" },
          },
        },
      ]);
      const next = await (
        await get(
          `/streams/s/records?changes_since=${encodeURIComponent(start.next_changes_since)}`,
          "refs",
        )
      ).json();
      expect(next.data).toEqual([]);
    });

    it("RS 23: a record whose own top-level fields are source_id, stream and record_id is served intact", async () => {
      const { ingest, get } = setup(backend);
      ingest([
        {
          instance: A,
          id: "own",
          name: "n",
          source_id: "src",
          stream: "s",
          record_id: "r1",
        } as never,
      ]);
      const token = "owner";
      for (const path of [
        "/streams/s/records",
        `/streams/s/records/own?instance_id=${A}`,
        "/streams/s/records?changes_since=beginning",
      ]) {
        const body = await (await get(path, token)).json();
        const record = body.data?.[0] ?? body;
        expect(record.data).toEqual({
          id: "own",
          name: "n",
          source_id: "src",
          stream: "s",
          record_id: "r1",
        });
      }
    });

    it("RS 18: a served blob_ref carries a fetch_url with its instance_id", async () => {
      const { ingest, get } = setup(backend);
      ingest([
        {
          instance: A,
          id: "m1",
          name: "n",
          media: { blob_id: "sha256:abc", mime_type: "image/png" },
        },
      ]);
      for (const token of ["refs", "owner"]) {
        const body = await (await get("/streams/s/records", token)).json();
        const media = body.data.find((r: { id: string }) => r.id === "m1").data
          .media;
        expect(media).toMatchObject({
          blob_id: "sha256:abc",
          mime_type: "image/png",
        });
        expect(media.fetch_url).toBe(
          `http://localhost/v1/blobs/${encodeURIComponent("sha256:abc")}?instance_id=${A}`,
        );
      }
    });

    it("RS 1 (§8 Stable sort): owner lists use the current cursor_field, then (instance_id, key), invalid values last", async () => {
      const { ingest, get } = setup(backend);
      ingest(seed);
      const desc = await walk(get, "/streams/s/records?limit=1", "owner");
      expect(desc.records.map((r) => r.id)).toEqual(["k1", "k3", "k2", "k0"]);
      const asc = await walk(
        get,
        "/streams/s/records?limit=1&order=asc",
        "owner",
      );
      expect(asc.records.map((r) => r.id)).toEqual(["k2", "k3", "k1", "k0"]);
    });

    it("RS 14: owner metadata reports the declared views, and owner reads accept view; clients cannot", async () => {
      const { ingest, get } = setup(backend);
      ingest(seed);
      const meta = await (await get("/streams/s", "owner")).json();
      expect(meta.views).toEqual([{ id: "basic", fields: ["id", "name"] }]);
      const viewed = await (
        await get("/streams/s/records?view=basic", "owner")
      ).json();
      for (const record of viewed.data)
        expect(Object.keys(record.data).sort()).toEqual(["id", "name"]);
      for (const [path, token] of [
        ["/streams/s/records?view=basic", "client"],
        ["/streams/s/records?view=nope", "owner"],
        ["/streams/s/records?view=basic&fields=id", "owner"],
      ] as const) {
        const res = await get(path, token);
        expect(res.status).toBe(400);
        expect((await res.json()).error.code).toBe("invalid_request");
      }
    });

    it("RS 10: an empty fields name is 400 invalid_request, not field_not_granted", async () => {
      const { get } = setup(backend);
      for (const query of ["fields=", "fields=id,,name"]) {
        const res = await get(`/streams/s/records?${query}`);
        expect(res.status).toBe(400);
        expect((await res.json()).error).toMatchObject({
          code: "invalid_request",
          param: "fields",
        });
      }
    });
  },
);

describe("RS 6: owner DELETE refusals by account mode use the unified §8 body", () => {
  it.each([
    ["switched", 426, "update_required", "invalid_request_error"],
    ["unknown", 503, "ACCOUNT_MODE_UNKNOWN", "api_error"],
  ] as const)("%s account", async (mode, status, code, type) => {
    const app = new Hono();
    app.route(
      "/v1",
      pdppRecordsRoutes({
        accountStorageMode: { owner: "owner", read: () => mode },
        store: createMemoryRecordStore(),
        auth: createFixtureAuthorizationService(tokens),
        declarations: createStreamDeclarationRegistry([
          {
            name: "s",
            semantics: "mutable_state",
            primaryKey: ["id"],
            requiredFields: ["id"],
          },
        ]),
        instancesForSubject: () => [A],
      }),
    );
    const res = await app.request(`/v1/streams/s/records/k1?instance_id=${A}`, {
      method: "DELETE",
      headers: { Authorization: "Bearer owner" },
    });
    expect(res.status).toBe(status);
    const body = await res.json();
    expect(body).toEqual({
      error: {
        type,
        code,
        message: expect.any(String),
        request_id: expect.stringMatching(/^req_/),
      },
    });
    expect(res.headers.get("Request-Id")).toBe(body.error.request_id);
  });
});

describe.each<Backend>(["memory", "sqlite"])(
  "RS 1: owner DELETE on an append_only stream (%s store)",
  (backend) => {
    // spec-core §4 "Stream semantics", `append_only`: "Explicit deletion is
    // permitted." §8 "Delete a record" makes no exception.
    it("removes the record and emits an owner tombstone with removal=deleted", async () => {
      const store =
        backend === "memory"
          ? createMemoryRecordStore()
          : createTestBoundRecordStore(new Database(":memory:"));
      store.ingestBatch(
        [
          {
            instance: A,
            stream: "log",
            key: "e1",
            data: { id: "e1" },
            emitted_at: "2026-05-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      const app = new Hono();
      app.route(
        "/v1",
        pdppRecordsRoutes({
          accountStorageMode: explicitLegacyStorageMode("unswitched"),
          store,
          auth: createFixtureAuthorizationService({
            owner: {
              active: true,
              tokenKind: "owner",
              subjectId: "owner",
              instanceIds: [A],
            },
          }),
          declarations: createStreamDeclarationRegistry([
            {
              name: "log",
              semantics: "append_only",
              primaryKey: ["id"],
              requiredFields: ["id"],
            },
          ]),
          instancesForSubject: () => [A],
        }),
      );
      const call = (path: string, method = "GET") =>
        app.request(`/v1${path}`, {
          method,
          headers: { Authorization: "Bearer owner" },
        });
      const start = await (
        await call("/streams/log/records?changes_since=beginning")
      ).json();
      expect((await call("/streams/log/records/e1", "DELETE")).status).toBe(
        204,
      );
      expect((await call("/streams/log/records/e1")).status).toBe(404);
      const next = await (
        await call(
          `/streams/log/records?changes_since=${encodeURIComponent(start.next_changes_since)}`,
        )
      ).json();
      expect(next.data).toEqual([
        expect.objectContaining({
          id: "e1",
          instance_id: A,
          deleted: true,
          removal: "deleted",
          deleted_at: expect.any(String),
          emitted_at: expect.any(String),
        }),
      ]);
    });
  },
);

describe("RS 1/6: append_only delete while replication is enabled", () => {
  // §4 permits the delete; replication cannot carry it yet (merge-plan.ts
  // `append_only_delete`), so a replicating server refuses it with the
  // unified §8 body. The default configuration (replication off) deletes.
  it("answers 409 append_only_delete_unsupported and keeps the record", async () => {
    const db = new Database(":memory:");
    const store = createReplicaRecordStore(db);
    store.registerConnection({
      instance: A,
      sourceId: "src",
      method: "m",
      label: "A",
    });
    store.ingestBatch(
      [
        {
          instance: A,
          stream: "log",
          key: "e1",
          data: { id: "e1" },
          emitted_at: "2026-05-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
      { method: "m", generation: 1 },
    );
    const app = new Hono();
    app.route(
      "/v1",
      pdppRecordsRoutes({
        accountStorageMode: explicitLegacyStorageMode("unswitched"),
        store,
        auth: createFixtureAuthorizationService({
          owner: {
            active: true,
            tokenKind: "owner",
            subjectId: "owner",
            instanceIds: [A],
          },
        }),
        declarations: createStreamDeclarationRegistry([
          {
            name: "log",
            semantics: "append_only",
            primaryKey: ["id"],
            requiredFields: ["id"],
          },
        ]),
        instancesForSubject: () => [A],
      }),
    );
    const res = await app.request("/v1/streams/log/records/e1", {
      method: "DELETE",
      headers: { Authorization: "Bearer owner" },
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toEqual({
      error: {
        type: "invalid_request_error",
        code: "append_only_delete_unsupported",
        message: expect.any(String),
        request_id: expect.stringMatching(/^req_/),
      },
    });
    expect(store.getRecord(A, "log", "e1")).toBeDefined();
    store.close();
  });
});

describe.each<Backend>(["memory", "sqlite"])(
  "RS 7/20: append_only delete, then the connector re-emits the key (%s store)",
  (backend) => {
    it("serves the re-emitted record as a new record to owner and client sync", async () => {
      const store =
        backend === "memory"
          ? createMemoryRecordStore()
          : createTestBoundRecordStore(new Database(":memory:"));
      const emit = (name: string, at: string) =>
        store.ingestBatch(
          [
            {
              instance: A,
              stream: "log",
              key: "e1",
              data: { id: "e1", name },
              emitted_at: at,
            },
          ],
          () => "append_only",
          () => ["id"],
        );
      emit("first", "2026-05-01T00:00:00.000Z");
      const app = new Hono();
      app.route(
        "/v1",
        pdppRecordsRoutes({
          accountStorageMode: explicitLegacyStorageMode("unswitched"),
          store,
          auth: createFixtureAuthorizationService({
            owner: {
              active: true,
              tokenKind: "owner",
              subjectId: "owner",
              instanceIds: [A],
            },
            client: {
              active: true,
              tokenKind: "client",
              subjectId: "sub",
              clientId: "c1",
              grant: grant([
                {
                  name: "log",
                  instance_ids: [A],
                  fields: ["id", "name"],
                  required_fields: ["id"],
                },
              ]),
            },
          }),
          declarations: createStreamDeclarationRegistry([
            {
              name: "log",
              semantics: "append_only",
              primaryKey: ["id"],
              requiredFields: ["id"],
            },
          ]),
          instancesForSubject: () => [A],
        }),
      );
      const call = (path: string, token = "owner", method = "GET") =>
        app.request(`/v1${path}`, {
          method,
          headers: { Authorization: `Bearer ${token}` },
        });
      const starts = {
        owner: (
          await (
            await call("/streams/log/records?changes_since=beginning")
          ).json()
        ).next_changes_since,
        client: (
          await (
            await call("/streams/log/records?changes_since=beginning", "client")
          ).json()
        ).next_changes_since,
      };
      expect(
        (await call("/streams/log/records/e1", "owner", "DELETE")).status,
      ).toBe(204);
      // The re-emitted key is not a duplicate any more: it is a new insert.
      expect(
        emit("second", "2026-05-03T00:00:00.000Z").results[0]?.outcome,
      ).toBe("accepted");
      const one = await (await call("/streams/log/records/e1")).json();
      expect(one.data).toEqual({ id: "e1", name: "second" });
      expect(one.emitted_at).toBe("2026-05-03T00:00:00.000Z");
      // Visible at both horizons with a new projection: the record, no tombstone.
      for (const token of ["owner", "client"] as const) {
        const next = await (
          await call(
            `/streams/log/records?changes_since=${encodeURIComponent(starts[token])}`,
            token,
          )
        ).json();
        expect(next.data).toEqual([
          expect.objectContaining({
            id: "e1",
            instance_id: A,
            data: { id: "e1", name: "second" },
          }),
        ]);
        expect(next.data[0].deleted).toBeUndefined();
      }
    });
  },
);
