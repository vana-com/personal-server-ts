import Database from "better-sqlite3";
import {
  createRecordQuery,
  openLocalDb,
  type SqlDriver,
  type SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { describe, it, expect, vi } from "vitest";
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
  MAX_BLOB_UPLOAD_BYTES,
  MAX_INGEST_BODY_BYTES,
  pdppRecordsRoutes,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";

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

describe("PS-2 D.8 local record routes", () => {
  it("reads keys and stamps through RecordQuery, expires old changes, and refuses switched writes", async () => {
    const db = new Database(":memory:");
    try {
      const driver: SqlDriver = {
        info: { sqliteVersion: "3.22.0", host: "node", persistent: false },
        async query<R extends Record<string, SqlValue>>(
          sql: string,
          params: readonly SqlValue[] = [],
        ) {
          const stmt = db.prepare(sql);
          if (stmt.reader) return stmt.all(...params) as R[];
          stmt.run(...params);
          return [];
        },
        async batch(statements) {
          return db.transaction(() => ({
            changes: statements.map(({ sql, params = [] }) => {
              const stmt = db.prepare(sql);
              return stmt.reader
                ? (stmt.all(...params), 0)
                : stmt.run(...params).changes;
            }),
          }))();
        },
        async close() {
          db.close();
        },
      };
      await openLocalDb(driver, {
        owner: "0xowner",
        network: "test",
        deviceId: "record-route",
      });
      const stamp = Date.parse("2026-09-02T00:00:00Z");
      const insert = db.prepare(
        "INSERT INTO records(connection_id,stream,record_key,pk_hash,body,stamp_o,stamp_r,body_sha256) VALUES (?, 'playlists', ?, ?, ?, ?, 'fixture', 'fixture')",
      );
      for (const [key, time] of [
        ["b", stamp],
        ["a", stamp + 1000],
        ["c", stamp - 1000],
      ] as const) {
        insert.run(
          "inst_1",
          key,
          key,
          JSON.stringify({ id: key, name: key, private_field: "hidden" }),
          time,
        );
      }
      const recordQuery = createRecordQuery(driver);
      const listRecords = vi.spyOn(recordQuery, "listRecords");
      const getRecord = vi.spyOn(recordQuery, "getRecord");
      const changesSince = vi.spyOn(recordQuery, "changesSince");
      const store = createMemoryRecordStore();
      const legacy = [
        "listRecords",
        "getRecord",
        "changesSince",
        "ingestBatch",
      ] as const;
      const legacyCalls = legacy.map((name) => vi.spyOn(store, name));
      const replaceStream = vi.fn();
      let mode: "switched" | "unswitched" | "unknown" = "switched";
      const readMode = vi.fn(() => mode);
      const deps: Partial<PdppRecordsRouteDeps> = {
        store,
        recordQuery,
        accountStorageMode: { owner: "sub_1", read: readMode },
        bindingStore: {
          getInstanceBinding: () => ({ sourceId: "src_1", deletedAt: null }),
          storeBlobBytesForInstance: vi.fn(),
          replaceStream,
        },
      };
      const tokens: Record<string, PdppTokenContext> = {
        owner: {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
        client: {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      };
      const { app } = buildApp(tokens, deps);
      const headers = { Authorization: "Bearer owner" };
      const path = "/streams/playlists/records";

      const first = await app.request(path + "?limit=2", { headers });
      expect(first.status).toBe(200);
      const firstBody = await first.json();
      expect(firstBody.data.map((row: { id: string }) => row.id)).toEqual([
        "a",
        "b",
      ]);
      expect(
        firstBody.data.map((row: { emitted_at: string }) => row.emitted_at),
      ).toEqual([
        new Date(stamp + 1000).toISOString(),
        new Date(stamp).toISOString(),
      ]);
      expect(firstBody.next_cursor).toBe("b");
      expect(firstBody.has_more).toBe(true);
      expect(listRecords).toHaveBeenCalledWith({
        connectionId: "inst_1",
        stream: "playlists",
        cursor: undefined,
        limit: 2,
      });
      expect(readMode).toHaveBeenCalledTimes(1);
      const second = await app.request(path + "?limit=2&cursor=b", { headers });
      expect(
        (await second.json()).data.map((row: { id: string }) => row.id),
      ).toEqual(["c"]);

      const single = await app.request(path + "/a", { headers });
      expect(single.status).toBe(200);
      expect((await single.json()).emitted_at).toBe(
        new Date(stamp + 1000).toISOString(),
      );
      expect(getRecord).toHaveBeenCalledWith({
        connectionId: "inst_1",
        stream: "playlists",
        recordKey: "a",
      });
      expect((await app.request(path + "/missing", { headers })).status).toBe(
        404,
      );

      const changed = await app.request(path + "?changes_since=0&limit=2", {
        headers,
      });
      const changeBody = await changed.json();
      expect(changed.status).toBe(200);
      expect(changeBody.data.map((row: { id: string }) => row.id)).toEqual([
        "b",
        "a",
      ]);
      expect(changeBody.data[1].emitted_at).toBe(
        new Date(stamp + 1000).toISOString(),
      );
      expect(changeBody.next_cursor).toBe("2");
      expect(changeBody.next_changes_since).toBe("2");
      expect(changesSince).toHaveBeenCalledWith({
        connectionId: "inst_1",
        stream: "playlists",
        cursor: 0,
        limit: 2,
      });
      const rest = await app.request(path + "?changes_since=0&cursor=2", {
        headers,
      });
      expect(
        (await rest.json()).data.map((row: { id: string }) => row.id),
      ).toEqual(["c"]);
      db.prepare(
        "INSERT INTO record_changes(connection_id, stream, record_key, pk_hash, op, stamp_o, stamp_r, origin) VALUES ('inst_1', 'playlists', 'removed', 'removed', 'remove', 0, 'fixture', 'local')",
      ).run();
      const removal = await app.request(path + "?changes_since=3", { headers });
      const removed = (await removal.json()).data[0];
      expect(removed.id).toBe("removed");
      expect(removed.deleted).toBe(true);
      expect(removed.emitted_at).toBeNull();
      for (const cursor of ["", "-1", "1x", "9007199254740992"]) {
        const invalid = await app.request(path + "?changes_since=" + cursor, {
          headers,
        });
        expect(invalid.status).toBe(400);
        expect((await invalid.json()).error.code).toBe("invalid_cursor");
      }
      db.prepare("DELETE FROM record_changes WHERE seq <= 2").run();
      const expired = await app.request(path + "?changes_since=0", { headers });
      expect(expired.status).toBe(410);
      expect((await expired.json()).error.code).toBe("cursor_expired");

      // Both routes refuse before parsing an invalid body or consulting storage.
      for (const route of ["ingest", "replace"]) {
        for (const header of [undefined, "1"]) {
          const refused = await app.request(path + "/" + route, {
            method: "POST",
            headers: {
              ...headers,
              ...(header && { "vana-stream-sync-client": header }),
            },
            body: "not json",
          });
          expect(refused.status).toBe(426);
          expect((await refused.json()).errorCode).toBe("update_required");
          expect(refused.headers.get("Request-Id")).toMatch(/^req_/);
        }
      }
      for (const call of legacyCalls) expect(call).not.toHaveBeenCalled();
      expect(replaceStream).not.toHaveBeenCalled();

      const clientHeaders = { Authorization: "Bearer client" };
      // Grant listing now needs the same frozen-snapshot port production supplies.
      // The base app deliberately omits it to keep testing unavailable history below.
      const clientListing = buildApp(tokens, {
        ...deps,
        recordHistory: async () => ({
          data: [
            {
              instance: "inst_1",
              stream: "playlists",
              recordKey: "a",
              data: { id: "a", name: "a", private_field: "hidden" },
              version: 1,
              emittedAt: new Date(stamp + 1000).toISOString(),
              deleted: false,
            },
          ],
          hasMore: false,
        }),
      }).app;
      const client = await clientListing.request(path, {
        headers: clientHeaders,
      });
      expect(client.status).toBe(200);
      expect(Object.keys((await client.json()).data[0].data).sort()).toEqual([
        "id",
        "name",
      ]);
      const clientSingle = await app.request(path + "/a?fields=id", {
        headers: clientHeaders,
      });
      expect(Object.keys((await clientSingle.json()).data)).toEqual(["id"]);
      const clientChanges = await app.request(path + "?changes_since=2", {
        headers: clientHeaders,
      });
      expect(clientChanges.status).toBe(503);

      // Identical keys in distinct connections survive a one-row page boundary.
      insert.run(
        "inst_2",
        "a",
        "a",
        JSON.stringify({ id: "a", name: "other" }),
        stamp,
      );
      const multi = buildApp(
        {
          owner: { ...tokens.owner, instanceIds: ["inst_1", "inst_2"] },
        },
        { ...deps, instancesForSubject: () => ["inst_1", "inst_2"] },
      ).app;
      const multiFirst = await multi.request(path + "?limit=1", { headers });
      const multiBody = await multiFirst.json();
      expect(multiBody.data[0].id).toBe("a");
      const multiNext = await multi.request(
        path + "?limit=1&cursor=" + encodeURIComponent(multiBody.next_cursor),
        { headers },
      );
      expect((await multiNext.json()).data[0].id).toBe("a");

      // Presence of a query is not the account mode; neither legacy state uses it.
      for (const state of ["unknown", "unswitched"] as const) {
        mode = state;
        listRecords.mockClear();
        const legacyRead = await app.request(path, { headers });
        expect(legacyRead.status).toBe(state === "unknown" ? 503 : 200);
        expect(listRecords).not.toHaveBeenCalled();
      }
      mode = "unknown";
      const paused = await app.request(path + "/ingest", {
        method: "POST",
        headers,
        body: "not json",
      });
      expect(paused.status).toBe(503);
      mode = "switched";
      const missingQuery = buildApp(tokens, {
        ...deps,
        recordQuery: undefined,
      }).app;
      const missing = await missingQuery.request(path, { headers });
      expect(missing.status).toBe(503);
    } finally {
      db.close();
    }
  });
});

describe("grant-safe database change history", () => {
  it("passes authorized fields and both-horizon visibility to the history port and only projects the response", async () => {
    const history = vi.fn(
      async (
        _stream: string,
        options: Parameters<
          NonNullable<PdppRecordsRouteDeps["recordHistory"]>
        >[1],
      ) => {
        expect(options.instanceIds).toEqual(["inst_1"]);
        expect(options.fields).toEqual(["id", "name"]);
        const row = {
          instance: "inst_1",
          stream: "playlists",
          recordKey: "allowed",
          data: {
            id: "allowed",
            name: "safe",
            captured_at: "2026-02-01T00:00:00Z",
            private_field: "hidden",
          },
          version: 1,
          emittedAt: "2026-02-01T00:00:00Z",
          deleted: false as const,
        };
        expect(options.isVisible?.(row)).toBe(true);
        expect(
          options.isVisible?.({
            ...row,
            data: { ...row.data, captured_at: "2025-02-01T00:00:00Z" },
          }),
        ).toBe(false);
        return {
          data: [row],
          hasMore: false,
          nextChangesSince: "opaque-history-horizon",
        };
      },
    );
    const grant = clientGrant({
      time_constraint: { field: "captured_at", since: "2026-01-01T00:00:00Z" },
    });
    const query = {
      listRecords: vi.fn(),
      getRecord: vi.fn(),
      changesSince: vi.fn(),
      streamRecords: vi.fn(),
    } as never;
    const store = createMemoryRecordStore();
    const legacy = vi.spyOn(store, "changesSince");
    const { app } = buildApp(
      {
        client: {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant,
        },
      },
      {
        store,
        recordQuery: query,
        recordHistory: history,
        accountStorageMode: { owner: "sub_1", read: () => "switched" },
      },
    );
    const response = await app.request(
      "/streams/playlists/records?changes_since=opaque-prior-horizon",
      { headers: { Authorization: "Bearer client" } },
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.data[0].data).toEqual({ id: "allowed", name: "safe" });
    expect(body.next_changes_since).toBe("opaque-history-horizon");
    expect(history).toHaveBeenCalledTimes(1);
    expect(legacy).not.toHaveBeenCalled();
  });
});

describe("pdpp records route body caps", () => {
  it("sets record and blob ingest request caps to 512 MiB", () => {
    expect(MAX_INGEST_BODY_BYTES).toBe(536870912);
    expect(MAX_BLOB_UPLOAD_BYTES).toBe(536870912);
  });
});

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
      ownerSubjectId: "sub_1",
      accountStorageMode: { owner: "sub_1", read: () => "unswitched" },
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
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
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

describe("pdpp records routes: caching", () => {
  it("marks every response private and no-store, including errors", async () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "personal" },
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
    const authorized = { headers: { Authorization: "Bearer client-tok" } };
    const responses = [
      await app.request("/streams/playlists/records", authorized),
      await app.request("/streams/playlists/records/pl_1", authorized),
      await app.request("/streams/playlists/records"),
    ];
    expect(responses.map((res) => res.status)).toEqual([200, 200, 401]);
    for (const res of responses)
      expect(res.headers.get("Cache-Control")).toBe("private, no-store");
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
          instanceIds: ["inst_1"],
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
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
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
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
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
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
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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

  it("uses the owner token's persisted instance scope for records and stream listings", async () => {
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
      {
        store,
        instancesForSubject: () => ["inst_1", "inst_other"],
      },
    );

    const records = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(records.status).toBe(200);
    const recordsBody = await records.json();
    expect(recordsBody.data.map((r: { id: string }) => r.id)).toEqual([
      "pl_mine",
    ]);

    const streams = await app.request("/streams", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(streams.status).toBe(200);
    const streamsBody = await streams.json();
    expect(streamsBody.data).toEqual([
      expect.objectContaining({ name: "playlists", record_count: 1 }),
    ]);

    const record = await app.request("/streams/playlists/records/pl_not_mine", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(record.status).toBe(404);
  });

  it("denies a scoped owner token after current ownership no longer includes its instance", async () => {
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
          instanceIds: ["inst_1"],
        },
      },
      {
        store,
        instancesForSubject: () => ["inst_other"],
      },
    );

    const records = await app.request("/streams/playlists/records", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(records.status).toBe(403);
    expect((await records.json()).error.code).toBe("grant_stream_not_allowed");
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      },
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

describe("pdpp records routes: record ingest ownership", () => {
  const envelope = {
    instance: "inst_1",
    key: "pl_1",
    data: { id: "pl_1" },
    emitted_at: "2026-04-01T00:00:00.000Z",
  };

  it("accepts an envelope for the token subject's owned instance", async () => {
    const { app, store } = buildApp({
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
    });
    const res = await app.request("/streams/playlists/records/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(envelope),
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      accepted: 1,
      unchanged: 0,
      rejected: [],
      results: [{ index: 0, outcome: "accepted" }],
    });
    expect(store.getRecord("inst_1", "playlists", "pl_1")?.data).toEqual({
      id: "pl_1",
    });
  });

  it.each(["memory", "sqlite"] as const)(
    "preserves top-level and nested __proto__ data on %s ingest",
    async (backend) => {
      const store =
        backend === "memory"
          ? createMemoryRecordStore()
          : createTestBoundRecordStore(new Database(":memory:"));
      const sqliteBinding = backend === "sqlite";
      const { app } = buildApp(
        {
          "owner-tok": {
            active: true,
            tokenKind: "owner",
            subjectId: "sub_1",
            instanceIds: ["inst_1"],
          },
        },
        {
          store,
          ...(sqliteBinding && {
            bindingStore: store,
            configuredMethods: new Map([["inst_1", ["test_method"]]]),
          }),
        },
      );
      try {
        const res = await app.request(
          `/streams/playlists/records/ingest${sqliteBinding ? "?method=test_method&binding_generation=1" : ""}`,
          {
            method: "POST",
            headers: {
              Authorization: "Bearer owner-tok",
              "Content-Type": "application/json",
            },
            body: '{"instance":"inst_1","key":"proto_1","data":{"id":"proto_1","__proto__":{"top":"kept"},"nested":{"__proto__":{"deep":"kept"}}},"emitted_at":"2026-04-01T00:00:00.000Z"}',
          },
        );

        expect(res.status).toBe(200);
        expect(await res.json()).toMatchObject({ accepted: 1, rejected: [] });
        const data = store.getRecord("inst_1", "playlists", "proto_1")?.data;
        expect(data && Object.hasOwn(data, "__proto__")).toBe(true);
        expect(data && Object.hasOwn(data.nested, "__proto__")).toBe(true);
        expect(data?.["__proto__"]).toEqual({ top: "kept" });
        expect(data?.nested["__proto__"]).toEqual({ deep: "kept" });
      } finally {
        store.close();
      }
    },
  );

  it.each([
    ["another subject", "sub_other", "inst_1"],
    ["an unowned instance", "sub_1", "inst_other"],
  ])("rejects %s before writing", async (_case, subjectId, instance) => {
    const { app, store } = buildApp({
      "owner-tok": { active: true, tokenKind: "owner", subjectId },
    });
    const res = await app.request("/streams/playlists/records/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ...envelope, instance }),
    });

    expect(res.status).toBe(401);
    expect(store.getRecord(instance, "playlists", "pl_1")).toBeUndefined();
  });

  it("rejects a mixed batch without writing the owned envelope", async () => {
    const { app, store } = buildApp({
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
    });
    const res = await app.request("/streams/playlists/records/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "application/json",
      },
      body: JSON.stringify([envelope, { ...envelope, instance: "inst_other" }]),
    });

    expect(res.status).toBe(401);
    expect(store.getRecord("inst_1", "playlists", "pl_1")).toBeUndefined();
    expect(store.getRecord("inst_other", "playlists", "pl_1")).toBeUndefined();
  });
});

describe("pdpp records routes: blob ingest", () => {
  it("rejects a chunked body above the byte cap without storing it", async () => {
    const { app, store } = buildApp({
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
    });
    const storeBlobBytes = vi.spyOn(store, "storeBlobBytes");
    const chunk = new Uint8Array(1024 * 1024);
    let chunksRead = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        chunksRead += 1;
        controller.enqueue(chunk);
      },
      cancel() {
        // A stalled source must not hold the size-limit response open.
        return new Promise<void>(() => undefined);
      },
    });

    const res = await app.request("/blobs/ingest", {
      method: "POST",
      duplex: "half",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "application/octet-stream",
      },
      body,
    });

    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("invalid_request");
    expect(storeBlobBytes).not.toHaveBeenCalled();
    expect(chunksRead).toBeGreaterThan(
      MAX_BLOB_UPLOAD_BYTES / chunk.byteLength,
    );
  });

  it("rejects a malformed media type before persisting bytes", async () => {
    const { app, store } = buildApp({
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
    });
    const storeBlobBytes = vi.spyOn(store, "storeBlobBytes");
    const res = await app.request("/blobs/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "not a media type",
      },
      body: new Uint8Array([1, 2, 3]),
    });

    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe("invalid_request");
    expect(storeBlobBytes).not.toHaveBeenCalled();
  });

  it("rejects an owner token for a different subject", async () => {
    const { app } = buildApp(
      {
        "foreign-owner": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_foreign",
        },
      },
      {
        instancesForSubject: () => ["inst_foreign"],
      },
    );
    const res = await app.request("/blobs/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer foreign-owner",
        "Content-Type": "application/octet-stream",
      },
      body: new Uint8Array([1, 2, 3]),
    });

    expect(res.status).toBe(401);
    expect((await res.json()).error.code).toBe("authentication_error");
  });

  it("stores owner-uploaded blob bytes and returns the blob_id a record can reference", async () => {
    const { app, store } = buildApp({
      "owner-tok": {
        active: true,
        tokenKind: "owner",
        subjectId: "sub_1",
        instanceIds: ["inst_1"],
      },
    });

    const bytes = new Uint8Array([1, 2, 3, 4, 5]);
    const res = await app.request("/blobs/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-tok",
        "Content-Type": "image/jpeg",
      },
      body: bytes,
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(typeof body.blob_id).toBe("string");
    expect(body.mime_type).toBe("image/jpeg");
    expect(body.size_bytes).toBe(5);

    // The point of the route: the bytes are retrievable afterwards, so a
    // record referencing this blob_id has something for GET /blobs/:id to
    // serve. A route that minted an id without persisting bytes would satisfy
    // the response assertions above and still be useless.
    expect(store.getBlobBytes(body.blob_id)).toEqual(bytes);
    expect(store.getBlobMeta(body.blob_id)?.mimeType).toBe("image/jpeg");
  });

  it("refuses a client token: ingest is the owner's lane", async () => {
    const { app } = buildApp({
      "client-tok": {
        active: true,
        tokenKind: "client",
        subjectId: "sub_1",
        grant: clientGrant(),
      },
    });

    const res = await app.request("/blobs/ingest", {
      method: "POST",
      headers: {
        Authorization: "Bearer client-tok",
        "Content-Type": "image/jpeg",
      },
      body: new Uint8Array([1, 2, 3]),
    });

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe("authentication_error");
  });
});

describe("pdpp records routes: snapshot replace", () => {
  it("refuses a client token for the owner subject with 401 and changes no rows", async () => {
    const db = new Database(":memory:");
    const store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "inst_1",
      sourceId: "https://test.invalid/connector",
      method: "m1",
      label: "Test account",
    });
    const { app } = buildApp(
      {
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      },
      {
        store,
        bindingStore: store,
        configuredMethods: new Map([["inst_1", ["m1"]]]),
      },
    );
    const replace = (token: string, records: unknown[]) =>
      app.request(
        "/streams/playlists/records/replace?method=m1&binding_generation=1",
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            instance: "inst_1",
            emitted_at: "2026-09-02T00:00:00Z",
            records,
          }),
        },
      );
    const seeded = await replace("owner-tok", [
      {
        key: "p1",
        data: { id: "p1", name: "a" },
        emitted_at: "2026-09-01T00:00:00Z",
      },
    ]);
    expect(seeded.status).toBe(200);
    const rows = () =>
      db
        .prepare(
          "SELECT instance, stream, record_key, version, deleted FROM pdpp_records ORDER BY record_key",
        )
        .all();
    const before = rows();
    expect(before).toEqual([
      {
        instance: "inst_1",
        stream: "playlists",
        record_key: "p1",
        version: 1,
        deleted: 0,
      },
    ]);

    const refused = await replace("client-tok", []);
    expect(refused.status).toBe(401);
    expect(rows()).toEqual(before);
    db.close();
  });
});

describe("strict record queries", () => {
  it.each(["", "1junk", "1.5", "1e2", " 1", "9007199254740992"])(
    "rejects malformed limit %j on list and sync",
    async (limit) => {
      const { app } = buildApp({
        owner: {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      });
      for (const suffix of ["", "&changes_since="]) {
        const res = await app.request(
          `/streams/playlists/records?limit=${encodeURIComponent(limit)}${suffix}`,
          { headers: { Authorization: "Bearer owner" } },
        );
        expect(res.status).toBe(400);
        expect((await res.json()).error.param).toBe("limit");
      }
    },
  );
});
