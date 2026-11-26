import { createHash } from "node:crypto";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { LocalSync } from "@opendatalabs/personal-server-ts-core/localdb";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import { pdppBlobsRoutes } from "../routes/pdpp-blobs.js";
import { grantBlobStore } from "./grant-blobs.js";
import { afterEach, describe, expect, it } from "vitest";
import { listPdppRecords } from "@opendatalabs/personal-server-ts-core/api";
import type { StreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/stream-declaration";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createLinkedRecordQuery,
  createGrantHistory,
  openLocalDb,
  type SqlDriver,
  type SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const opened: SqlDriver[] = [];
const run = (db: SqlDriver, sql: string, params: (string | number)[] = []) =>
  db.batch([{ sql, params }]);
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
});
async function fixture() {
  const db = openBetterSqlite3(":memory:");
  opened.push(db);
  await openLocalDb(db, {
    owner: "0xabc",
    network: "moksha",
    deviceId: "test",
  });
  const id = controlScope("fixture", "");
  await run(
    db,
    "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?, 'fixture', '', 1, 'active', 1)",
    [id],
  );
  for (const [stream, key] of [
    ["selected", "allowed"],
    ["private", "secret"],
  ]) {
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run','{}','hash')",
      [id, stream!, key!, key!],
    );
  }
  const deleted = new Set<string>();
  const query = createLinkedRecordQuery(db, (instance, stream) =>
    !deleted.has(instance) &&
    ["handle-a", "handle-b"].includes(instance) &&
    stream === "selected"
      ? { connector: "fixture", namespace: "" }
      : null,
  );
  return { db, id, deleted, query };
}
describe("host-authorized connection links", () => {
  it("two handles of one source read the same selected stream", async () => {
    const { query } = await fixture();
    const a = await query.listRecords({
      connectionId: "handle-a",
      stream: "selected",
    });
    expect(a.records.map((r) => r.recordKey)).toEqual(["allowed"]);
    expect(
      await query.listRecords({ connectionId: "handle-b", stream: "selected" }),
    ).toEqual(a);
  });
  it("does not read outside the link's stream selection", async () => {
    const { query } = await fixture();
    expect(
      (await query.listRecords({ connectionId: "handle-a", stream: "private" }))
        .records,
    ).toEqual([]);
    expect(
      await query.getRecord({
        connectionId: "handle-a",
        stream: "private",
        recordKey: "secret",
      }),
    ).toBeNull();
  });
  it("deleted binding stays unreadable even after sync reconnect", async () => {
    const { query, deleted, db, id } = await fixture();
    deleted.add("handle-a");
    await run(db, "UPDATE connections SET generation=3 WHERE connection_id=?", [
      id,
    ]);
    expect(
      (
        await query.listRecords({
          connectionId: "handle-a",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
    expect(
      (
        await query.listRecords({
          connectionId: "handle-b",
          stream: "selected",
        })
      ).records,
    ).toHaveLength(1);
  });
  it("unresolvable namespaces read nothing", async () => {
    const { query } = await fixture();
    expect(
      (
        await query.listRecords({
          connectionId: "unresolved",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
    expect(
      await query.changesSince({
        connectionId: "unresolved",
        stream: "selected",
        cursor: 0,
      }),
    ).toBe("gone");
  });
  it("a deleted sync connection reads nothing", async () => {
    const { db, id, query } = await fixture();
    await run(
      db,
      "UPDATE connections SET control_state='deleted' WHERE connection_id=?",
      [id],
    );
    expect(
      (
        await query.listRecords({
          connectionId: "handle-a",
          stream: "selected",
        })
      ).records,
    ).toEqual([]);
  });
});

describe("database grant change horizons", () => {
  const history = (db: SqlDriver) =>
    createGrantHistory(db, (instance, stream) =>
      instance === "handle-a" && stream === "selected"
        ? { connector: "fixture", namespace: "" }
        : null,
    );
  const opts = { instanceIds: ["handle-a"], limit: 1 };
  it("filters initial rows and binds checkpoints to fields and connections", async () => {
    const { db } = await fixture();
    const read = history(db);
    const page = await read("selected", {
      ...opts,
      fields: ["id"],
      isVisible: () => false,
    });
    expect(page.data).toEqual([]);
    expect(page.nextChangesSince).toBeDefined();
    await expect(
      read("selected", {
        ...opts,
        fields: ["private"],
        changesSince: page.nextChangesSince,
      }),
    ).rejects.toThrow();
    await expect(
      read("private", { ...opts, changesSince: page.nextChangesSince }),
    ).rejects.toThrow();
  });
  it("returns newly visible inserts after the checkpoint", async () => {
    const { db, id } = await fixture();
    const read = history(db);
    const first = await read("selected", opts);
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'selected','new','new',2,'next','{}','h')",
      [id],
    );
    const next = await read("selected", {
      ...opts,
      changesSince: first.nextChangesSince,
    });
    expect(next.data.map((r) => r.recordKey)).toEqual(["new"]);
  });
  it.each([
    "UPDATE records SET stamp_o=2,body='{}' WHERE stream='selected'",
    "DELETE FROM records WHERE stream='selected'",
  ])("expires after a prior body is lost: %s", async (sql) => {
    const { db } = await fixture();
    const read = history(db);
    const first = await read("selected", opts);
    await run(db, sql);
    await expect(
      read("selected", { ...opts, changesSince: first.nextChangesSince }),
    ).rejects.toThrow();
  });
  it("pins page horizons, excluding later inserts until the next session", async () => {
    const { db, id } = await fixture();
    const read = history(db);
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'selected','z','z',2,'next','{}','h')",
      [id],
    );
    const first = await read("selected", opts);
    expect(first.hasMore).toBe(true);
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'selected','later','later',3,'next','{}','h')",
      [id],
    );
    const second = await read("selected", {
      ...opts,
      cursor: first.nextCursor,
    });
    expect(second.data.map((r) => r.recordKey)).toEqual(["z"]);
    expect(second.hasMore).toBe(false);
    const third = await read("selected", {
      ...opts,
      changesSince: second.nextChangesSince,
    });
    expect(third.data.map((r) => r.recordKey)).toEqual(["later"]);
  });
  it("expires a checkpoint after sync reconnect changes generation", async () => {
    const { db, id } = await fixture();
    const read = history(db);
    const first = await read("selected", opts);
    await run(db, "UPDATE connections SET generation=3 WHERE connection_id=?", [
      id,
    ]);
    await expect(
      read("selected", { ...opts, changesSince: first.nextChangesSince }),
    ).rejects.toThrow();
  });
});

describe("grant reads through database HTTP ports", () => {
  const declarations = createStreamDeclarationRegistry([
    {
      name: "selected",
      semantics: "mutable_state",
      primaryKey: ["id"],
      cursorField: "emitted_at",
      requiredFields: ["id"],
    },
  ]);
  const grant: Grant = {
    version: "0.1.0",
    grant_id: "g",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "owner" },
    client: { client_id: "client" },
    source: { kind: "provider_native", id: "source" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "selected",
        instance_ids: ["handle-a"],
        fields: ["id", "blob_ref"],
      },
    ],
  };
  it("serves exactly the selected connection and fields, then nothing after deletion", async () => {
    const { db, query, deleted } = await fixture();
    const store = createMemoryRecordStore();
    try {
      const app = pdppRecordsRoutes({
        store,
        recordQuery: query,
        recordHistory: historyFor(db, deleted),
        accountStorageMode: { owner: "owner", read: () => "switched" },
        declarations,
        auth: createFixtureAuthorizationService({
          token: {
            active: true,
            tokenKind: "client",
            subjectId: "owner",
            grant,
          },
        }),
      });
      const headers = { Authorization: "Bearer token" };
      const selected = await app.request("/streams/selected/records", {
        headers,
      });
      expect(selected.status).toBe(200);
      expect(
        (await selected.json()).data.map((r: { id: string }) => r.id),
      ).toEqual(["allowed"]);
      expect(
        // A stream outside the grant is refused before any declaration
        // lookup (spec-core §8 grant enforcement; RS item 32).
        (await app.request("/streams/private/records", { headers })).status,
      ).toBe(403);
      const listed = await app.request("/streams", { headers });
      expect(listed.status).toBe(200);
      expect(
        (await listed.json()).data.map((r: { name: string }) => r.name),
      ).toEqual(["selected"]);
      deleted.add("handle-a");
      expect(
        (
          await (
            await app.request("/streams/selected/records", { headers })
          ).json()
        ).data,
      ).toEqual([]);
    } finally {
      store.close();
    }
  });
  it("filters grant resources before paginating records or exposing cursors", async () => {
    const { db, id, query } = await fixture();
    for (const key of ["0-hidden", "z-visible"])
      await run(
        db,
        "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'selected',?,?,2,'run',?,'h')",
        [id, key, key, JSON.stringify({ id: key })],
      );
    const store = createMemoryRecordStore();
    try {
      const app = pdppRecordsRoutes({
        store,
        recordQuery: query,
        recordHistory: historyFor(db),
        accountStorageMode: { owner: "owner", read: () => "switched" },
        declarations,
        auth: createFixtureAuthorizationService({
          token: {
            active: true,
            tokenKind: "client",
            subjectId: "owner",
            grant: {
              ...grant,
              streams: [
                { ...grant.streams[0]!, resources: ["allowed", "z-visible"] },
              ],
            },
          },
        }),
      });
      const headers = { Authorization: "Bearer token" };
      const firstResponse = await app.request(
        "/streams/selected/records?limit=1&order=asc",
        { headers },
      );
      expect(firstResponse.status).toBe(200);
      const first = await firstResponse.json();
      expect(first.data.map((r: { id: string }) => r.id)).toEqual(["allowed"]);
      expect(first.has_more).toBe(true);
      expect(typeof first.next_cursor).toBe("string");
      expect(first.next_cursor).not.toContain("0-hidden");
      expect(
        Buffer.from(first.next_cursor, "base64url").toString(),
      ).not.toContain("0-hidden");
      const second = await (
        await app.request(
          `/streams/selected/records?limit=1&order=asc&cursor=${encodeURIComponent(first.next_cursor)}`,
          { headers },
        )
      ).json();
      expect(second.data.map((r: { id: string }) => r.id)).toEqual([
        "z-visible",
      ]);
      expect(second.has_more).toBe(false);
      expect(second.next_cursor).toBeUndefined();
      expect(
        (await app.request("/streams/selected/records/0-hidden", { headers }))
          .status,
      ).toBe(404);
      for (const query of ["cursor=not-a-token", "changes_since=not-a-token"]) {
        const malformed = await app.request(
          `/streams/selected/records?${query}`,
          { headers },
        );
        expect(malformed.status).toBe(400);
        expect((await malformed.json()).error.code).toBe("invalid_cursor");
      }
      await run(
        db,
        "UPDATE records SET stamp_o=3,body_sha256='replacement' WHERE stream='selected' AND record_key='z-visible'",
      );
      const expired = await app.request(
        `/streams/selected/records?limit=1&order=asc&cursor=${encodeURIComponent(first.next_cursor)}`,
        { headers },
      );
      expect(expired.status).toBe(410);
      expect((await expired.json()).error.code).toBe("cursor_expired");
    } finally {
      store.close();
    }
  });
  const historyFor = (db: SqlDriver, deleted?: Set<string>) =>
    createGrantHistory(db, (instance, stream) =>
      !deleted?.has(instance) &&
      instance === "handle-a" &&
      stream === "selected"
        ? { connector: "fixture", namespace: "" }
        : null,
    );
  it("authorizes blob references with the same connection, stream and field selection", async () => {
    const { db, query, deleted } = await fixture();
    const bytes = new Uint8Array([1, 2, 3]);
    const hash = createHash("sha256").update(bytes).digest("hex");
    const blobId = `sha256:${hash}`;
    await run(db, "UPDATE records SET body=? WHERE stream='selected'", [
      JSON.stringify({ id: "allowed", blob_ref: { blob_id: blobId } }),
    ]);
    const store = createMemoryRecordStore();
    const link = (instance: string, stream: string) =>
      !deleted.has(instance) && instance === "handle-a" && stream === "selected"
        ? { connector: "fixture", namespace: "" }
        : null;
    let removeReference = false;
    const local = {
      recordsFor: () => query,
      blobs: {
        get: async () => {
          if (removeReference)
            await run(db, "DELETE FROM records WHERE stream='selected'");
          return { bytes, mimeType: "application/octet-stream" };
        },
      },
    } as unknown as LocalSync;
    const auth = createFixtureAuthorizationService({
      token: { active: true, tokenKind: "client", subjectId: "owner", grant },
      noFields: {
        active: true,
        tokenKind: "client",
        subjectId: "owner",
        grant: {
          ...grant,
          streams: [{ ...grant.streams[0]!, fields: ["id"] }],
        },
      },
    });
    const app = pdppBlobsRoutes({
      store,
      auth,
      declarations,
      prepareReads: (context, id) =>
        grantBlobStore({
          local,
          link,
          context,
          blobId: id,
          declarations,
          ownerInstances: [],
        }),
      isConnectionAvailable: (i) => !deleted.has(i),
    });
    try {
      const response = await app.request(`/${blobId}?instance_id=handle-a`, {
        headers: { Authorization: "Bearer token" },
      });
      expect(response.status).toBe(200);
      expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
      expect(
        (
          await app.request(`/${blobId}?instance_id=handle-a`, {
            headers: { Authorization: "Bearer noFields" },
          })
        ).status,
      ).toBe(404);
      removeReference = true;
      expect(
        (
          await app.request(`/${blobId}?instance_id=handle-a`, {
            method: "HEAD",
            headers: { Authorization: "Bearer token" },
          })
        ).status,
      ).toBe(404);
      deleted.add("handle-a");
      expect(
        (
          await app.request(`/${blobId}?instance_id=handle-a`, {
            headers: { Authorization: "Bearer token" },
          })
        ).status,
      ).toBe(404);
    } finally {
      store.close();
    }
  });
});

describe("grant change history after compaction", () => {
  it("fresh listing still returns current records when the old change log is compacted", async () => {
    const { db } = await fixture();
    await run(db, "DELETE FROM record_changes");
    const read = createGrantHistory(db, () => ({
      connector: "fixture",
      namespace: "",
    }));
    expect(
      (
        await read("selected", { instanceIds: ["handle-a"], limit: 10 })
      ).data.map((r) => r.recordKey),
    ).toEqual(["allowed"]);
  });
  it("orders multiple handles by record identity without retaining the full bodies", async () => {
    const { db, id } = await fixture();
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,'selected','empty','',2,'next','{}','h')",
      [id],
    );
    const read = createGrantHistory(db, () => ({
      connector: "fixture",
      namespace: "",
    }));
    const opts = { instanceIds: ["handle-b", "handle-a"], limit: 1 };
    let page = await read("selected", opts);
    const values = page.data.map((r) => [r.recordKey, r.instance]);
    while (page.nextCursor) {
      page = await read("selected", { ...opts, cursor: page.nextCursor });
      values.push(...page.data.map((r) => [r.recordKey, r.instance]));
    }
    // (instance_id, canonical key) order (spec-core §9 RS item 21).
    expect(values).toEqual([
      ["", "handle-a"],
      ["allowed", "handle-a"],
      ["", "handle-b"],
      ["allowed", "handle-b"],
    ]);
  });
});

it("rechecks binding authority after the database query resolves", async () => {
  const { db, deleted } = await fixture();
  const guarded: SqlDriver = {
    ...db,
    query: async <R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) => {
      const rows = await db.query<R>(sql, params);
      if (sql.includes("FROM records")) deleted.add("handle-a");
      return rows;
    },
  };
  const query = createLinkedRecordQuery(guarded, (instance) =>
    deleted.has(instance) ? null : { connector: "fixture", namespace: "" },
  );
  expect(
    await query.getRecord({
      connectionId: "handle-a",
      stream: "selected",
      recordKey: "allowed",
    }),
  ).toBeNull();
});

it("a delete intent that lands while rows are read expires the grant read", async () => {
  const { db } = await fixture();
  let inserted = false;
  const guarded: SqlDriver = {
    ...db,
    query: async <R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) => {
      const rows = await db.query<R>(sql, params);
      if (!inserted && sql.includes("FROM records r JOIN targets")) {
        inserted = true;
        await run(db, "INSERT INTO delete_intents VALUES ('fixture','d','{}')");
      }
      return rows;
    },
  };
  const read = createGrantHistory(guarded, () => ({
    connector: "fixture",
    namespace: "",
  }));
  await expect(
    read("selected", { instanceIds: ["handle-a"], limit: 10 }),
  ).rejects.toThrow();
  expect(inserted).toBe(true);
});

it("a relink during an exact-count list reads one target for count and page", async () => {
  const { db } = await fixture();
  const other = controlScope("other", "");
  await run(
    db,
    "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?, 'other', '', 1, 'active', 1)",
    [other],
  );
  for (const key of ["x", "y"])
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run','{}','hash')",
      [other, "selected", key, key],
    );
  let connector = "fixture";
  const guarded: SqlDriver = {
    ...db,
    query: async <R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) => {
      const rows = await db.query<R>(sql, params);
      // The first read of rows has finished; the host relinks the handle
      // before the caller can issue another read.
      if (sql.includes("FROM records")) connector = "other";
      return rows;
    },
  };
  const declaration = { name: "selected" } as never;
  const declarations: StreamDeclarationRegistry = {
    get: () => declaration,
    forInstance: () => declaration,
    declares: () => true,
    list: () => [declaration],
  };
  const { body } = await listPdppRecords(
    {
      accountMode: { read: () => "switched" },
      recordQuery: createLinkedRecordQuery(guarded, () => ({
        connector,
        namespace: "",
      })),
      declarations,
      ownerInstances: () => ["handle-a"],
    },
    {
      url: "https://ps.test/v1/streams/selected/records?limit=100",
      stream: "selected",
      context: { active: true, tokenKind: "owner", subjectId: "owner" },
      prefer: "count=exact",
    },
  );
  const count = (body.meta as { count: { value: number } }).count.value;
  expect((body.data as unknown[]).length).toBe(count);
});

it("grant listing orders by (instance_id, key) in the requested direction, or by the frozen sort_field (RS item 33)", async () => {
  const { db, id } = await fixture();
  for (const [key, at] of [
    ["b", "2026-03-01T00:00:00Z"],
    ["c", "nope"],
    ["d", "2026-05-01"],
  ] as const)
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run',?,'hash')",
      [id, "selected", key, key, JSON.stringify({ at })],
    );
  const read = createGrantHistory(db, () => ({
    connector: "fixture",
    namespace: "",
  }));
  const walk = async (options: Record<string, unknown>) => {
    const ids: string[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = await read("selected", {
        purpose: "listing",
        instanceIds: ["handle-a"],
        limit: 1,
        cursor,
        ...options,
      });
      ids.push(...page.data.map((row) => row.recordKey));
      if (!page.hasMore) return ids;
      cursor = page.nextCursor;
    }
  };
  expect(await walk({ order: "desc", sort: { by: "key" } })).toEqual([
    "d",
    "c",
    "b",
    "allowed",
  ]);
  expect(await walk({ order: "asc", sort: { by: "key" } })).toEqual([
    "allowed",
    "b",
    "c",
    "d",
  ]);
  // Dates and instants by what they denote; absent or invalid values last.
  expect(
    await walk({ order: "desc", sort: { by: "field", field: "at" } }),
  ).toEqual(["d", "b", "c", "allowed"]);
});

it("owner change sessions follow the two-horizon rules on a switched account (RS items 7, 20, 21)", async () => {
  const { db, id } = await fixture();
  const put = (key: string, stamp: number) =>
    run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,?,'run','{}','hash')",
      [id, "selected", key, key, stamp],
    );
  const remove = (key: string) =>
    run(db, "DELETE FROM records WHERE connection_id=? AND stream='selected' AND record_key=?", [id, key]);
  await put("gone", 1);
  await put("kept", 1);
  const read = createGrantHistory(db, () => ({
    connector: "fixture",
    namespace: "",
  }));
  const session = (changesSince?: string, order: "asc" | "desc" = "desc") =>
    read("selected", {
      instanceIds: ["handle-a"],
      limit: 100,
      changesSince,
      order,
      removals: true,
    });
  const first = await session();
  // `beginning`: every visible record, no tombstones, descending key order.
  expect(first.data.map((r) => [r.recordKey, r.deleted])).toEqual([
    ["kept", false],
    ["gone", false],
    ["allowed", false],
  ]);
  // Visible only between the horizons: never tombstoned.
  await put("brief", 2);
  await remove("brief");
  await remove("gone");
  const next = await session(first.nextChangesSince);
  expect(next.data).toEqual([
    expect.objectContaining({
      recordKey: "gone",
      instance: "handle-a",
      deleted: true,
      deletedAt: new Date(1).toISOString(),
    }),
  ]);
  // The session horizon is fixed at page one: a write after page one waits.
  const paged = await read("selected", {
    instanceIds: ["handle-a"],
    limit: 1,
    order: "asc",
    removals: true,
  });
  await put("late", 3);
  const rest = await read("selected", {
    instanceIds: ["handle-a"],
    limit: 100,
    order: "asc",
    removals: true,
    cursor: paged.nextCursor,
  });
  expect([...paged.data, ...rest.data].map((r) => r.recordKey)).toEqual([
    "allowed",
    "kept",
  ]);
});

it("an owner change session with a fields projection fails closed (410) when a record visible at h0 was written, and keeps tombstones (RS items 7, 20)", async () => {
  const { db, id } = await fixture();
  await run(
    db,
    "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run','{\"a\":1}','h1')",
    [id, "selected", "kept", "kept"],
  );
  const read = createGrantHistory(db, () => ({
    connector: "fixture",
    namespace: "",
  }));
  const session = (changesSince?: string, fields?: string[]) =>
    read("selected", {
      instanceIds: ["handle-a"],
      limit: 100,
      changesSince,
      removals: true,
      ...(fields && { fields }),
    });
  const projectedStart = await session(undefined, ["a"]);
  const wholeStart = await session();
  // A removal alone: still a tombstone with a projection.
  await run(db, "DELETE FROM records WHERE connection_id=? AND record_key='allowed'", [id]);
  const removedOnly = await session(projectedStart.nextChangesSince, ["a"]);
  expect(removedOnly.data.map((r) => [r.recordKey, r.deleted])).toEqual([
    ["allowed", true],
  ]);
  // A write to a record visible at h0: the h0 body is gone, so the
  // projected session cannot compare and expires; a whole-record owner
  // session returns the record.
  await run(
    db,
    "UPDATE records SET body='{\"a\":1,\"b\":2}', body_sha256='h2', stamp_o=2 WHERE connection_id=? AND record_key='kept'",
    [id],
  );
  await expect(
    session(projectedStart.nextChangesSince, ["a"]),
  ).rejects.toThrow(/expired/i);
  const whole = await session(wholeStart.nextChangesSince);
  expect(whole.data.map((r) => [r.recordKey, r.deleted])).toEqual([
    ["allowed", true],
    ["kept", false],
  ]);
});

describe("owner sessions over a compacted change log (RS items 7, 20, 21)", () => {
  async function compacted() {
    const { db, id } = await fixture();
    for (const key of ["b", "c", "d", "e"])
      await run(
        db,
        "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,1,'run','{}','hash')",
        [id, "selected", key, key],
      );
    const compact = () =>
      run(
        db,
        "DELETE FROM record_changes WHERE connection_id=? AND seq<=(SELECT MAX(seq) FROM record_changes)",
        [id],
      );
    const read = createGrantHistory(db, () => ({
      connector: "fixture",
      namespace: "",
    }));
    return { db, id, compact, read };
  }

  it.each(["delete", "update"] as const)(
    "a %s after page one of a paged whole-record session expires it (410) instead of skipping a record",
    async (mutate) => {
      const { db, id, compact, read } = await compacted();
      await compact();
      const options = {
        instanceIds: ["handle-a"],
        limit: 2,
        order: "asc" as const,
        removals: true,
      };
      const first = await read("selected", options);
      expect(first.hasMore).toBe(true);
      await run(
        db,
        mutate === "delete"
          ? "DELETE FROM records WHERE connection_id=? AND record_key='allowed'"
          : "UPDATE records SET body='{\"x\":1}', body_sha256='h2', stamp_o=2 WHERE connection_id=? AND record_key='allowed'",
        [id],
      );
      await expect(
        read("selected", { ...options, cursor: first.nextCursor }),
      ).rejects.toThrow(/expired/i);
    },
  );

  it("a key with no retained change at h0, written and then removed between the horizons, expires the session (no tombstone)", async () => {
    const { db, id, compact, read } = await compacted();
    const session = (changesSince?: string) =>
      read("selected", {
        instanceIds: ["handle-a"],
        limit: 100,
        changesSince,
        removals: true,
      });
    const start = await session();
    await compact();
    await run(
      db,
      "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,2,'run','{}','hash')",
      [id, "selected", "n", "n"],
    );
    await run(
      db,
      "DELETE FROM records WHERE connection_id=? AND record_key='n'",
      [id],
    );
    await expect(session(start.nextChangesSince)).rejects.toThrow(/expired/i);
  });

  it("a removal whose key has no retained change at h0 and no write since is a tombstone", async () => {
    const { db, id, compact, read } = await compacted();
    const session = (changesSince?: string) =>
      read("selected", {
        instanceIds: ["handle-a"],
        limit: 100,
        changesSince,
        removals: true,
      });
    const start = await session();
    await compact();
    await run(
      db,
      "DELETE FROM records WHERE connection_id=? AND record_key='c'",
      [id],
    );
    const next = await session(start.nextChangesSince);
    expect(next.data.map((r) => [r.recordKey, r.deleted])).toEqual([
      ["c", true],
    ]);
  });
});
