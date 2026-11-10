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
        (await app.request("/streams/private/records", { headers })).status,
      ).toBe(404);
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
        "/streams/selected/records?limit=1",
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
          `/streams/selected/records?limit=1&cursor=${encodeURIComponent(first.next_cursor)}`,
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
        `/streams/selected/records?limit=1&cursor=${encodeURIComponent(first.next_cursor)}`,
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
      const response = await app.request(`/${blobId}`, {
        headers: { Authorization: "Bearer token" },
      });
      expect(response.status).toBe(200);
      expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
      expect(
        (
          await app.request(`/${blobId}`, {
            headers: { Authorization: "Bearer noFields" },
          })
        ).status,
      ).toBe(404);
      removeReference = true;
      expect(
        (
          await app.request(`/${blobId}`, {
            method: "HEAD",
            headers: { Authorization: "Bearer token" },
          })
        ).status,
      ).toBe(404);
      deleted.add("handle-a");
      expect(
        (
          await app.request(`/${blobId}`, {
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
    expect(values).toEqual([
      ["", "handle-a"],
      ["", "handle-b"],
      ["allowed", "handle-a"],
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
