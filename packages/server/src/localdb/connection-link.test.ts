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
import { createGrantHistory } from "../../../core/src/localdb/query.js";
import { afterEach, describe, expect, it } from "vitest";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  createLinkedRecordQuery,
  openLocalDb,
  type SqlDriver,
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
        recordHistory: historyFor(db),
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
  const historyFor = (db: SqlDriver) =>
    createGrantHistory(db, (instance, stream) =>
      instance === "handle-a" && stream === "selected"
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
    const local = {
      recordsFor: () => query,
      blobs: {
        get: async () => ({ bytes, mimeType: "application/octet-stream" }),
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
