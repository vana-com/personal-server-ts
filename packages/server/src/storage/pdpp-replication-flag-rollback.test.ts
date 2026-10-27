/**
 * Replica triggers live only on the connection that enabled replication.
 * A database used with the flag on, then opened plain (flag off, or a main
 * build), runs no replica SQL: its writes touch no replica table and the file
 * holds no trigger on a canonical table. The next enabled open converges.
 *
 * The statement proxy in `pdpp-replication-flag.test.ts` cannot see SQL that
 * runs inside a trigger, so these tests compare table state.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const declarations: MergeContext["declarations"] = [
  { sourceId, binding, validateData: (data) => typeof data.id === "string" },
];
const baseline = { owner: "owner", declarations: [{ sourceId, binding }] };

type Store = ReturnType<typeof createSqliteRecordStore>;

const directories: string[] = [];
const handles: Database.Database[] = [];
function file(): string {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-replication-rollback-"));
  directories.push(directory);
  return join(directory, "db.sqlite");
}
function open(path = ":memory:"): Database.Database {
  const db = new Database(path);
  handles.push(db);
  return db;
}
afterEach(() => {
  for (const db of handles.splice(0)) if (db.open) db.close();
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

const register = (store: Store) =>
  store.registerConnection({
    instance: "conn_a",
    sourceId,
    method: "collector",
    label: "A",
  });
const ingest = (store: Store, key: string, blobId?: string) =>
  store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key,
        data: {
          id: key,
          ...(blobId && {
            blob_ref: {
              blob_id: blobId,
              mime_type: "application/octet-stream",
            },
          }),
        },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "collector", generation: 1 },
  );
const keys = (store: Store) =>
  store
    .listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 100,
      order: "asc",
    })
    .data.map((row) => row.recordKey);

/** Every row of every table the replica code owns, as comparable text. */
function replicaState(db: Database.Database): Record<string, unknown[]> {
  const tables = db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND (name GLOB 'pdpp_replica_*' OR name GLOB 'pdpp_binary_*' OR name GLOB 'pdpp_transport_*' OR name='pdpp_installation_writer') ORDER BY name",
    )
    .all() as { name: string }[];
  return Object.fromEntries(
    tables.map(({ name }) => [
      name,
      db.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all(),
    ]),
  );
}
const triggersOnDisk = (db: Database.Database) =>
  db
    .prepare(
      "SELECT name, tbl_name AS tableName FROM sqlite_master WHERE type='trigger' ORDER BY name",
    )
    .all() as { name: string; tableName: string }[];

describe("a database used with replication on, then opened plain", () => {
  it("runs no replica SQL: replica tables stay untouched and no replica trigger sits on a canonical table", () => {
    const path = file();
    const onDb = open(path);
    const on = createReplicaRecordStore(onDb);
    register(on);
    on.replication.beginBaseline(baseline);
    createReplicaReceiver({
      db: onDb,
      store: on,
      owner: "owner",
      authenticate: () => "owner",
      declarations: () => declarations,
    });
    const small = on.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes: new Uint8Array([1, 2, 3]),
      mimeType: "application/octet-stream",
    });
    // Above 1 MiB the replica keeps canonical bytes in its chunk tables too.
    const large = on.storeBlobBytesForInstance({
      instance: "conn_a",
      method: "collector",
      generation: 1,
      bytes: new Uint8Array(2 * 1024 * 1024).fill(3),
      mimeType: "application/octet-stream",
    });
    ingest(on, "a", small.blobId);
    ingest(on, "b", large.blobId);
    ingest(on, "c");
    onDb.close();

    const db = open(path);
    // Reopen plain and add nothing replica-related.
    const plain = createSqliteRecordStore(db);
    // Neither the file nor this connection may hold a replica trigger that
    // reaches a canonical table.
    expect(
      triggersOnDisk(db).filter(
        ({ tableName }) =>
          !/^pdpp_replica_|^pdpp_binary_|^pdpp_transport_/.test(tableName),
      ),
    ).toEqual([]);
    expect(
      db
        .prepare("SELECT name FROM sqlite_temp_master WHERE type='trigger'")
        .all(),
    ).toEqual([]);

    const before = replicaState(db);
    ingest(plain, "d");
    ingest(plain, "a"); // rewrite
    expect(
      plain.deleteRecord("conn_a", "messages", "c", at, "mutable_state"),
    ).toBe(true);
    // Deleting the connection erases its records and blobs, including the
    // chunked one.
    plain.deleteConnection("conn_a");
    expect(keys(plain)).toEqual([]);
    expect(plain.getBlobMeta(large.blobId)).toBeUndefined();

    expect(replicaState(db)).toEqual(before);
    expect(
      triggersOnDisk(db).filter(
        ({ tableName }) =>
          !/^pdpp_replica_|^pdpp_binary_|^pdpp_transport_/.test(tableName),
      ),
    ).toEqual([]);

    // The plain delete left the erased blob's replica chunks. The next
    // enabled open clears them.
    const chunks = (handle: Database.Database) =>
      (
        handle
          .prepare(
            "SELECT count(*) AS n FROM pdpp_binary_chunks WHERE namespace = 'canonical' AND blob_id = ?",
          )
          .get(large.blobId) as { n: number }
      ).n;
    expect(chunks(db)).toBeGreaterThan(0);
    db.close();
    const againDb = open(path);
    createReplicaRecordStore(againDb);
    expect(chunks(againDb)).toBe(0);
  }, 30_000);

  it("an enabled open removes persistent replica triggers an earlier build left", () => {
    const path = file();
    const onDb = open(path);
    const on = createReplicaRecordStore(onDb);
    register(on);
    on.replication.beginBaseline(baseline);
    createReplicaReceiver({
      db: onDb,
      store: on,
      owner: "owner",
      authenticate: () => "owner",
      declarations: () => declarations,
    });
    // An earlier build created these as persistent objects.
    const temp = onDb
      .prepare(
        "SELECT name, sql FROM sqlite_temp_master WHERE type='trigger' AND (name GLOB 'pdpp_replica_view*' OR name GLOB 'pdpp_records_summary_*' OR name = 'pdpp_canonical_chunks_delete')",
      )
      .all() as { name: string; sql: string }[];
    expect(temp.length).toBeGreaterThan(20);
    ingest(on, "a");
    onDb.close();

    const legacyDb = open(path);
    for (const { sql } of temp)
      legacyDb.exec(sql.replace(/^CREATE TEMP TRIGGER/i, "CREATE TRIGGER"));
    expect(
      triggersOnDisk(legacyDb).filter(
        ({ tableName }) => tableName === "pdpp_records",
      ),
    ).not.toEqual([]);
    legacyDb.close();

    const againDb = open(path);
    const again = createReplicaRecordStore(againDb);
    createReplicaReceiver({
      db: againDb,
      store: again,
      owner: "owner",
      authenticate: () => "owner",
      declarations: () => declarations,
    });
    expect(
      triggersOnDisk(againDb).filter(({ name }) =>
        /^pdpp_replica_(?:view|local)|^pdpp_records_summary_|^pdpp_canonical_chunks/.test(
          name,
        ),
      ),
    ).toEqual([]);
    // This connection still maintains its summaries.
    ingest(again, "b");
    expect(
      againDb
        .prepare(
          "SELECT live_count FROM pdpp_replica_view_streams WHERE preview = 0 AND instance = 'conn_a'",
        )
        .get(),
    ).toEqual({ live_count: 2 });
  });

  it("converges on the next enabled open: summaries match writes made while plain", () => {
    const path = file();
    const onDb = open(path);
    const on = createReplicaRecordStore(onDb);
    register(on);
    on.replication.beginBaseline(baseline);
    const receiver = (db: Database.Database, store: typeof on) =>
      createReplicaReceiver({
        db,
        store,
        owner: "owner",
        authenticate: () => "owner",
        declarations: () => declarations,
      });
    receiver(onDb, on);
    ingest(on, "a");
    ingest(on, "b");
    const summary = (db: Database.Database) =>
      db
        .prepare(
          "SELECT live_count AS live, row_count AS rows, last_updated AS lastUpdated, revision FROM pdpp_replica_view_streams WHERE preview=0 AND instance='conn_a' AND stream='messages'",
        )
        .get() as {
        live: number;
        rows: number;
        lastUpdated: string | null;
        revision: number;
      };
    expect(summary(onDb)).toMatchObject({ live: 2, rows: 2 });
    const revisionBefore = summary(onDb).revision;
    onDb.close();

    const plainDb = open(path);
    const plain = createSqliteRecordStore(plainDb);
    plain.deleteRecord("conn_a", "messages", "a", at, "mutable_state");
    ingest(plain, "c");
    ingest(plain, "d");
    plainDb.close();

    const againDb = open(path);
    const again = createReplicaRecordStore(againDb);
    receiver(againDb, again);
    expect(summary(againDb)).toMatchObject({ live: 3, rows: 3 });
    expect(summary(againDb).revision).toBeGreaterThan(revisionBefore);
    expect(keys(again)).toEqual(["b", "c", "d"]);
  });
});
