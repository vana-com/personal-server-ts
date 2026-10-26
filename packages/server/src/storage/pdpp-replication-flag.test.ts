/**
 * The replication flag contract. With `replication.enabled` off (the default),
 * the record store is main's: same schema, no replica SQL. Turning it on applies
 * the replica schema lazily; a database used with it on still opens without it.
 */
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  REPLICA_MIGRATIONS,
  createReplicaRecordStore,
} from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

interface SchemaObject {
  type: string;
  name: string;
  tableName: string;
  sql: string | null;
}
const main = JSON.parse(
  readFileSync(
    new URL("../__fixtures__/main-record-store-schema.json", import.meta.url),
    "utf8",
  ),
) as { schemaVersion: number; objects: SchemaObject[] };

/** Every table, index, trigger and view the replica code can create. */
const REPLICA_SQL =
  /pdpp_replica_|pdpp_installation_writer|pdpp_transport_|pdpp_binary_(?:chunks|manifests)|pdpp_canonical_chunks|pdpp_mutation_journal|pdpp_records_summary_/;

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

function schemaOf(db: Database.Database): SchemaObject[] {
  return db
    .prepare(
      "SELECT type, name, tbl_name AS tableName, sql FROM sqlite_master ORDER BY type, name",
    )
    .all() as SchemaObject[];
}
function schemaVersion(db: Database.Database): number {
  return (
    db.prepare("SELECT MAX(version) AS v FROM pdpp_schema_version").get() as {
      v: number;
    }
  ).v;
}
/** A handle that records every SQL text the store prepares or executes. */
function traced(db: Database.Database, seen: string[]): Database.Database {
  return new Proxy(db, {
    get(target, property) {
      if (property === "prepare" || property === "exec")
        return (sql: string) => {
          seen.push(sql);
          return property === "prepare"
            ? target.prepare(sql)
            : target.exec(sql);
        };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

const register = (store: Store, instance = "conn_a") =>
  store.registerConnection({
    instance,
    sourceId,
    method: "collector",
    label: "A",
  });
const ingest = (store: Store, key: string, text: string, blobId?: string) =>
  store.ingestBatch(
    [
      {
        instance: "conn_a",
        stream: "messages",
        key,
        data: {
          id: key,
          text,
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
const storeBytes = (store: Store, bytes: Uint8Array) =>
  store.storeBlobBytesForInstance({
    instance: "conn_a",
    method: "collector",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
const keys = (store: Store) =>
  store
    .listRecords("messages", {
      instanceIds: ["conn_a"],
      limit: 100,
      order: "asc",
    })
    .data.map((row) => row.recordKey);

const directories: string[] = [];
const handles: Database.Database[] = [];
function file(): string {
  const directory = mkdtempSync(join(tmpdir(), "pdpp-replication-flag-"));
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

describe("replication flag off (the default)", () => {
  it("is off in the default server config", () => {
    expect(ServerConfigSchema.parse({}).replication).toEqual({
      enabled: false,
    });
  });

  it("opens a new database with exactly main's record-store schema", () => {
    const db = open();
    openRecordStore(db, false);
    expect(schemaOf(db)).toEqual(main.objects);
    expect(schemaVersion(db)).toBe(main.schemaVersion);
  });

  it("runs no replica SQL and adds no schema across writes, reads and deletes", () => {
    const seen: string[] = [];
    const db = open();
    const store = openRecordStore(traced(db, seen), false);
    register(store);
    const small = storeBytes(store, new Uint8Array([1, 2, 3]));
    const large = storeBytes(store, new Uint8Array(2 * 1024 * 1024).fill(7));
    ingest(store, "a", "first", small.blobId);
    ingest(store, "b", "second", large.blobId);
    ingest(store, "a", "updated", small.blobId);
    expect(keys(store)).toEqual(["a", "b"]);
    expect(store.getRecord("conn_a", "messages", "a")?.data).toMatchObject({
      text: "updated",
    });
    expect(
      store
        .changesSince("messages", { instanceIds: ["conn_a"], limit: 100 })
        .data.map((row) => row.recordKey),
    ).toEqual(["a", "b"]);
    expect(store.getBlobBytes(small.blobId)).toEqual(new Uint8Array([1, 2, 3]));
    expect(store.getBlobBytes(large.blobId)?.byteLength).toBe(2 * 1024 * 1024);
    store.listStreams(["conn_a"]);
    store.deleteConnection("conn_a");
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.filter((sql) => REPLICA_SQL.test(sql))).toEqual([]);
    expect(schemaOf(db)).toEqual(main.objects);
  });
});

describe("replication flag on", () => {
  it("applies the replica schema when the store opens, not before", () => {
    const db = open();
    openRecordStore(db, true);
    expect(
      (
        db
          .prepare("SELECT MAX(version) AS v FROM pdpp_replica_schema_version")
          .get() as { v: number }
      ).v,
    ).toBe(REPLICA_MIGRATIONS.length);
    expect(schemaVersion(db)).toBe(main.schemaVersion);
  });

  it("off → on: enabling baselines rows written while off, and a second device converges", () => {
    const path = file();
    const offDb = open(path);
    const off = openRecordStore(offDb, false);
    register(off);
    const blob = storeBytes(off, new Uint8Array([4, 5, 6]));
    ingest(off, "a", "written while off", blob.blobId);
    ingest(off, "b", "also while off");
    off.close();

    const onDb = open(path);
    const on = createReplicaRecordStore(onDb);
    on.replication.beginBaseline(baseline);
    const operations: ReplicaOperation[] = [
      ...on.replication.readBaselinePage({ limit: 1000 }).operations,
      ...on.replication.readTailPage({ limit: 1000 }).operations,
    ];
    expect(
      operations.filter((op) => op.kind === "upsert").map((op) => op.recordKey),
    ).toEqual(expect.arrayContaining(["a", "b"]));

    const peerDb = open(file());
    const peer = createReplicaRecordStore(peerDb);
    register(peer);
    peer.replication.beginBaseline(baseline);
    createReplicaReceiver({
      db: peerDb,
      store: peer,
      owner: "owner",
      authenticate: (credential: unknown) =>
        credential === "replica-secret" ? "owner" : undefined,
      declarations: () => declarations,
    }).import({
      credential: "replica-secret",
      envelope: {
        format: "vana-pdpp-replica",
        version: 1,
        owner: "owner",
        batchId: "off-to-on",
        operations,
      },
      blobs: [{ blobId: blob.blobId, bytes: new Uint8Array([4, 5, 6]) }],
    });
    expect(keys(peer)).toEqual(["a", "b"]);
    expect(peer.getRecord("conn_a", "messages", "a")?.data).toMatchObject({
      text: "written while off",
    });
    expect(peer.getBlobBytes(blob.blobId)).toEqual(new Uint8Array([4, 5, 6]));
  });

  it.todo(
    "on → off → write → on: re-enabling re-baselines, so a replica sees the writes made while off (§5, pending Tim's decision)",
  );

  it("rollback: a database used with replication on opens under the plain store with main's objects unchanged", () => {
    const path = file();
    const onDb = open(path);
    const on = createReplicaRecordStore(onDb);
    register(on);
    on.replication.beginBaseline(baseline);
    // The receiver installs the visibility view's triggers on main tables.
    createReplicaReceiver({
      db: onDb,
      store: on,
      owner: "owner",
      authenticate: () => "owner",
      declarations: () => declarations,
    });
    const blob = storeBytes(on, new Uint8Array([9, 9, 9]));
    ingest(on, "a", "written while on", blob.blobId);
    on.close();

    const db = open(path);
    const plain = createSqliteRecordStore(db);
    expect(schemaVersion(db)).toBe(main.schemaVersion);
    const objects = new Map(schemaOf(db).map((o) => [o.name, o]));
    for (const object of main.objects)
      expect(objects.get(object.name), object.name).toEqual(object);
    expect(plain.getRecord("conn_a", "messages", "a")?.data).toMatchObject({
      text: "written while on",
    });
    expect(plain.getBlobBytes(blob.blobId)).toEqual(new Uint8Array([9, 9, 9]));
    ingest(plain, "b", "written after rollback");
    expect(keys(plain)).toEqual(["a", "b"]);
    plain.deleteConnection("conn_a");
    expect(keys(plain)).toEqual([]);
  });
});
