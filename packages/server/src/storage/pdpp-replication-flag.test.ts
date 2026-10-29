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
import { ReplicationRefusedError } from "@opendatalabs/personal-server-ts-core/replication/door";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  openRecordStore,
  resolveReplication,
} from "../pdpp/records-bootstrap.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  REPLICA_MIGRATIONS,
  createReplicaRecordStore,
  ensureReplicaSchema,
} from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { REPLICA_BLOB_CLAIM_INDEX_MIGRATION } from "./pdpp-replication-sqlite.js";

const quiet = { warn: () => {} };
/** Length of main's whole canonical row for a blob, if it has one. */
const wholeRow = (db: Database.Database, blobId: string) =>
  (
    db
      .prepare(
        "SELECT length(bytes) AS size FROM pdpp_blob_bytes WHERE blob_id = ?",
      )
      .get(blobId) as { size: number } | undefined
  )?.size;
const canonicalChunks = (db: Database.Database, blobId: string) =>
  (
    db
      .prepare(
        "SELECT count(*) AS n FROM pdpp_binary_chunks WHERE namespace = 'canonical' AND blob_id = ?",
      )
      .get(blobId) as { n: number }
  ).n;
/** Whole-blob equality. `toEqual` walks a 2 MiB array element by element. */
const sameBytes = (actual: Uint8Array | undefined, expected: Uint8Array) =>
  actual !== undefined && Buffer.from(actual).equals(Buffer.from(expected));

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

  it("reopens a flag-off database with main's schema and ordinary write behavior", () => {
    const path = file();
    const firstDb = open(path);
    const first = openRecordStore(firstDb, false);
    register(first);
    ingest(first, "before-reopen", "kept while replication is off");
    first.close();

    const reopenedDb = open(path);
    const reopened = openRecordStore(reopenedDb, false);
    expect(schemaOf(reopenedDb)).toEqual(main.objects);
    expect(schemaVersion(reopenedDb)).toBe(main.schemaVersion);
    expect(keys(reopened)).toEqual(["before-reopen"]);
    ingest(reopened, "after-reopen", "still ordinary storage");
    expect(keys(reopened)).toEqual(["after-reopen", "before-reopen"]);
    expect(schemaOf(reopenedDb)).toEqual(main.objects);
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
  it("keeps large blobs readable through flag-off and plain main stores", () => {
    const path = file();
    const bytes = new Uint8Array(2 * 1024 * 1024).fill(0x5a);
    const writerDb = open(path);
    const writer = openRecordStore(writerDb, true);
    register(writer);
    const blob = storeBytes(writer, bytes);
    expect(storeBytes(writer, bytes).blobId).toBe(blob.blobId);
    writerDb.close();

    const canonicalDb = open(path);
    expect(
      (
        canonicalDb
          .prepare(
            "SELECT length(bytes) AS size FROM pdpp_blob_bytes WHERE blob_id = ?",
          )
          .get(blob.blobId) as { size: number }
      ).size,
    ).toBe(bytes.byteLength);
    // Replication promotes a large blob in the chunk form only. Model that.
    canonicalDb
      .prepare("DELETE FROM pdpp_blob_bytes WHERE blob_id = ?")
      .run(blob.blobId);
    canonicalDb.close();

    // An enabled open keeps it chunk-only, and its readers accept that form.
    const onDb = open(path);
    expect(
      sameBytes(openRecordStore(onDb, true).getBlobBytes(blob.blobId), bytes),
    ).toBe(true);
    expect(wholeRow(onDb, blob.blobId)).toBeUndefined();
    onDb.close();

    // The flag-off boot retires replication and writes main's row.
    const offDb = open(path);
    expect(resolveReplication(offDb, false, quiet).status.state).toBe("off");
    expect(wholeRow(offDb, blob.blobId)).toBe(bytes.byteLength);
    expect(canonicalChunks(offDb, blob.blobId)).toBe(0);
    const off = openRecordStore(offDb, false);
    expect(sameBytes(off.getBlobBytes(blob.blobId), bytes)).toBe(true);
    offDb.close();

    const mainDb = open(path);
    const mainStore = createSqliteRecordStore(mainDb);
    expect(sameBytes(mainStore.getBlobBytes(blob.blobId), bytes)).toBe(true);
    mainDb.close();
  }, 30_000);

  it("receiver imports large blobs into bytes the plain store can read", () => {
    const bytes = new Uint8Array(2 * 1024 * 1024).fill(0x6b);
    const sourceDb = open();
    const source = openRecordStore(sourceDb, true);
    register(source);
    const blob = storeBytes(source, bytes);
    ingest(source, "received", "from another device", blob.blobId);
    source.replication.beginBaseline(baseline);
    const operations: ReplicaOperation[] = [
      ...source.replication.readBaselinePage({ limit: 1000 }).operations,
      ...source.replication.readTailPage({ limit: 1000 }).operations,
    ];

    const path = file();
    const receiverDb = open(path);
    const receiverStore = createReplicaRecordStore(receiverDb);
    register(receiverStore);
    receiverStore.replication.beginBaseline(baseline);
    createReplicaReceiver({
      db: receiverDb,
      store: receiverStore,
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
        batchId: "large-blob-import",
        operations,
      },
      blobs: [{ blobId: blob.blobId, bytes }],
    });
    receiverDb.close();

    // Promotion stores the large blob once, in the chunk form.
    const chunkDb = open(path);
    expect(wholeRow(chunkDb, blob.blobId)).toBeUndefined();
    expect(canonicalChunks(chunkDb, blob.blobId)).toBeGreaterThan(0);
    chunkDb.close();

    // The flag-off boot writes main's row before any plain store reads it.
    const offDb = open(path);
    resolveReplication(offDb, false, quiet);
    expect(
      sameBytes(openRecordStore(offDb, false).getBlobBytes(blob.blobId), bytes),
    ).toBe(true);
    offDb.close();
    const plainDb = open(path);
    expect(wholeRow(plainDb, blob.blobId)).toBe(bytes.byteLength);
    const plainStore = createSqliteRecordStore(plainDb);
    expect(sameBytes(plainStore.getBlobBytes(blob.blobId), bytes)).toBe(true);
    plainDb.close();
  }, 30_000);

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

  it("on → off → write → on: the enabled open is refused, and the rows written while off stay", () => {
    const path = file();
    const onDb = open(path);
    const on = openRecordStore(onDb, true);
    register(on);
    (
      on as ReturnType<typeof createReplicaRecordStore>
    ).replication.beginBaseline(baseline);
    ingest(on, "a", "written while on");
    on.close();

    const offDb = open(path);
    ingest(openRecordStore(offDb, false), "b", "written while off");
    offDb.close();

    expect(() => openRecordStore(open(path), true)).toThrow(
      new ReplicationRefusedError("reenable_refused"),
    );
    expect(keys(createSqliteRecordStore(open(path)))).toEqual(["a", "b"]);
  });

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

  it("refuses every connection-scoped mutator after quarantine without changing canonical state", () => {
    const db = open();
    const store = openRecordStore(db, true);
    register(store);
    const blob = storeBytes(store, new Uint8Array([1, 2, 3]));
    ingest(store, "a", "before", blob.blobId);
    db.prepare(
      "INSERT INTO pdpp_claude_transition (instance, archive_instance, generation, snapshots_json) VALUES (?, ?, ?, ?)",
    ).run(
      "conn_a",
      "retired-claude:test",
      2,
      JSON.stringify({ "claude.conversations": {} }),
    );
    db.prepare(
      "INSERT INTO pdpp_strava_transition (instance, archive_instance, generation, snapshots_json) VALUES (?, ?, ?, ?)",
    ).run(
      "conn_a",
      "retired-strava:test",
      2,
      JSON.stringify({ "strava.activities": {} }),
    );
    db.prepare(
      "INSERT INTO pdpp_replica_quarantined_connections (instance) VALUES (?)",
    ).run("conn_a");
    const state = () => ({
      records: db
        .prepare(
          "SELECT * FROM pdpp_records ORDER BY instance, stream, record_key",
        )
        .all(),
      history: db
        .prepare("SELECT * FROM pdpp_record_changes ORDER BY id")
        .all(),
      bindings: db
        .prepare("SELECT * FROM pdpp_instance_binding ORDER BY instance")
        .all(),
      claude: db
        .prepare("SELECT * FROM pdpp_claude_transition ORDER BY instance")
        .all(),
      strava: db
        .prepare("SELECT * FROM pdpp_strava_transition ORDER BY instance")
        .all(),
      claims: db
        .prepare("SELECT * FROM pdpp_blob_claims ORDER BY blob_id, instance")
        .all(),
      bytes: db
        .prepare(
          "SELECT blob_id, length(bytes) AS size FROM pdpp_blob_bytes ORDER BY blob_id",
        )
        .all(),
      clock: db.prepare("SELECT value FROM pdpp_write_clock").get(),
    });
    const before = state();
    const mutations: [string, () => unknown][] = [
      [
        "resetInstanceBinding",
        () =>
          store.resetInstanceBinding({
            instance: "conn_a",
            expectedMethod: "collector",
            expectedGeneration: 1,
            nextMethod: "collector",
          }),
      ],
      ["deleteConnection", () => store.deleteConnection("conn_a")],
      ["registerConnection", () => register(store)],
      [
        "storeBlobBytesForInstance",
        () => storeBytes(store, new Uint8Array([4, 5, 6])),
      ],
      ["ingestBatch", () => ingest(store, "b", "after")],
      [
        "replaceStream",
        () =>
          store.replaceStream({
            instance: "conn_a",
            stream: "messages",
            method: "collector",
            generation: 1,
            emittedAt: at,
            envelopes: [],
            primaryKey: ["id"],
          }),
      ],
      [
        "deleteRecord",
        () =>
          store.deleteRecord("conn_a", "messages", "a", at, "mutable_state"),
      ],
      [
        "replaceStreams",
        () =>
          store.replaceStreams([
            {
              instance: "conn_a",
              stream: "messages",
              method: "collector",
              generation: 1,
              emittedAt: at,
              envelopes: [],
              primaryKey: ["id"],
            },
          ]),
      ],
      [
        "completeStreams",
        () =>
          store.completeStreams(
            {
              instance: "conn_a",
              sourceId,
              method: "collector",
              generation: 1,
              sourceCollectedAt: at,
              collectionTimeBasis: "host_run_finished",
              streams: [
                {
                  stream: "messages",
                  coverage: "full_stream",
                  liveCount: 1,
                  snapshotSha256: "0".repeat(64),
                },
              ],
            },
            () => ["id"],
          ),
      ],
      [
        "transitionClaudeToLive",
        () =>
          store.transitionClaudeToLive({
            instance: "conn_a",
            expectedGeneration: 1,
            expectedWriteClock: store.transitionWriteClock(),
            snapshots: {},
          }),
      ],
      [
        "transitionStravaToBrowser",
        () =>
          store.transitionStravaToBrowser({
            instance: "conn_a",
            expectedGeneration: 1,
            expectedWriteClock: store.transitionWriteClock(),
            snapshots: {},
          }),
      ],
      [
        "confirmClaudeTransition",
        () => store.confirmClaudeTransition("conn_a", 1),
      ],
      [
        "confirmStravaTransition",
        () => store.confirmStravaTransition("conn_a", 1),
      ],
      [
        "clearClaudeTransitionScope",
        () => store.clearClaudeTransitionScope("claude.conversations"),
      ],
      [
        "clearStravaTransitionScope",
        () => store.clearStravaTransitionScope("strava.activities"),
      ],
    ];
    for (const [name, mutate] of mutations) {
      expect(() => mutate(), name).toThrow("replica_integrity_quarantine");
      expect(state(), name).toEqual(before);
    }
  });
  describe("method transitions (Strava and Claude) are not journaled", () => {
    const transitionRow = (table: string, archive: string) =>
      `INSERT INTO ${table} (instance, archive_instance, generation, snapshots_json) VALUES ('conn_a', '${archive}', 2, '{}')`;

    it("refuses enabling replication while a transition exists, naming the connection", () => {
      for (const [table, archive] of [
        ["pdpp_claude_transition", "retired-claude:test"],
        ["pdpp_strava_transition", "retired-strava:test"],
      ]) {
        const path = file();
        const db = open(path);
        const off = openRecordStore(db, false);
        register(off);
        db.prepare(transitionRow(table, archive)).run();
        off.close();
        const on = createReplicaRecordStore(open(path));
        expect(() => on.replication.beginBaseline(baseline)).toThrow(
          /connection conn_a has a Strava or Claude method transition/,
        );
      }
    });

    it("refuses re-enabling after a transition made while the flag was off, at the door", () => {
      const path = file();
      const first = open(path);
      const on = createReplicaRecordStore(first);
      on.registerConnection({
        instance: "strava_a",
        sourceId: "https://registry.pdpp.dev/sources/strava",
        method: "strava",
        label: "Strava",
      });
      on.replication.beginBaseline(baseline);
      on.close();

      const offDb = open(path);
      const off = openRecordStore(offDb, false);
      off.transitionStravaToBrowser({
        instance: "strava_a",
        expectedGeneration: 1,
        expectedWriteClock: off.transitionWriteClock(),
        snapshots: {},
      });
      off.close();

      // The transition wrote fenced tables outside capture, so the door
      // refuses the open before the baseline's own transition check runs.
      expect(() => createReplicaRecordStore(open(path))).toThrow(
        new ReplicationRefusedError("reenable_refused"),
      );
    });

    it("refuses new transitions once replication is enabled, leaving canonical state alone", () => {
      const db = open();
      const store = createReplicaRecordStore(db);
      register(store);
      store.replication.beginBaseline(baseline);
      const before = db.prepare("SELECT * FROM pdpp_instance_binding").all();
      const input = {
        instance: "conn_a",
        expectedGeneration: 1,
        expectedWriteClock: store.transitionWriteClock(),
        snapshots: {},
      };
      expect(() => store.transitionClaudeToLive(input)).toThrow(
        "replica_method_transition_unsupported",
      );
      expect(() => store.transitionStravaToBrowser(input)).toThrow(
        "replica_method_transition_unsupported",
      );
      expect(db.prepare("SELECT * FROM pdpp_instance_binding").all()).toEqual(
        before,
      );
    });
  });

  it("gives an existing database the blob-claim index through a new migration", () => {
    const db = open();
    // A database that migrated before the index existed: every earlier
    // migration applied, the index absent, the version just before it.
    const store = createReplicaRecordStore(db);
    db.exec("DROP INDEX pdpp_replica_blob_claim_idx");
    db.prepare("UPDATE pdpp_replica_schema_version SET version = ?").run(
      REPLICA_MIGRATIONS.indexOf(REPLICA_BLOB_CLAIM_INDEX_MIGRATION),
    );
    const names = () =>
      (
        db
          .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'pdpp_replica_blob_claim_idx'",
          )
          .all() as { name: string }[]
      ).length;
    expect(names()).toBe(0);
    ensureReplicaSchema(db);
    expect(names()).toBe(1);
    const plan = db
      .prepare(
        "EXPLAIN QUERY PLAN SELECT 1 FROM pdpp_replica_operations WHERE json_extract(operation_json, '$.kind') = 'blob-claim' AND json_extract(operation_json, '$.connectionId') = ? AND json_extract(operation_json, '$.generation') = ? AND json_extract(operation_json, '$.blob.blobId') = ? LIMIT 1",
      )
      .all("conn_a", 1, "sha256:x") as { detail: string }[];
    expect(plan.map((row) => row.detail).join("\n")).toContain(
      "pdpp_replica_blob_claim_idx",
    );
    store.close();
  });

  it("never reconciles a write whose transaction rolled back", () => {
    const db = open();
    const store = createReplicaRecordStore(db);
    register(store);
    store.replication.beginBaseline(baseline);
    const reconciled: string[] = [];
    store.setReplicaLocalWriteObserver((_instance, _stream, recordKey) => {
      reconciled.push(recordKey);
    });
    const envelope = (key: string) => ({
      instance: "conn_a",
      stream: "messages",
      key,
      data: { id: key, text: key },
      emitted_at: at,
    });
    const queued = () =>
      (
        db
          .prepare(
            "SELECT count(*) AS n FROM temp.pdpp_replica_unsettled_writes",
          )
          .get() as { n: number }
      ).n;
    for (let attempt = 0; attempt < 3; attempt++) {
      let calls = 0;
      expect(() =>
        store.ingestBatch(
          [envelope(`failed-${attempt}-a`), envelope(`failed-${attempt}-b`)],
          // The first envelope is written and queued; the second throws.
          () => {
            if (++calls === 2) throw new Error("boom");
            return "mutable_state";
          },
          () => ["id"],
          { method: "collector", generation: 1 },
        ),
      ).toThrow("boom");
      expect(queued()).toBe(0);
    }
    expect(reconciled).toEqual([]);
    ingest(store, "kept", "written");
    expect(reconciled).toEqual(["kept"]);
    expect(queued()).toBe(0);
    expect(keys(store)).toEqual(["kept"]);
  });

  it("looks up an existing blob claim through the index, however long the journal is", () => {
    const db = open();
    const seen: string[] = [];
    const store = createReplicaRecordStore(traced(db, seen));
    register(store);
    store.replication.beginBaseline(baseline);
    const insert = db.prepare(
      "INSERT INTO pdpp_replica_operations (sequence, operation_json, digest) VALUES (?, ?, 'x')",
    );
    db.transaction(() => {
      for (let sequence = 1000; sequence < 21000; sequence++)
        insert.run(sequence, JSON.stringify({ kind: "filler", sequence }));
    })();
    const blob = storeBytes(store, new Uint8Array([7, 8, 9]));
    ingest(store, "a", "with blob", blob.blobId);
    const lookup = seen.find(
      (sql) =>
        sql.includes("blob-claim") &&
        sql.startsWith("SELECT 1 FROM pdpp_replica_operations"),
    );
    expect(lookup).toBeDefined();
    const plan = db
      .prepare(`EXPLAIN QUERY PLAN ${lookup}`)
      .all("conn_a", 1, blob.blobId, "writer") as { detail: string }[];
    expect(plan.map((row) => row.detail).join("\n")).toContain(
      "pdpp_replica_blob_claim_idx",
    );
  });
});
