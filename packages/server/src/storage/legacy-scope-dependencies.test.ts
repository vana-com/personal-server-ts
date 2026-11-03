import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, expect, it } from "vitest";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  installLegacyScopeDependencies,
  readLegacyScopeDependencies as read,
} from "./legacy-scope-dependencies.js";
import { ensureReplicaSchema } from "./pdpp-replica-canonical-port.js";
let db: Database.Database;
beforeEach(() => {
  db = new Database(":memory:");
  createSqliteRecordStore(db);
});
afterEach(() => db.close());
const token = (stream = "a", instance = "i") => read(db, instance, [stream]);
function record(stream = "a", blob = "blob", instance = "i") {
  db.prepare(
    "INSERT INTO pdpp_records(instance,stream,record_key,data,version,emitted_at,blob_id) VALUES (?,?,'key','{}',1,'2026-01-01',?)",
  ).run(instance, stream, blob);
}
it("fails closed without installed base schema", () => {
  const empty = new Database(":memory:");
  expect(read(empty, "i", ["a"])).toBeNull();
  empty.close();
});
it("isolates streams, persists final deletion and rolls counters back with savepoints", () => {
  const zero = token();
  record();
  const one = token();
  expect(one).not.toBe(zero);
  const other = token("b");
  db.exec("UPDATE pdpp_records SET data='{}'");
  expect(token()).not.toBe(one);
  expect(token("b")).toBe(other);
  const two = token();
  expect(() =>
    db.transaction(() => {
      db.exec("DELETE FROM pdpp_records");
      throw Error("rollback");
    })(),
  ).toThrow();
  expect(token()).toBe(two);
  db.exec("DELETE FROM pdpp_records");
  expect(token()).not.toBe(two);
  expect(token()).not.toBe(zero);
  record();
  expect(token()).not.toBe(one);
});
it("aborts overflow even under outer conflict policies", () => {
  record();
  db.exec("UPDATE legacy_scope_stream_revisions SET revision=9007199254740991");
  const before = token();
  expect(() =>
    db.exec("UPDATE OR IGNORE pdpp_records SET data='null'"),
  ).toThrow();
  expect(token()).toBe(before);
  expect(db.prepare("SELECT data FROM pdpp_records").pluck().get()).toBe("{}");
});
it.each(["pdpp_record_arrival", "pdpp_stream_completion"])(
  "tracks %s inserts, identity updates and removals",
  (table) => {
    const start = token();
    if (table === "pdpp_record_arrival")
      db.exec("INSERT INTO pdpp_record_arrival VALUES ('i','a','key',1,1)");
    else
      db.exec(
        "INSERT INTO pdpp_stream_completion(instance,stream,method,generation,source_collected_at,write_seq,live_count) VALUES ('i','a','test',1,'2026-01-01',1,0)",
      );
    const added = token();
    expect(added).not.toBe(start);
    const beforeB = token("b");
    db.exec(`UPDATE ${table} SET stream='b'`);
    expect(token()).not.toBe(added);
    expect(token("b")).not.toBe(beforeB);
    const updated = token("b");
    db.exec(`DELETE FROM ${table}`);
    expect(token("b")).not.toBe(updated);
  },
);
it.each([
  "pdpp_blobs",
  "pdpp_blob_bytes",
  "pdpp_replica_received_bytes",
  "pdpp_replica_pending_bytes",
  "pdpp_binary_manifests",
  "pdpp_binary_chunks",
])("invalidates shared references on %s changes", (table) => {
  ensureReplicaSchema(db);
  db.exec(
    "CREATE TABLE IF NOT EXISTS pdpp_replica_pending_bytes(batch_id TEXT,blob_id TEXT,bytes BLOB,PRIMARY KEY(batch_id,blob_id))",
  );
  installLegacyScopeDependencies(db);
  record();
  record("b", "blob", "j");
  const unrelated = token("unrelated");
  let previous = token();
  const shared = token("b", "j");
  const inserts: Record<string, string> = {
    pdpp_blobs: "INSERT INTO pdpp_blobs VALUES ('blob','text/plain',1,'hash')",
    pdpp_blob_bytes:
      "INSERT INTO pdpp_blobs VALUES ('blob','text/plain',1,'hash'); INSERT INTO pdpp_blob_bytes VALUES ('blob',X'01')",
    pdpp_replica_received_bytes:
      "INSERT INTO pdpp_replica_received_bytes VALUES ('blob',X'01')",
    pdpp_replica_pending_bytes:
      "INSERT INTO pdpp_replica_pending_bytes VALUES ('batch','blob',X'01')",
    pdpp_binary_manifests:
      "INSERT INTO pdpp_binary_manifests VALUES ('canonical','blob',1)",
    pdpp_binary_chunks:
      "INSERT INTO pdpp_binary_chunks VALUES ('canonical','blob',0,X'01')",
  };
  db.exec(inserts[table]!);
  expect(token()).not.toBe(previous);
  expect(token("b", "j")).not.toBe(shared);
  previous = token();
  db.exec(`UPDATE ${table} SET blob_id=blob_id`);
  expect(token()).not.toBe(previous);
  previous = token();
  db.exec(`DELETE FROM ${table}`);
  expect(token()).not.toBe(previous);
  expect(token("unrelated")).toBe(unrelated);
});
it("invalidates batch custody and quarantine without record clocks", () => {
  ensureReplicaSchema(db);
  db.exec(
    "CREATE TABLE pdpp_replica_pending_batches(id TEXT PRIMARY KEY,state TEXT); CREATE TABLE pdpp_replica_pending_bytes(batch_id TEXT,blob_id TEXT,bytes BLOB,PRIMARY KEY(batch_id,blob_id))",
  );
  installLegacyScopeDependencies(db);
  record();
  db.exec(
    `INSERT INTO pdpp_binary_manifests VALUES ('pending','["batch","blob"]',1); INSERT INTO pdpp_replica_pending_batches VALUES ('batch','pending')`,
  );
  let previous = token();
  db.exec("DELETE FROM pdpp_replica_pending_batches");
  expect(token()).not.toBe(previous);
  previous = token();
  db.exec("INSERT INTO pdpp_replica_quarantined_keys VALUES ('i',1,'a','key')");
  expect(token()).not.toBe(previous);
  previous = token();
  db.exec("DELETE FROM pdpp_replica_quarantined_keys");
  expect(token()).not.toBe(previous);
  const plan = db
    .prepare(
      "EXPLAIN QUERY PLAN SELECT DISTINCT instance,stream FROM pdpp_records WHERE blob_id='blob'",
    )
    .all();
  expect(JSON.stringify(plan)).toContain("idx_pdpp_records_blob_id");
});
it("tracks binding reset and deletion without erasing revision rows", () => {
  const before = token();
  db.exec(
    "INSERT INTO pdpp_instance_binding(instance,method,generation,reset_clock) VALUES ('i','oura',1,0)",
  );
  const inserted = token();
  expect(inserted).not.toBe(before);
  db.exec(
    "UPDATE pdpp_instance_binding SET generation=2,reset_clock=1 WHERE instance='i'",
  );
  const reset = token();
  expect(reset).not.toBe(inserted);
  db.exec("DELETE FROM pdpp_instance_binding WHERE instance='i'");
  expect(token()).not.toBe(reset);
  expect(token()).not.toBe(before);
});
it.each([
  "pdpp_replica_quarantined_connections",
  "pdpp_replica_integrity_fences",
  "pdpp_replica_binding_conflicts",
])("tracks %s and descriptor eligibility across instances", (table) => {
  ensureReplicaSchema(db);
  db.exec(
    "CREATE TABLE pdpp_replica_view(instance TEXT,stream TEXT,record_key TEXT,blob_id TEXT)",
  );
  installLegacyScopeDependencies(db);
  record("a", "shared", "j");
  db.exec(
    "INSERT INTO pdpp_replica_view VALUES ('i','fallback','key','shared')",
  );
  let previous = token("a", "j");
  const values =
    table === "pdpp_replica_integrity_fences"
      ? "('i',1)"
      : table === "pdpp_replica_binding_conflicts"
        ? "('i','conflict','{}')"
        : "('i')";
  db.exec(`INSERT INTO ${table} VALUES ${values}`);
  expect(token("a", "j")).not.toBe(previous);
  if (table === "pdpp_replica_binding_conflicts") return;
  previous = token("a", "j");
  db.exec(`DELETE FROM ${table}`);
  expect(token("a", "j")).not.toBe(previous);
});
it("invalidates descriptors, pending byte custody and binary namespace moves", () => {
  ensureReplicaSchema(db);
  db.exec(
    "CREATE TABLE pdpp_replica_view(instance TEXT,stream TEXT,record_key TEXT,blob_id TEXT); CREATE TABLE pdpp_replica_pending_batches(id TEXT PRIMARY KEY,state TEXT);CREATE TABLE pdpp_replica_pending_bytes(batch_id TEXT,blob_id TEXT,bytes BLOB,PRIMARY KEY(batch_id,blob_id))",
  );
  installLegacyScopeDependencies(db);
  record();
  for (const statement of [
    "INSERT INTO pdpp_replica_view VALUES ('j','fallback','key','blob')",
    "UPDATE pdpp_replica_view SET stream='other'",
    "DELETE FROM pdpp_replica_view",
    "INSERT INTO pdpp_replica_pending_bytes VALUES ('batch','blob',X'00')",
    "INSERT INTO pdpp_replica_pending_batches VALUES ('batch','pending')",
    "UPDATE pdpp_replica_pending_batches SET state='confirmed'",
    "DELETE FROM pdpp_replica_pending_batches",
    `INSERT INTO pdpp_binary_chunks VALUES ('pending','["batch","blob"]',0,X'00')`,
    `UPDATE pdpp_binary_chunks SET namespace='received',blob_id='blob'`,
    `DELETE FROM pdpp_binary_chunks`,
  ]) {
    const before = token();
    db.exec(statement);
    expect(token(), statement).not.toBe(before);
  }
});

it("keeps durable counters across two handles, rollback and reopen", () => {
  const dir = mkdtempSync("/home/tnunamak/.tmp/listing-dependencies-");
  const path = join(dir, "index.db");
  const writer = new Database(path);
  const first = createSqliteRecordStore(writer);
  const second = new Database(path);
  try {
    const before = read(second, "i", ["a"]);
    writer.exec(
      "INSERT INTO pdpp_records(instance,stream,record_key,data,version,emitted_at) VALUES ('i','a','key','{}',1,'2026-01-01')",
    );
    const inserted = read(second, "i", ["a"]);
    expect(inserted).not.toBe(before);
    writer.transaction(() => {
      try {
        writer.transaction(() => {
          writer.exec("DELETE FROM pdpp_records");
          throw Error("savepoint");
        })();
      } catch {
        /* outer transaction can still commit */
      }
    })();
    expect(read(second, "i", ["a"])).toBe(inserted);
    second.exec("DELETE FROM pdpp_records");
    expect(read(writer, "i", ["a"])).not.toBe(inserted);
  } finally {
    second.close();
    first.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
it("rolls back a failed v17 migration without advancing schema", () => {
  const old = new Database(":memory:");
  createSqliteRecordStore(old);
  old.exec(
    "DROP TABLE legacy_scope_stream_revisions; DROP TABLE legacy_scope_instance_revisions; UPDATE pdpp_schema_version SET version=16; CREATE TABLE legacy_scope_instance_revisions(broken TEXT)",
  );
  try {
    expect(() => createSqliteRecordStore(old)).toThrow();
    expect(
      old.prepare("SELECT version FROM pdpp_schema_version").pluck().get(),
    ).toBe(16);
    expect(
      old
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE name='legacy_scope_stream_revisions'",
        )
        .get(),
    ).toBeUndefined();
  } finally {
    old.close();
  }
});
