import { expect, it } from "vitest";
import Database from "better-sqlite3";
import { ReplicaPendingCapacityError } from "@opendatalabs/personal-server-ts-core/replication/pending-budget";
import { REPLICA_PENDING_BUDGET_MIGRATION } from "./pdpp-replication-sqlite.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";

const emittedAt = "2026-10-20T10:00:00.000Z";
const binding = { method: "collector", generation: 1 };
const declaration = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1.0.0",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const limits = { operations: 1, logicalBytes: 100_000 };
const uniqueJournalOperations = (db: Database.Database) =>
  (
    db
      .prepare(
        `SELECT count(DISTINCT json_extract(operation_json,'$.revision.writerId') || char(0) ||
        json_extract(operation_json,'$.revision.operationId')) AS n FROM pdpp_replica_operations`,
      )
      .get() as { n: number }
  ).n;
const journal = () => {
  const db = new Database(":memory:");
  const store = createReplicaRecordStore(db);
  store.registerConnection({
    instance: "account-a",
    sourceId: "https://source.invalid/declaration",
    method: binding.method,
    label: "Account A",
  });
  const put = (key: string) =>
    store.ingestBatch(
      [
        {
          instance: "account-a",
          stream: "messages",
          key,
          data: { id: key },
          emitted_at: emittedAt,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      binding,
    );
  put("baseline");
  store.replication.beginBaseline({
    owner: "owner",
    declarations: [
      { sourceId: "https://source.invalid/declaration", binding: declaration },
    ],
  });
  put("tail-one");
  put("tail-two");
  return { db, store, put };
};
const resetLedger = (db: Database.Database) => {
  db.exec(`DROP TABLE pdpp_replica_pending_publications;
    DROP TABLE pdpp_replica_pending_released;
    DROP TABLE pdpp_replica_pending_operation_blobs;
    DROP TABLE pdpp_replica_pending_blobs;
    DROP TABLE pdpp_replica_pending_operations;
    DROP TABLE pdpp_replica_pending_budget;`);
  db.exec(REPLICA_PENDING_BUDGET_MIGRATION);
};

it("reconstructs tail debt after baseline retention when tail_cursor is null", () => {
  const { db, store, put } = journal();
  try {
    db.exec(`CREATE TABLE pdpp_transport_state (
      id INTEGER PRIMARY KEY, owner TEXT NOT NULL, writer TEXT NOT NULL,
      baseline_cursor INTEGER NOT NULL, baseline_done INTEGER NOT NULL, tail_cursor INTEGER
    );`);
    const watermark = (
      db
        .prepare("SELECT watermark FROM pdpp_replica_settings WHERE id=1")
        .get() as { watermark: number }
    ).watermark;
    // The engine reaches this cursor after its final baseline retain commit;
    // NULL is the real default tail cursor, which starts at the journal watermark.
    db.prepare(
      "INSERT INTO pdpp_transport_state VALUES (1,'owner','writer',?,1,NULL)",
    ).run(watermark);
    db.exec(`CREATE TABLE pdpp_transport_manifests_out (batch TEXT PRIMARY KEY, state TEXT NOT NULL);
      CREATE TABLE pdpp_transport_operation_outcomes (
        batch TEXT NOT NULL,position INTEGER NOT NULL,operation_json TEXT,
        writer_id TEXT,operation_id TEXT,outcome TEXT,encoding_failed INTEGER NOT NULL DEFAULT 0
      );
      INSERT INTO pdpp_transport_manifests_out VALUES ('old-published','published');`);
    // These are actual captured baseline operation bytes plus the legacy
    // engine's published-manifest survivor rows; no pending-budget rows exist.
    const baseline = db
      .prepare(
        `SELECT o.operation_json FROM pdpp_replica_operations o
      JOIN pdpp_replica_baseline b ON b.sequence=o.sequence`,
      )
      .all() as { operation_json: string }[];
    const insertPublished = db.prepare(
      "INSERT INTO pdpp_transport_operation_outcomes VALUES ('old-published',?,?,?,?,NULL,0)",
    );
    baseline.forEach((row, position) => {
      const operation = JSON.parse(row.operation_json) as {
        revision: { writerId: string; operationId: string };
      };
      insertPublished.run(
        position,
        row.operation_json,
        operation.revision.writerId,
        operation.revision.operationId,
      );
    });
    resetLedger(db);
    const owed = (
      db
        .prepare(
          `SELECT count(DISTINCT json_extract(operation_json,'$.revision.writerId') || char(0) ||
        json_extract(operation_json,'$.revision.operationId')) AS n FROM pdpp_replica_operations
        WHERE sequence>?`,
        )
        .get(watermark) as { n: number }
    ).n;
    expect(owed).toBeGreaterThan(1);
    expect(store.replication.activatePendingBudget(limits).operations).toBe(
      owed,
    );
    expect(() => put("new-write")).toThrow(ReplicaPendingCapacityError);
  } finally {
    db.close();
  }
});

it("reconstructs both baseline and post-watermark tail while baseline retention is active", () => {
  const { db, store, put } = journal();
  try {
    // This is the engine's initial state after baseline setup and before its
    // first retain commit: checkpoint 0, baseline open, no tail page retained.
    db.exec(`CREATE TABLE pdpp_transport_state (
      id INTEGER PRIMARY KEY, owner TEXT NOT NULL, writer TEXT NOT NULL,
      baseline_cursor INTEGER NOT NULL, baseline_done INTEGER NOT NULL, tail_cursor INTEGER
    );
    INSERT INTO pdpp_transport_state VALUES (1,'owner','writer',0,0,NULL);`);
    resetLedger(db);
    const owed = uniqueJournalOperations(db);
    expect(owed).toBeGreaterThan(1);
    expect(store.replication.activatePendingBudget(limits).operations).toBe(
      owed,
    );
    expect(() => put("new-write")).toThrow(ReplicaPendingCapacityError);
  } finally {
    db.close();
  }
});

it("reconstructs journal debt before the lazy transport state table exists", () => {
  const { db, store, put } = journal();
  try {
    // Host settings and captures precede lazy engine schema initialization.
    resetLedger(db);
    const owed = uniqueJournalOperations(db);
    expect(owed).toBeGreaterThan(1);
    expect(store.replication.activatePendingBudget(limits).operations).toBe(
      owed,
    );
    expect(() => put("new-write")).toThrow(ReplicaPendingCapacityError);
  } finally {
    db.close();
  }
});
