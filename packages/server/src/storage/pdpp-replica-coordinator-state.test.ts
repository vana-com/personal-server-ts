import assert from "node:assert/strict";
import { expect, it } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  createReplicaCoordinator,
  type ReplicaPhaseHandler,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicaPhase } from "@opendatalabs/personal-server-ts-core/replication/outcome";
import { initialReplicaWorkState } from "@opendatalabs/personal-server-ts-core/replication/schedule";
import {
  replicaCoordinatorStateContract,
  type ReplicaCoordinatorContractHarness,
} from "@opendatalabs/personal-server-ts-core/replication/coordinator-state.test-utils";
import {
  createSqliteReplicaCoordinatorState,
  REPLICA_COORDINATOR_SCHEMA,
} from "./pdpp-replica-coordinator-state.js";

function open(): ReplicaCoordinatorContractHarness {
  const db = new Database(":memory:");
  // The existing lock layout is unchanged. No registration tables are needed.
  db.exec(`CREATE TABLE pdpp_transport_lock(id INTEGER PRIMARY KEY CHECK(id=1),pid INTEGER NOT NULL,token TEXT NOT NULL);
    CREATE TABLE checkpoints(value TEXT NOT NULL);`);
  db.exec(REPLICA_COORDINATOR_SCHEMA);
  // Forward-open is idempotent on an existing installation.
  db.exec(REPLICA_COORDINATOR_SCHEMA);
  return {
    port: (owner) =>
      createSqliteReplicaCoordinatorState({
        db,
        owner: () => owner,
        atomically: (run) => db.transaction(run).immediate(),
      }),
    acquire: (owner) => {
      db.prepare("INSERT INTO pdpp_transport_lock VALUES(1,1,?)").run(owner);
    },
    recover: (owner) => {
      db.prepare("UPDATE pdpp_transport_lock SET token=? WHERE id=1").run(
        owner,
      );
    },
    checkpoint: (value) => {
      db.prepare("INSERT INTO checkpoints VALUES(?)").run(value);
    },
    receipts: () =>
      (
        db.prepare("SELECT value FROM checkpoints ORDER BY rowid").all() as {
          value: string;
        }[]
      ).map((row) => row.value),
    failCursorWrites: (fail) =>
      db.exec(
        fail
          ? "CREATE TRIGGER fail_cursor BEFORE UPDATE ON pdpp_transport_coordinator BEGIN SELECT RAISE(ABORT,'cursor write failed'); END;"
          : "DROP TRIGGER fail_cursor",
      ),
    close: () => db.close(),
  };
}

replicaCoordinatorStateContract({ test: it, expect }, open);

it("does not accept a callback boundary that forgot to start a transaction", () => {
  const db = new Database(":memory:");
  try {
    db.exec(
      "CREATE TABLE pdpp_transport_lock(id INTEGER PRIMARY KEY,pid INTEGER,token TEXT); INSERT INTO pdpp_transport_lock VALUES(1,1,'a');",
    );
    db.exec(REPLICA_COORDINATOR_SCHEMA);
    const port = createSqliteReplicaCoordinatorState({
      db,
      owner: () => "a",
      atomically: (run) => run(),
    });
    let checkpoints = 0;
    assert.throws(
      () => port.commit(port.load(), { writers: {} }, () => checkpoints++),
      /write transaction/,
    );
    assert.equal(checkpoints, 0);
  } finally {
    db.close();
  }
});

it("closes SQLite before every budget-one turn and keeps exact phase/writer cursors", async () => {
  const directory = mkdtempSync(join(tmpdir(), "replica-cursor-"));
  const path = join(directory, "state.sqlite");
  const trace: {
    served: string;
    version: number;
    nextPhase?: ReplicaPhase;
    writers: Partial<Record<ReplicaPhase, string>>;
  }[] = [];
  try {
    for (let turn = 0; turn < 6; turn++) {
      const db = new Database(path);
      try {
        db.exec(`CREATE TABLE IF NOT EXISTS pdpp_transport_lock(id INTEGER PRIMARY KEY CHECK(id=1),pid INTEGER NOT NULL,token TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS work(phase TEXT,writer TEXT,sequence INTEGER,PRIMARY KEY(phase,writer));
          CREATE TABLE IF NOT EXISTS receipts(phase TEXT,writer TEXT);
          INSERT OR IGNORE INTO work VALUES('retain','A',0),('retain','B',0),('publish','A',0),('import','Z',0);`);
        db.exec(REPLICA_COORDINATOR_SCHEMA);
        const owner = `turn-${turn}`;
        db.prepare("INSERT INTO pdpp_transport_lock VALUES(1,1,?)").run(owner);
        const port = createSqliteReplicaCoordinatorState({
          db,
          owner: () => owner,
          atomically: (run) => db.transaction(run).immediate(),
        });
        const phases = (["retain", "publish", "import"] as const).map(
          (phase): ReplicaPhaseHandler => ({
            phase,
            due(_eligibility, limit) {
              // The Node selectors' ROW_NUMBER + cyclic-after ordering, with a
              // bounded one-row page. B is absent from later A-only pages.
              const rows = db
                .prepare(
                  `SELECT writer FROM (
              SELECT writer,sequence,ROW_NUMBER() OVER (PARTITION BY writer ORDER BY sequence) AS writer_rank
              FROM work WHERE phase=?) WHERE writer_rank<=?
              ORDER BY writer_rank,writer<=?,writer,sequence LIMIT ?`,
                )
                .all(
                  phase,
                  limit.perWriter,
                  limit.after ?? "",
                  limit.total,
                ) as { writer: string }[];
              return rows.map(({ writer }) => ({
                id: writer,
                writer,
                phase,
                state: { ...initialReplicaWorkState },
              }));
            },
            run: async (item) => ({
              outcome: {
                tag: "progress",
                receipt: { phase, key: item.writer },
              },
            }),
            commit(item, attempt, settle) {
              const result = settle(attempt.plan?.() ?? attempt.outcome);
              db.prepare("INSERT INTO receipts VALUES(?,?)").run(
                phase,
                item.writer,
              );
              return result.outcome;
            },
            earliest: () => 0,
          }),
        );
        const report = await createReplicaCoordinator({
          state: port,
          phases,
        }).step({ now: 1000 + turn, budget: { units: 1, bytes: 1 } });
        const cursor = port.load();
        trace.push({
          served: `${report.receipts[0].phase}:${report.receipts[0].key}`,
          version: cursor.version,
          nextPhase: cursor.nextPhase,
          writers: cursor.writers,
        });
        assert.equal(
          (
            db.prepare("SELECT count(*) AS n FROM receipts").get() as {
              n: number;
            }
          ).n,
          cursor.version,
        );
        db.prepare("DELETE FROM pdpp_transport_lock WHERE token=?").run(owner);
      } finally {
        db.close();
      }
    }
    assert.deepEqual(
      trace.map((row) => [row.served, row.nextPhase, row.version]),
      [
        ["retain:A", "publish", 1],
        ["publish:A", "import", 2],
        ["import:Z", "retain", 3],
        ["retain:B", "publish", 4],
        ["publish:A", "import", 5],
        ["import:Z", "retain", 6],
      ],
    );
    assert.deepEqual(trace[5].writers, {
      retain: "B",
      publish: "A",
      import: "Z",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

it("malformed stored/proposed rotation and exhausted revisions fail before checkpoint", () => {
  const db = new Database(":memory:");
  try {
    db.exec(
      "CREATE TABLE pdpp_transport_lock(id INTEGER PRIMARY KEY,pid INTEGER,token TEXT); INSERT INTO pdpp_transport_lock VALUES(1,1,'a'); CREATE TABLE receipts(value TEXT);",
    );
    db.exec(REPLICA_COORDINATOR_SCHEMA);
    const port = createSqliteReplicaCoordinatorState({
      db,
      owner: () => "a",
      atomically: (run) => db.transaction(run).immediate(),
    });
    let checkpoints = 0;
    for (const invalid of [
      "null",
      "[]",
      "{}",
      '{"writers":[]}',
      '{"writers":{"publish":1}}',
      '{"writers":{"unexpected":"x"}}',
      '{"writers":{},"nextPhase":"unexpected"}',
    ]) {
      db.prepare("UPDATE pdpp_transport_coordinator SET rotation_json=?").run(
        invalid,
      );
      assert.throws(() => port.load());
    }
    db.prepare("UPDATE pdpp_transport_coordinator SET rotation_json=?").run(
      '{"writers":{}}',
    );
    const initial = port.load();
    assert.throws(() =>
      port.commit(
        initial,
        { writers: { publish: 1 } } as never,
        () => checkpoints++,
      ),
    );
    assert.deepEqual(port.load(), initial);
    db.prepare("UPDATE pdpp_transport_coordinator SET version=?").run(
      Number.MAX_SAFE_INTEGER,
    );
    assert.throws(
      () => port.commit(port.load(), { writers: {} }, () => checkpoints++),
      RangeError,
    );
    assert.equal(checkpoints, 0);
  } finally {
    db.close();
  }
});

it("a trigger that corrupts the just-written cursor cannot leave a receipt", () => {
  const db = new Database(":memory:");
  try {
    db.exec(
      "CREATE TABLE pdpp_transport_lock(id INTEGER PRIMARY KEY,pid INTEGER,token TEXT); INSERT INTO pdpp_transport_lock VALUES(1,1,'a'); CREATE TABLE receipts(value TEXT);",
    );
    db.exec(REPLICA_COORDINATOR_SCHEMA);
    const port = createSqliteReplicaCoordinatorState({
      db,
      owner: () => "a",
      atomically: (run) => db.transaction(run).immediate(),
    });
    const initial = port.load();
    db.exec(
      "CREATE TRIGGER corrupt_cursor AFTER UPDATE ON pdpp_transport_coordinator BEGIN UPDATE pdpp_transport_coordinator SET rotation_json='{\"writers\":{}}'; END;",
    );
    assert.throws(() =>
      port.commit(
        initial,
        { nextPhase: "import", writers: { publish: "A" } },
        () => db.prepare("INSERT INTO receipts VALUES('lost')").run(),
      ),
    );
    assert.deepEqual(port.load(), initial);
    assert.equal(
      (db.prepare("SELECT count(*) AS n FROM receipts").get() as { n: number })
        .n,
      0,
    );
  } finally {
    db.close();
  }
});
