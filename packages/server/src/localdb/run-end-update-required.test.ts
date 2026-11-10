import { afterEach, describe, expect, it, vi } from "vitest";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { TEMP_TABLES } from "../../../core/src/localdb/merge.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

// These two dependencies are interface-only at this slice's base.
vi.mock("../../../core/src/localdb/fence.js", () => ({
  checkRunFence: async () => [],
}));
vi.mock("../../../core/src/localdb/replace.js", () => ({
  decideReplace: () => false,
}));

const databases: SqlDriver[] = [];
afterEach(async () => {
  for (const db of databases.splice(0)) await db.close();
});

async function fixture() {
  const db = openBetterSqlite3(":memory:");
  databases.push(db);
  await db.batch(
    [...MIGRATIONS.flat(), ...TEMP_TABLES].map((sql) => ({ sql })),
  );
  await db.batch([
    {
      sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES (?, ?, ?, 1, 'active')",
      params: ["connection", "source", "namespace"],
    },
    {
      sql: "INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental) VALUES (?, ?, ?, 'mutable_state', 1)",
      params: ["connection", "items", '["id"]'],
    },
  ]);
  let op = 0;
  const store = createRunEndStore({
    db,
    queue: connectionQueue(),
    newOp: () => `operation-${++op}`,
  } as LocalSyncDeps);
  const stage = async (runId: string, version: string, observedAt: number) => {
    await db.batch([
      {
        sql: "INSERT INTO runs (run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch) VALUES (?, ?, ?, 1, ?, 'incremental', 'collecting', 0)",
        params: [runId, "connection", observedAt, version],
      },
      {
        sql: "INSERT INTO run_streams (run_id, stream, delete_snapshot, primary_key, profile_key, profile_version) VALUES (?, ?, 0, ?, ?, ?)",
        params: [runId, "items", '["id"]', "source", version],
      },
      ...["shared", runId].map((id) => ({
        sql: "INSERT INTO run_rows (run_id, stream, pk_hash, record_key, body, body_sha256) VALUES (?, ?, ?, ?, ?, ?)",
        params: [
          runId,
          "items",
          id,
          id,
          JSON.stringify({ id, value: runId }),
          `${runId}-${id}`,
        ],
      })),
    ]);
  };
  const end = (runId: string) =>
    store.end(runId, {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: 0,
    });
  const records = () =>
    db.query(
      "SELECT * FROM records WHERE connection_id = ? AND stream = ? ORDER BY pk_hash",
      ["connection", "items"],
    );
  const changes = () => db.query("SELECT * FROM record_changes ORDER BY seq");
  const decision = (runId: string) =>
    db.query("SELECT decision, reason FROM run_streams WHERE run_id = ?", [
      runId,
    ]);
  return { db, stage, end, records, changes, decision };
}

describe("run end update required", () => {
  it("older-version-after-unpublished-newer-run", async () => {
    const f = await fixture();
    await f.stage("run-a", "2", 100);
    expect((await f.end("run-a")).result).toBe("queued");
    const rows = await f.records();
    const changes = await f.changes();
    expect(rows).toHaveLength(2);
    expect(rows.every((row) => row.stamp_r === "run-a")).toBe(true);
    expect(
      await f.db.query("SELECT head_version, floor_version FROM stream_state"),
    ).toEqual([{ head_version: 0, floor_version: "2" }]);

    await f.stage("run-b", "1", 200);
    expect(await f.end("run-b")).toMatchObject({
      result: "no_checkpoint",
      updateRequired: true,
    });
    expect(await f.decision("run-b")).toEqual([
      { decision: "refused", reason: "connector_update_required" },
    ]);
    expect(await f.records()).toEqual(rows);
    expect(await f.changes()).toEqual(changes);
    expect(
      await f.db.query("SELECT run_id FROM run_rows WHERE run_id = ?", [
        "run-b",
      ]),
    ).toEqual([]);
  });

  it("older-version-after-newer-head", async () => {
    const f = await fixture();
    // No local version floor: this refusal must come from the published head.
    await f.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = 1, head_generation = 1, profile_key = ?, profile_version = ?, complete = 1",
        params: ["source", "2"],
      },
      {
        sql: "INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, ?, ?, ?, 100, ?, ?, ?)",
        params: [
          "connection",
          "items",
          "shared",
          "shared",
          "head-run",
          '{"id":"shared","value":"head"}',
          "head-hash",
        ],
      },
    ]);
    const rows = await f.records();
    const head = await f.db.query("SELECT * FROM stream_state");
    const changes = await f.changes();
    expect(rows).toHaveLength(1);
    await f.stage("older-run", "1", 200);
    expect((await f.end("older-run")).updateRequired).toBe(true);
    expect(await f.decision("older-run")).toEqual([
      { decision: "refused", reason: "connector_update_required" },
    ]);
    expect(await f.records()).toEqual(rows);
    expect(await f.db.query("SELECT * FROM stream_state")).toEqual(head);
    expect(await f.changes()).toEqual(changes);
  });

  it("same-or-newer-version", async () => {
    const f = await fixture();
    await f.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = 1, head_generation = 1, profile_key = ?, profile_version = ?, floor_version = ?",
        params: ["source", "2", "2"],
      },
    ]);
    for (const [runId, version, observedAt] of [
      ["same-run", "2", 100],
      ["newer-run", "3", 200],
    ] as const) {
      await f.stage(runId, version, observedAt);
      expect(await f.end(runId)).toMatchObject({
        result: "queued",
        updateRequired: false,
      });
      expect(await f.decision(runId)).toEqual([
        { decision: "publish", reason: null },
      ]);
    }

    // An out-of-order run from the current version needs no app update.
    const rows = await f.records();
    await f.stage("late-run", "3", 150);
    expect((await f.end("late-run")).updateRequired).toBe(false);
    expect(await f.decision("late-run")).toEqual([
      { decision: "refused", reason: "out_of_order" },
    ]);
    expect(await f.records()).toEqual(rows);
  });
});
