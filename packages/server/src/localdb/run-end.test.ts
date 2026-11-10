import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { checkRunFence } from "../../../core/src/localdb/fence.js";
import { decideReplace } from "../../../core/src/localdb/replace.js";
import type { EndRequest } from "../../../core/src/stream-sync/intake.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

vi.mock("../../../core/src/localdb/fence.js", () => ({
  checkRunFence: vi.fn(),
}));
vi.mock("../../../core/src/localdb/replace.js", () => ({
  decideReplace: vi.fn(),
}));

const dirs: string[] = [];
const databases: SqlDriver[] = [];
beforeEach(() => {
  vi.mocked(checkRunFence).mockReset().mockResolvedValue([]);
  vi.mocked(decideReplace).mockReset().mockReturnValue(false);
});
afterEach(async () => {
  vi.restoreAllMocks();
  for (const db of databases.splice(0)) await db.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

async function fresh(complete = 1) {
  const dir = mkdtempSync(join(process.cwd(), ".run-end-test-"));
  dirs.push(dir);
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  databases.push(driver);
  const db = await openLocalDb(driver, {
    owner: "0xAbC",
    network: "moksha",
    deviceId: "run-end-test",
  });
  await db.batch([
    {
      sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES ('c1', 'example', '', 1, 'active')",
    },
    {
      sql: `INSERT INTO stream_state
          (connection_id, stream, primary_key, semantics, incremental,
           profile_key, profile_version, complete, head_version, head_generation)
          VALUES ('c1', 's', '["id"]', 'mutable_state', 1, 'example', '1.0.0', ?, ?, 1)`,
      params: [complete, complete],
    },
  ]);
  let serial = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {} as LocalSyncDeps["registry"],
    blobs: {} as LocalSyncDeps["blobs"],
    keys: {} as LocalSyncDeps["keys"],
    signer: {} as LocalSyncDeps["signer"],
    logger: { info() {}, warn() {} },
    now: () => 100,
    newOp: () => `operation-${++serial}`,
  };
  return { db, store: createRunEndStore(deps) };
}

// The intake sibling is interface-only here. Seed its durable outputs instead.
async function begin(
  db: SqlDriver,
  runId: string,
  start: number,
  end: number,
  o = 10,
) {
  await db.batch([
    {
      sql: `INSERT INTO runs
          (run_id, connection_id, o, generation, artifact_version, collection_mode, state, last_batch)
          VALUES (?, 'c1', ?, 1, '1.0.0', 'incremental', 'collecting', 0)`,
      params: [runId, o],
    },
    {
      sql: `INSERT INTO run_streams
          (run_id, stream, delete_snapshot, primary_key, profile_key, profile_version, full_read)
          VALUES (?, 's', 0, '["id"]', 'example', '1.0.0', 1)`,
      params: [runId],
    },
    ...Array.from({ length: Math.max(0, end - start + 1) }, (_, index) => {
      const n = start + index;
      return {
        sql: "INSERT INTO run_rows (run_id, stream, pk_hash, record_key, body, body_sha256) VALUES (?, 's', ?, ?, ?, ?)",
        params: [runId, `hash-${n}`, `r${n}`, "{}", `digest-${n}`],
      };
    }),
  ]);
}

const request = (
  outcome: EndRequest["outcome"],
  checkpoint = false,
): EndRequest => ({
  outcome,
  coveredStreams: ["s"],
  lastBatch: 0,
  ...(checkpoint ? { checkpointCandidate: { s: "cursor" } } : {}),
});
const keys = async (db: SqlDriver) =>
  (
    await db.query<{ record_key: string }>(
      "SELECT record_key FROM records WHERE connection_id = 'c1' AND stream = 's' ORDER BY length(record_key), record_key",
    )
  ).map((row) => row.record_key);
const checkpoint = async (db: SqlDriver) =>
  (
    await db.query<{ checkpoint: string | null }>(
      "SELECT checkpoint FROM connections WHERE connection_id = 'c1'",
    )
  )[0]!.checkpoint;

describe("run end", () => {
  it("EndResult table", async () => {
    const cases = [
      { name: "failed", outcome: "failed", rows: 1, expected: "aborted" },
      { name: "cancelled", outcome: "cancelled", rows: 1, expected: "aborted" },
      { name: "abort", outcome: "failed", rows: 1, expected: "aborted" },
      { name: "fenced", outcome: "succeeded", rows: 1, expected: "discarded" },
      { name: "merged", outcome: "succeeded", rows: 1, expected: "queued" },
      {
        name: "checkpoint",
        outcome: "succeeded",
        rows: 0,
        expected: "checkpoint_only",
      },
      {
        name: "empty",
        outcome: "succeeded",
        rows: 0,
        expected: "no_checkpoint",
      },
    ] as const;
    for (const row of cases) {
      const { db, store } = await fresh();
      await begin(db, row.name, 1, row.rows);
      vi.mocked(checkRunFence).mockResolvedValue(
        row.name === "fenced"
          ? [{ stream: "s", trip: "stream_deleted_after_start" }]
          : [],
      );
      if (row.name === "fenced") {
        await db.batch([
          {
            sql: "UPDATE connections SET checkpoint = 'old-cursor' WHERE connection_id = 'c1'",
          },
        ]);
      }
      if (row.name === "abort") {
        // abort has a void API, but shares the failed/cancelled cleanup path.
        await expect(store.abort(row.name, "failed")).resolves.toBeUndefined();
        expect(
          await db.query("SELECT decision, reason FROM run_streams"),
          row.name,
        ).toEqual([{ decision: "discarded", reason: "failed" }]);
      } else {
        expect(
          await store.end(
            row.name,
            request(row.outcome, row.name === "checkpoint"),
          ),
          row.name,
        ).toEqual({ result: row.expected, updateRequired: false });
      }
      expect(await db.query("SELECT state FROM runs"), row.name).toEqual([
        { state: "ended" },
      ]);
      expect(
        await db.query("SELECT COUNT(*) AS n FROM run_rows"),
        row.name,
      ).toEqual([{ n: 0 }]);
      expect(await keys(db), row.name).toEqual(
        row.name === "merged" ? ["r1"] : [],
      );
      if (row.name === "fenced") {
        expect(await checkpoint(db)).toBeNull();
        expect(
          await db.query("SELECT needs_full, complete FROM stream_state"),
        ).toEqual([{ needs_full: 1, complete: 0 }]);
      }
      if (row.name === "checkpoint") {
        expect(JSON.parse((await checkpoint(db))!)).toEqual({ s: "cursor" });
      }
    }
  });

  it("retry-pending-keeps-progress", async () => {
    const { db, store } = await fresh(0);
    const first = Array.from({ length: 50 }, (_, index) => `r${index + 1}`);
    await begin(db, "run-A", 1, 50);
    const batches = vi.spyOn(db, "batch");
    // Even a replacement verdict cannot turn a retry into a full replacement.
    vi.mocked(decideReplace).mockReturnValue(true);
    expect(
      await store.end("run-A", {
        outcome: "retry_pending",
        coveredStreams: ["s"],
        provenFullStreams: ["s"],
        checkpointCandidate: { s: "C50" },
        lastBatch: 0,
      }),
    ).toEqual({ result: "queued", updateRequired: false });
    const endBatch = batches.mock.calls.at(-1)![0];
    expect(
      endBatch.some((statement) =>
        statement.sql.includes("INSERT INTO records"),
      ),
    ).toBe(true);
    expect(
      endBatch.some((statement) =>
        statement.sql.includes("UPDATE connections SET checkpoint"),
      ),
    ).toBe(true);
    expect(await keys(db)).toEqual(first);
    expect(await db.query("SELECT complete FROM stream_state")).toEqual([
      { complete: 0 },
    ]);
    expect(
      await db.query("SELECT replace FROM run_streams WHERE run_id = 'run-A'"),
    ).toEqual([{ replace: 0 }]);
    expect(decideReplace).not.toHaveBeenCalled();

    // Model a producer resuming from the persisted cursor, not a replay of A.
    const resume = JSON.parse((await checkpoint(db))!) as { s: string };
    expect(resume.s).toBe("C50");
    const next = Number(resume.s.slice(1)) + 1;
    await begin(db, "run-B", next, 60, 20);
    const received = await db.query<{ record_key: string }>(
      "SELECT record_key FROM run_rows WHERE run_id = 'run-B' ORDER BY record_key",
    );
    expect(received).toHaveLength(10);
    expect(received.every((row) => !first.includes(row.record_key))).toBe(true);
    vi.mocked(decideReplace).mockReturnValue(false);
    expect(
      await store.end("run-B", {
        outcome: "succeeded",
        coveredStreams: ["s"],
        checkpointCandidate: { s: "C60" },
        lastBatch: 0,
      }),
    ).toEqual({ result: "queued", updateRequired: false });
    expect(await keys(db)).toEqual(
      Array.from({ length: 60 }, (_, index) => `r${index + 1}`),
    );
    const counts = await db.query<{ record_key: string; n: number }>(
      `SELECT record_key, COUNT(*) AS n FROM record_changes
         WHERE connection_id = 'c1' AND stream = 's' AND origin = 'local'
         GROUP BY record_key ORDER BY length(record_key), record_key`,
    );
    expect(counts.filter((row) => first.includes(row.record_key))).toEqual(
      first.map((record_key) => ({ record_key, n: 1 })),
    );
    expect(await db.query("SELECT COUNT(*) AS n FROM run_rows")).toEqual([
      { n: 0 },
    ]);
    expect(await db.query("SELECT COUNT(*) AS n FROM incoming")).toEqual([
      { n: 0 },
    ]);
  });

  it("refused run never visible", async () => {
    const { db, store } = await fresh();
    await db.batch([
      {
        sql: "UPDATE stream_state SET floor_version = '2.0.0' WHERE connection_id = 'c1' AND stream = 's'",
      },
    ]);
    await begin(db, "old-version", 1, 1);
    expect(await store.end("old-version", request("succeeded", true))).toEqual({
      result: "no_checkpoint",
      updateRequired: true,
    });
    expect(await db.query("SELECT decision, reason FROM run_streams")).toEqual([
      { decision: "refused", reason: "connector_update_required" },
    ]);
    expect(await db.query("SELECT COUNT(*) AS n FROM run_rows")).toEqual([
      { n: 0 },
    ]);
    expect(await keys(db)).toEqual([]);
    expect(await db.query("SELECT COUNT(*) AS n FROM record_changes")).toEqual([
      { n: 0 },
    ]);
    expect(await checkpoint(db)).toBeNull();
    expect(await db.query("SELECT floor_version FROM stream_state")).toEqual([
      { floor_version: "2.0.0" },
    ]);
  });
});
