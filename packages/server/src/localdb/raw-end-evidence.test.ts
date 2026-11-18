import { afterEach, expect, it } from "vitest";
import {
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { readRawRecordEvidence } from "../../../core/src/localdb/raw-end-evidence.js";
import { normalizeRawEnd } from "../../../core/src/stream-sync/normalize-raw-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "evidence",
  });
  drivers.push(db);
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns) VALUES('c','fixture','')",
    },
    {
      sql: "INSERT INTO runs(run_id,connection_id,o,artifact_version,collection_mode,state) VALUES('run','c',1,'1','full_refresh','collecting')",
    },
  ]);
  return db;
}
async function capture(db: SqlDriver) {
  const counts = await db.query<{
    stream: string;
    upserts: number;
    deletes: number;
  }>(
    "SELECT stream,SUM(op='upsert') AS upserts,SUM(op='delete') AS deletes FROM run_rows WHERE run_id='run' GROUP BY stream",
  );
  return readRawRecordEvidence(db, "run", counts);
}
const body = (recordsEmitted: number, count: number) => ({
  wireDialect: "connector-end-evidence/1",
  lastBatch: -1,
  selectedStreams: ["A", "B", "empty"],
  done: { status: "succeeded", recordsEmitted },
  errors: [],
  checkpoints: {},
  preflightExcludedStreams: [],
  detailCoverage: {},
  invalidDetailCoverageStreams: [],
  wholeStreamEvidence: ["A", "empty"].map((stream) => ({
    stream,
    report: {
      considered: stream === "A" ? count : 0,
      covered: stream === "A" ? count : 0,
    },
  })),
});
const begin = {
  selectedStreams: ["A", "B", "empty"],
  streams: Object.fromEntries(
    ["A", "B", "empty"].map((s) => [
      s,
      {
        mode: "full_refresh" as const,
        fullRead: true,
        coverageStrategy: "full_inventory" as const,
      },
    ]),
  ),
};
it("preserves empty streams, final folds, repeated events and orphan ledger history", async () => {
  const db = await fixture();
  const insert = (stream: string, key: string, op: string) => ({
    sql: "INSERT OR REPLACE INTO run_rows(run_id,stream,pk_hash,record_key,body,body_sha256,op,pk_values) VALUES('run',?,?,?,'{}','digest',?,?)",
    params: [stream, key, key, op, JSON.stringify([key])],
  });
  await db.batch([
    insert("A", "one", "delete"),
    insert("A", "one", "upsert"),
    insert("A", "one", "upsert"),
    insert("A", "two", "delete"),
    insert("B", "orphan", "delete"),
    { sql: "DELETE FROM run_rows WHERE stream='B'" },
  ]);
  const evidence = await capture(db);
  expect(Object.keys(evidence).sort()).toEqual(["A", "B"]);
  const end = normalizeRawEnd(body(5, 2), begin, evidence);
  expect(end.provenFullStreams).toEqual(["A", "empty"]);
  expect(end.streams.A).toMatchObject({
    liveRecord: true,
    explicitDelete: true,
  });
  expect(end.streams.B).toMatchObject({
    liveRecord: false,
    explicitDelete: true,
  });
  expect(end.streams.empty).toMatchObject({
    liveRecord: false,
    explicitDelete: false,
  });
  expect(
    normalizeRawEnd(body(5, 3), begin, evidence).provenFullStreams,
  ).toEqual(["empty"]);
  expect(() => normalizeRawEnd(body(4, 2), begin, evidence)).toThrow(
    /record count/,
  );
  await db.batch([
    {
      sql: "UPDATE run_record_evidence SET stream='unselected' WHERE stream='B'",
    },
  ]);
  const unselected = await capture(db);
  expect(() => normalizeRawEnd(body(5, 2), begin, unselected)).toThrow(
    /unselected/,
  );
});
it("rejects event totals outside safe integers", async () => {
  const db = await fixture();
  await db.batch([
    {
      sql: "INSERT INTO run_record_evidence VALUES('run','A','key','[]',0,9007199254740991,1)",
    },
  ]);
  expect(() => normalizeRawEnd(body(0, 0), begin, {})).not.toThrow();
  const evidence = await capture(db);
  expect(() => normalizeRawEnd(body(0, 0), begin, evidence)).toThrow(
    /record count/,
  );
});

it("does not parse trigger-owned stored key JSON when deriving count evidence", async () => {
  const db = await fixture();
  await db.batch([
    {
      sql: "INSERT INTO run_rows(run_id,stream,pk_hash,record_key,body,body_sha256,pk_values) VALUES('run','A','key','key','{}','digest','[\"key\"]')",
    },
    { sql: "UPDATE run_record_evidence SET pk_values='malformed'" },
  ]);
  const evidence = await capture(db);
  expect(evidence.A).toEqual({
    liveCount: 1,
    deletedCount: 0,
    everDeleted: false,
    upsertEvents: 1,
    deleteEvents: 0,
  });
  expect(
    normalizeRawEnd(body(1, 1), begin, evidence).provenFullStreams,
  ).toEqual(["A", "empty"]);
});
