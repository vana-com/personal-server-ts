// The view-change event: one call per committed write that moved what the
// local database serves, none for a write that moved nothing.
//
// Real SQLite devices share one in-memory registry and blob store. Device A
// collects and publishes; device B is the consumer (the Web tab) whose
// listener is under test. The recorder attaches to each device's driver, so
// the tests drive the engine's own paths (cycle, resolver, intake, importer)
// and `views.settled()` is the only wait: no sleeps.
import { afterEach, describe, expect, it } from "vitest";
import {
  connectionQueue,
  createLocalSync,
  createViewChanges,
  openLocalDb,
  type LocalSync,
  type LocalSyncDeps,
  type SqlDriver,
  type ViewChange,
  type ViewChangeRecorder,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
  type StreamSyncBlobs,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  IMPORT_CHUNK_ROWS,
  importLegacySource,
} from "../../../core/src/localdb/legacy-import.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { unwriteRefusedRun } from "../../../core/src/localdb/unwrite.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const STREAMS = ["s0", "s1"];
/** A second namespace of one connector: 16 lowercase hex characters. */
const OTHER_NS = "ffffffffffffffff";
// These fixtures restore an older on-disk schema before testing migrations.
const dropBootstrapSchema = [
  // A fixture restored to an old version must remove later system-stream
  // schema too; the forward migration still creates each object exactly once.
  ...["insert", "update", "delete"].map((event) => ({
    sql: `DROP TRIGGER system_stream_records_${event}`,
  })),
  { sql: "DROP TRIGGER system_stream_outbox_capacity" },
  ...[
    "instance",
    "outbox",
    "projection",
    "checkpoint",
    "quarantine",
    "changes",
  ].map((table) => ({ sql: `DROP TABLE system_stream_${table}` })),
  ...["insert", "update", "delete"].map((event) => ({
    sql: `DROP TRIGGER records_bootstrap_${event}`,
  })),
  ...["load", "segments", "deletions", "preview"].map((table) => ({
    sql: `DROP TABLE bootstrap_${table}`,
  })),
];
const dropRawEndSchema = [
  { sql: "DROP TRIGGER IF EXISTS run_rows_evidence" },
  { sql: "DROP TABLE IF EXISTS run_record_evidence" },
  { sql: "ALTER TABLE runs DROP COLUMN selected_streams" },
  { sql: "ALTER TABLE runs DROP COLUMN raw_end" },
  // The stream cursor on its way into the log came after.
  { sql: "DROP TRIGGER IF EXISTS connections_checkpoint_cleared" },
  ...["unpublished", "seq", "children", "version", "applied", "write"].map(
    (column) => ({
      sql: `ALTER TABLE stream_state DROP COLUMN cursor_${column}`,
    }),
  ),
];
const dropJoinSchema = [
  { sql: "DROP TABLE IF EXISTS connection_participation" },
];
// Later migrations' indexes on tables the older schema has too.
const dropStampIndexSchema = [
  { sql: "DROP INDEX IF EXISTS log_tombstones_by_stamp" },
  { sql: "DROP INDEX IF EXISTS log_tombstones_by_record_key" },
  { sql: "DROP INDEX IF EXISTS record_changes_by_record_key" },
];
// A later migration's table of the body pieces an erasure left in storage.
const dropRetainedPiecesSchema = [
  { sql: "DROP TABLE IF EXISTS retained_log_pieces" },
  { sql: "DROP TABLE IF EXISTS enumerated_logs" },
  { sql: "DROP TABLE IF EXISTS delete_tombstones" },
];
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

interface Shared {
  registry: MemoryStreamSyncRegistry;
  blobs: StreamSyncBlobs;
}

type Device = LocalSync & {
  readonly db: SqlDriver;
  readonly deps: LocalSyncDeps;
  readonly views: ViewChangeRecorder;
  /** The driver before the recorder wrapped it. */
  readonly raw: SqlDriver;
  /** Reads of the counter table the recorder made on this device. */
  readonly counterReads: () => number;
};

async function device(
  shared: Shared,
  id: string,
  hooks: {
    streams?: string[];
    views?: ViewChangeRecorder;
    /** The device's clock: set `at` to move time between runs. */
    clock?: { at: number };
    /** Open this driver (already holding data) instead of a new database. */
    driver?: SqlDriver;
    blobs?: (inner: StreamSyncBlobs, db: SqlDriver) => StreamSyncBlobs;
  } = {},
): Promise<Device> {
  const streams = hooks.streams ?? STREAMS;
  const raw = await openLocalDb(hooks.driver ?? openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: id,
  });
  let counterReads = 0;
  const query = raw.query.bind(raw);
  raw.query = ((sql: string, params?: never) => {
    if (sql.includes("FROM view_versions")) counterReads += 1;
    return query(sql, params);
  }) as typeof raw.query;
  const views = hooks.views ?? createViewChanges();
  const db = views.attach(raw, { warn: () => {} });
  drivers.push(db);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry: shared.registry,
    blobs: hooks.blobs?.(shared.blobs, db) ?? shared.blobs,
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => hooks.clock?.at ?? 1000,
    newOp: () => `${id}-op-${++op}`,
  };
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: streams.map((name) => ({
        name,
        semantics: "mutable_state" as const,
        primaryKey: ["id"],
      })),
    }),
  });
  return Object.assign(sync, {
    db,
    deps,
    views,
    raw,
    counterReads: () => counterReads,
  });
}

let runs = 0;
/** One full run of `connector`: the rows `row` of each stream, at `version`. */
async function collect(
  sync: LocalSync,
  connector: string,
  version = 1,
  row = 0,
  streams = STREAMS,
) {
  const runId = `run-${++runs}`;
  await sync.intake.begin(runId, {
    connector,
    artifactDigest: connector,
    join: true,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  await sync.intake.batch(runId, {
    batch: 0,
    records: streams.map((stream) => ({
      stream,
      data: { id: `${stream}-${row}`, version },
    })),
  });
  await sync.intake.end(runId, endRequest({ lastBatch: 0, live: streams }));
}

function shared(): Shared {
  return {
    registry: createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry,
    blobs: createMemoryStreamSyncBlobs(),
  };
}

function listen(d: Pick<Device, "views">) {
  const seen: ViewChange[] = [];
  const unsubscribe = d.views.subscribe((c) => seen.push(c));
  return { seen, unsubscribe };
}

const ids = (seen: readonly ViewChange[]) =>
  seen.map((c) => [...c.connectionIds]);
/** At least one event, and every event names exactly this connection. */
const onlyConnection = (seen: readonly ViewChange[], id: string) => {
  expect(seen.length).toBeGreaterThan(0);
  expect(new Set(ids(seen).map((i) => i.join(",")))).toEqual(new Set([id]));
};
const scopeOf = (connector: string, stream: string) =>
  ({
    scope: `pdpp.${connector}.${stream}`,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  }) as const;

/** Both devices hold `connector` active and equal. */
async function converged(connector: string, streams = STREAMS) {
  const s = shared();
  const a = await device(s, "a", { streams });
  const b = await device(s, "b", { streams });
  await collect(a, connector, 1, 0, streams);
  await a.cycle();
  await b.cycle();
  return { s, a, b };
}

/**
 * Everything a reader can see of the local view: the scope listing, the
 * status, the resolver's answer (its cursor names the stream bindings) for
 * one scope per connector, the records with the time each was last seen, and
 * the additions summary (it counts rows by the day they were first seen).
 */
async function visible(d: Device) {
  const scopes = await d.listing.listScopes({ canRead: () => true });
  const status = await d.listing.status();
  const answers: unknown[] = [];
  for (const connector of ["c0", "c1"]) {
    const answer = await d.resolver.resolve(scopeOf(connector, "s0"));
    if ("body" in answer) {
      await answer.body.cancel();
      const { body: _body, ...rest } = answer as Record<string, unknown>;
      answers.push(rest);
    } else answers.push(answer);
  }
  const records: unknown[] = [];
  const connections = await d.db.query<{ connection_id: string }>(
    "SELECT connection_id FROM connections ORDER BY connection_id",
  );
  for (const { connection_id: connectionId } of connections)
    for (const stream of STREAMS) {
      const read = await d.query.listRecords({ connectionId, stream });
      records.push([connectionId, stream, read.records]);
    }
  const additions = await d.history.additions({ timezone: "UTC", days: 7 });
  return JSON.parse(
    JSON.stringify({ scopes, status, answers, records, additions }),
  ) as unknown;
}

/** A second namespace of `from` that serves the same data. */
async function cloneConnection(d: Device, from: string, ns: string) {
  const to = `${from}${ns}`;
  const control = await d.deps.registry.read(from);
  if (!control.found || control.version !== 1)
    throw new Error("Expected an active first-generation fixture control");
  const posted = await d.deps.registry.post({
    ownerAddress: OWNER,
    scope: to,
    dataHash: control.dataHash,
    metadataHash: control.metadataHash,
    expectedVersion: "1",
    signature: "0x00",
  });
  if (posted.kind !== "committed") throw new Error("Fixture control conflict");
  await d.db.batch([
    {
      sql: `INSERT INTO connections (connection_id, connector, ns, generation, control_state, control_version, checkpoint, label, deleted_at)
            SELECT ?, connector, ?, generation, control_state, control_version, checkpoint, label, deleted_at FROM connections WHERE connection_id = ?`,
      params: [to, ns, from],
    },
    {
      sql: `INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental, profile_key, profile_version, complete, needs_full, floor_version, floor_o, floor_r, last_delete_version, head_version, head_generation, head_data_hash, head_blob, publish_watermark)
            SELECT ?, stream, primary_key, semantics, incremental, profile_key, profile_version, complete, needs_full, floor_version, floor_o, floor_r, last_delete_version, head_version, head_generation, head_data_hash, head_blob, publish_watermark FROM stream_state WHERE connection_id = ?`,
      params: [to, from],
    },
    {
      sql: `INSERT INTO stream_versions (connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind)
            SELECT ?, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind FROM stream_versions WHERE connection_id = ?`,
      params: [to, from],
    },
    {
      sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, seen_o, seen_r, body_bytes)
            SELECT ?, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o, seen_o, seen_r, body_bytes FROM records WHERE connection_id = ?`,
      params: [to, from],
    },
  ]);
}

describe("view changes", () => {
  it("(a) a remote apply under a pending local write, with compaction in the same cycle, names the connection", async () => {
    const { a, b } = await converged("c0", ["s0"]);
    await collect(b, "c0", 1, 1, ["s0"]); // pending local write, not published
    await collect(a, "c0", 1, 2, ["s0"]); // a remote change to another row
    await a.cycle();
    const { seen } = listen(b);
    await b.cycle(); // applies a's row, publishes b's, compacts the log
    await b.views.settled();
    const compacted = await b.db.query<{ n: number }>(
      "SELECT count(*) AS n FROM record_changes",
    );
    expect(compacted[0]!.n).toBe(0); // the attribution a log read would need is gone
    onlyConnection(seen, "pdpp.c0~"); // the apply and the publish each move the view
  });

  it("(b) a resolver that installs a newer head, or a tombstone, emits", async () => {
    const { a, b } = await converged("c0");
    const { seen } = listen(b);
    await collect(a, "c0", 2);
    await a.cycle();
    const newer = await b.resolver.resolve(scopeOf("c0", "s0"));
    if ("body" in newer) await newer.body.cancel();
    await b.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    seen.length = 0;
    await a.deleter.requestConnectionDelete("c0");
    await a.cycle();
    await b.resolver.resolve(scopeOf("c0", "s0"));
    await b.views.settled();
    onlyConnection(seen, "pdpp.c0~");
  });

  it("(c) an intake begin that purges a deleted connection and then rejects emits", async () => {
    const { a, b } = await converged("c0");
    await a.deleter.requestConnectionDelete("c0");
    await a.cycle();
    const { seen } = listen(b);
    await expect(
      b.intake.begin("rejected-run", {
        connector: "c0",
        artifactDigest: "c0",
        join: true,
        wantFull: true,
        owner: { address: OWNER, leaseId: null },
      }),
    ).rejects.toThrow();
    await b.views.settled();
    const left = await b.db.query("SELECT 1 AS x FROM records LIMIT 1");
    expect(left).toEqual([]); // the purge did commit
    onlyConnection(seen, "pdpp.c0~");
  });

  it("(d) an import that fails after committed batches emits", async () => {
    const s = shared();
    const a = await device(s, "a");
    await a.db.batch([
      {
        sql: "INSERT OR IGNORE INTO connections (connection_id, connector, ns, generation, control_state) VALUES ('connection', 'fixture', 'known', 1, 'active')",
      },
    ]);
    const { seen } = listen(a);
    let pass = 0;
    const source: ImportSource = {
      source: "fixture-revision",
      owner: OWNER,
      network: "test",
      revision: "revision",
      target: {
        connectionId: "connection",
        connector: "fixture",
        stream: "items",
        primaryKey: ["id"],
        semantics: "mutable_state",
        incremental: true,
      },
      exclusions: [],
      async *records() {
        pass += 1;
        for (let i = 0; i < IMPORT_CHUNK_ROWS + 1; i++) {
          // The second pass (the merge) fails after its first chunk landed.
          if (pass === 2 && i === IMPORT_CHUNK_ROWS)
            throw new Error("source down");
          yield { id: `row-${i}`, text: "x" };
        }
      },
    };
    await expect(
      importLegacySource(a.deps, createImportLedger(a.db), source),
    ).rejects.toThrow("source down");
    await a.views.settled();
    const landed = await a.db.query<{ n: number }>(
      "SELECT count(*) AS n FROM records WHERE connection_id = 'connection'",
    );
    expect(landed[0]!.n).toBeGreaterThan(0);
    expect(ids(seen)).toEqual([["connection"]]);
  });

  it("(e) a subscriber taken before any write hears the first local run", async () => {
    const a = await device(shared(), "a");
    const { seen } = listen(a); // before the first commit, with no cycle running
    await collect(a, "c0");
    await a.views.settled();
    expect(seen.length).toBeGreaterThan(0);
    expect(new Set(ids(seen).flat())).toEqual(new Set(["pdpp.c0~"]));
  });

  it("(f) an idle cycle, a bookkeeping-only move and a same-value write emit nothing", async () => {
    const { a, b } = await converged("c0");
    await collect(a, "c0", 2);
    await a.cycle(); // publishes run 2: the head moves, which is visible
    const before = await visible(a); // reading may install a head: settle first
    await a.views.settled();
    const { seen } = listen(a);
    await b.cycle();
    await a.cycle(); // nothing to do
    await a.db.batch([
      // Publish bookkeeping no read shows.
      {
        sql: "UPDATE stream_state SET publish_watermark = publish_watermark + 1, floor_o = 5, needs_full = 0",
      },
      // Writes that keep the stored value.
      {
        sql: "UPDATE stream_state SET head_version = head_version, complete = complete, profile_version = profile_version, last_delete_version = last_delete_version",
      },
      {
        sql: "UPDATE records SET stamp_o = stamp_o, body_sha256 = body_sha256",
      },
      {
        sql: "UPDATE stream_versions SET observed_at = observed_at, complete = complete",
      },
      // The same version row written again, as a repeated apply does.
      {
        sql: "INSERT OR REPLACE INTO stream_versions SELECT * FROM stream_versions",
      },
      {
        sql: "UPDATE connections SET control_version = control_version, generation = generation",
      },
    ]);
    await a.views.settled();
    expect(seen).toEqual([]);
    expect(await visible(a)).toEqual(before);
  });

  it("(f2) publishing a run moves the head a reader sees, and emits", async () => {
    const { a } = await converged("c0");
    await collect(a, "c0", 2);
    const before = await visible(a);
    await a.views.settled();
    const { seen } = listen(a);
    await a.cycle();
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await visible(a)).not.toEqual(before);
  });

  it("(i) a run that sees the same body at a later time moves the seen time a reader sees, and emits", async () => {
    const clock = { at: 1000 };
    const a = await device(shared(), "a", { clock });
    await collect(a, "c0");
    await a.cycle();
    const before = await visible(a);
    await a.views.settled();
    const { seen } = listen(a);
    clock.at = 5000;
    await collect(a, "c0"); // same rows, same bodies, not yet published
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await visible(a)).not.toEqual(before); // emittedAt and updatedAt moved
  });

  it("(j) un-writing that later run moves the seen time back, and emits", async () => {
    const clock = { at: 1000 };
    const a = await device(shared(), "a", { clock });
    await collect(a, "c0");
    await a.cycle();
    const first = await visible(a);
    clock.at = 5000;
    const later = `run-${runs + 1}`;
    await collect(a, "c0");
    expect(await visible(a)).not.toEqual(first);
    await a.views.settled();
    const { seen } = listen(a);
    for (const stream of STREAMS)
      await unwriteRefusedRun(a.deps, {
        connectionId: "pdpp.c0~",
        stream,
        runId: later,
        reason: "out_of_order",
      });
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await visible(a)).toEqual(first);
  });

  /** Two namespaces of one connector; the second is listening-ready and silent. */
  async function twoNamespaces() {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    await cloneConnection(a, "pdpp.c0~", OTHER_NS);
    const before = await visible(a);
    await a.views.settled();
    return { a, before, other: `pdpp.c0~${OTHER_NS}`, ...listen(a) };
  }
  const moveHead = {
    "a replaced version row": `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind)
      SELECT connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at + 10, complete, kind FROM stream_versions WHERE connection_id LIKE '%ffffffffffffffff'`,
    "an updated version row": `UPDATE stream_versions SET observed_at = observed_at + 10 WHERE connection_id LIKE '%ffffffffffffffff'`,
  };
  for (const [what, sql] of Object.entries(moveHead))
    it(`(k) ${what} that only changes which namespace a scope serves emits, though no record moved`, async () => {
      const { a, before, other, seen } = await twoNamespaces();
      const records = await a.db.query(
        "SELECT stamp_o, body_sha256 FROM records",
      );
      await a.db.batch([{ sql }]);
      await a.views.settled();
      expect(ids(seen).flat()).toContain(other);
      expect(
        await a.db.query("SELECT stamp_o, body_sha256 FROM records"),
      ).toEqual(records);
      expect(await visible(a)).not.toEqual(before); // the other namespace now answers
    });

  it("(k) deleting a version row, as an eviction does, emits", async () => {
    const { a, other, seen } = await twoNamespaces();
    await a.db.batch([
      {
        sql: "UPDATE stream_versions SET observed_at = observed_at + 1 WHERE connection_id LIKE '%ffffffffffffffff'",
      },
    ]);
    const before = await visible(a);
    await a.views.settled();
    seen.length = 0;
    await a.db.batch([
      {
        sql: "DELETE FROM stream_versions WHERE connection_id LIKE '%ffffffffffffffff'",
      },
    ]);
    await a.views.settled();
    expect(ids(seen).flat()).toContain(other);
    expect(await visible(a)).not.toEqual(before); // the connection no longer serves
  });

  it("(l) a change of the profile binding a stream is read through emits, with completeness unchanged", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    const before = await visible(a);
    await a.views.settled();
    const { seen } = listen(a);
    await a.db.batch([
      {
        sql: "UPDATE stream_state SET profile_version = 'other' WHERE stream = 's0'",
      },
    ]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await visible(a)).not.toEqual(before); // the resolver cursor names the profile
  });

  it("(o) a change of the day a record was first seen moves the additions a reader sees, and emits", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    const before = await visible(a);
    await a.views.settled();
    const { seen } = listen(a);
    await a.db.batch([
      {
        sql: "UPDATE records SET first_o = ? WHERE stream = 's0'",
        params: [Date.now()],
      },
    ]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await visible(a)).not.toEqual(before);
  });

  // One write by itself, so each trigger is the only reason the event fires.
  const alone: readonly {
    what: string;
    setup?: string;
    sql: string;
    id: string;
  }[] = [
    {
      what: "a record deleted",
      sql: "DELETE FROM records WHERE stream = 's0'",
      id: "pdpp.c0~",
    },
    {
      what: "a connection added",
      sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES ('pdpp.c9~', 'c9', '', 1, 'active')",
      id: "pdpp.c9~",
    },
    {
      what: "a connection removed",
      setup:
        "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES ('pdpp.c9~', 'c9', '', 1, 'active')",
      sql: "DELETE FROM connections WHERE connection_id = 'pdpp.c9~'",
      id: "pdpp.c9~",
    },
    {
      what: "a connection's control state changed",
      sql: "UPDATE connections SET control_version = control_version + 1",
      id: "pdpp.c0~",
    },
    {
      what: "a stream added",
      sql: "INSERT INTO stream_state (connection_id, stream, primary_key, semantics, incremental) VALUES ('pdpp.c0~', 's9', '[\"id\"]', 'mutable_state', 1)",
      id: "pdpp.c0~",
    },
    {
      what: "a stream removed",
      sql: "DELETE FROM stream_state WHERE stream = 's1'",
      id: "pdpp.c0~",
    },
    ...[
      "primary_key = '[\"other\"]'",
      "profile_key = 'other'",
      "complete = 1 - complete",
      "last_delete_version = last_delete_version + 1",
      "head_version = head_version + 1",
      "head_generation = head_generation + 1",
      "head_data_hash = 'other'",
      "head_blob = 'other'",
    ].map((set) => ({
      what: `a stream's ${set.split(" ")[0]} changed`,
      sql: `UPDATE stream_state SET ${set} WHERE stream = 's0'`,
      id: "pdpp.c0~",
    })),
  ];
  it.each(alone)("(p) $what emits", async ({ setup, sql, id }) => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    if (setup) await a.db.batch([{ sql: setup }]);
    await a.views.settled();
    const { seen } = listen(a);
    await a.db.batch([{ sql }]);
    await a.views.settled();
    expect(ids(seen).flat()).toEqual([id]);
  });

  async function versioned() {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    const before = await visible(a);
    await a.views.settled();
    return { a, before, ...listen(a) };
  }

  // Neither column reaches a reader any more: `head_format` named how a
  // per-stream head was encoded, and `record_count` was reported only by the
  // older-version listing. A change of either only has to emit.
  const versionColumns = {
    record_count: "record_count + 7",
    head_format: "head_format + 7",
  };
  for (const [column, next] of Object.entries(versionColumns)) {
    it(`(p) a change of ${column} on a version row emits`, async () => {
      for (const how of ["an update", "a replacement"]) {
        const { a, seen } = await versioned();
        await a.db.batch([
          {
            sql:
              how === "an update"
                ? `UPDATE stream_versions SET ${column} = ${next}`
                : `INSERT OR REPLACE INTO stream_versions (connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind)
                   SELECT connection_id, stream, version, generation, head_blob, ${column === "head_format" ? next : "head_format"}, ${column === "record_count" ? next : "record_count"}, observed_at, complete, kind FROM stream_versions`,
          },
        ]);
        await a.views.settled();
        onlyConnection(seen, "pdpp.c0~");
      }
    });
  }

  it("(p) the same version rows written again, by update or by replacement, emit nothing", async () => {
    const { a, before, seen } = await versioned();
    await a.db.batch([
      {
        sql: "UPDATE stream_versions SET record_count = record_count, head_format = head_format",
      },
      {
        sql: "INSERT OR REPLACE INTO stream_versions SELECT * FROM stream_versions",
      },
    ]);
    await a.views.settled();
    expect(seen).toEqual([]);
    expect(await visible(a)).toEqual(before);
  });

  const intent = (id: string) =>
    `INSERT OR REPLACE INTO delete_intents(connector, delete_id, intent) VALUES ('c0', '${id}', '{}')`;

  /**
   * The records a grant read sees per connection. A connection under a delete
   * intent serves none.
   */
  const listed = async (d: Device) => {
    const seen = async (connector: string) => {
      const records = d.recordsFor(() => ({ connector, namespace: "" }));
      const page = await records.listRecords({
        connectionId: connector,
        stream: "s0",
      });
      return page.records.length;
    };
    return { c0: await seen("c0"), c1: await seen("c1") };
  };

  it("(q) a delete intent that starts to exist hides the connection, and emits; replacing it is silent; clearing it restores the connection, and emits", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await collect(a, "c1");
    await a.cycle();
    const shown = await listed(a);
    expect(shown.c0).toBeGreaterThan(0);
    await a.views.settled();
    const { seen } = listen(a);

    await a.db.batch([{ sql: intent("first") }]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~"); // c1 has no intent and is not named
    const hidden = await listed(a);
    expect(hidden).toEqual({ c0: 0, c1: shown.c1 }); // the reader no longer sees c0

    seen.length = 0;
    await a.db.batch([{ sql: intent("second") }]); // the same connector's intent, replaced
    await a.views.settled();
    expect(seen).toEqual([]);
    expect(await listed(a)).toEqual(hidden);

    await a.db.batch([
      { sql: "DELETE FROM delete_intents WHERE connector = 'c0'" },
    ]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await listed(a)).toEqual(shown);
  });

  it("(q) a purge that waits after its intent is saved has already told the listener", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    expect((await listed(a)).c0).toBeGreaterThan(0);
    await a.views.settled();
    const { seen } = listen(a);
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    // Another job holds the connection's queue, so the purge cannot start.
    const holding = a.deps.queue.run("pdpp.c0~", "purge", () => held);
    const requested = a.deleter.requestConnectionDelete("c0");
    for (let turn = 0; turn < 10_000; turn++) {
      const rows = await a.raw.query("SELECT 1 FROM delete_intents");
      if (rows.length > 0) break;
      await Promise.resolve();
    }
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~"); // heard while the purge has not run
    expect((await listed(a)).c0).toBe(0);
    release();
    await holding;
    await requested;
  });

  /** The delete a person requested, run to its end: purged, tombstoned, cleared. */
  async function deleted(d: Device, connector: string) {
    await d.deleter.requestConnectionDelete(connector);
    await d.deleter.resumeDeletes();
    expect(await d.raw.query("SELECT 1 FROM delete_intents")).toEqual([]);
  }
  const stateOf = async (d: Device, id: string) =>
    (
      await d.raw.query<{ control_state: string }>(
        "SELECT control_state FROM connections WHERE connection_id = ?",
        [id],
      )
    )[0]?.control_state;

  it("(q) a connection the purge has deleted is unreadable with or without an intent, so an intent that starts or ends to exist is silent", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await collect(a, "c1");
    await a.cycle();
    const shown = await listed(a);
    await deleted(a, "c0"); // the purge marks it deleted; the landing clears the intent
    expect(await stateOf(a, "pdpp.c0~")).toBe("deleted");
    await a.views.settled();
    const { seen } = listen(a);
    const gone = await listed(a);
    expect(gone).toEqual({ c0: 0, c1: shown.c1 });

    await a.db.batch([{ sql: intent("late") }]); // an intent on a deleted connection
    await a.views.settled();
    expect(seen).toEqual([]);
    await a.db.batch([
      { sql: "DELETE FROM delete_intents WHERE connector = 'c0'" },
    ]); // the clear after a purge has nothing to restore
    await a.views.settled();
    expect(seen).toEqual([]);
    expect(await listed(a)).toEqual(gone);
    expect(await stateOf(a, "pdpp.c0~")).toBe("deleted");
  });

  it("(q) an intent on a connector with one deleted and one active connection names the active one only", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    await cloneConnection(a, "pdpp.c0~", OTHER_NS);
    await a.db.batch([
      {
        sql: "UPDATE connections SET control_state = 'deleted' WHERE connection_id = ?",
        params: [`pdpp.c0~${OTHER_NS}`],
      },
    ]);
    await a.views.settled();
    const { seen } = listen(a);
    await a.db.batch([{ sql: intent("first") }]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
  });

  it("(q) an intent hides what a reader sees without changing the connection; a clear restores it; once a read has marked the connection deleted, a clear restores nothing", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    const shown = await listed(a);
    expect(shown.c0).toBeGreaterThan(0);
    await a.views.settled();
    const { seen } = listen(a);

    // Hidden by the intent alone: the connection row is untouched.
    await a.db.batch([{ sql: intent("first") }]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~");
    expect(await stateOf(a, "pdpp.c0~")).toBe("active");
    seen.length = 0;
    await a.db.batch([
      { sql: "DELETE FROM delete_intents WHERE connector = 'c0'" },
    ]);
    await a.views.settled();
    onlyConnection(seen, "pdpp.c0~"); // restored, and told
    expect(await listed(a)).toEqual(shown);

    // The same intent, but a resolver read meets it first. That read is the
    // production path (apply.ts), and it marks the connection deleted.
    await a.db.batch([{ sql: intent("second") }]);
    await a.views.settled();
    seen.length = 0;
    const answer = await a.resolver.resolve(scopeOf("c0", "s0"));
    if ("body" in answer) await answer.body.cancel();
    await a.views.settled();
    expect(await stateOf(a, "pdpp.c0~")).toBe("deleted");
    onlyConnection(seen, "pdpp.c0~"); // the mark is a change of its own
    seen.length = 0;
    await a.db.batch([
      { sql: "DELETE FROM delete_intents WHERE connector = 'c0'" },
    ]);
    await a.views.settled();
    expect(seen).toEqual([]); // nothing came back, so nothing is announced
    expect(await stateOf(a, "pdpp.c0~")).toBe("deleted");
    expect((await listed(a)).c0).toBe(0);
  });

  it("(q) a purge that fails keeps its intent and its hide signal, and the rolled-back writes tell nothing", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.cycle();
    expect((await listed(a)).c0).toBeGreaterThan(0);
    const rows = async () =>
      (
        await a.raw.query<{ n: number }>(
          "SELECT count(*) AS n FROM records WHERE connection_id = 'pdpp.c0~'",
        )
      )[0]!.n;
    const before = await rows();
    expect(before).toBeGreaterThan(0);
    // The purge's last write fails, after its deletes of the records ran.
    await a.raw.batch([
      {
        sql: `CREATE TRIGGER fail_purge BEFORE UPDATE ON connections
              WHEN NEW.control_state = 'deleted'
              BEGIN SELECT RAISE(ABORT, 'purge failed'); END`,
      },
    ]);
    await a.views.settled();
    const { seen } = listen(a);
    await expect(a.deleter.requestConnectionDelete("c0")).rejects.toThrow();
    await a.views.settled();
    expect(
      (await a.raw.query("SELECT 1 FROM delete_intents")).length,
    ).toBeGreaterThan(0); // the intent is kept
    expect(await rows()).toBe(before); // the purge batch rolled back
    expect(await stateOf(a, "pdpp.c0~")).toBe("active");
    expect((await listed(a)).c0).toBe(0); // still hidden by the intent
    expect(seen.length).toBe(1); // the hide, and nothing from the rolled-back writes
    expect([...seen[0]!.connectionIds]).toEqual(["pdpp.c0~"]);
  });

  it("(m) a listener that makes one idempotent write after each event is heard once", async () => {
    const a = await device(shared(), "a");
    await collect(a, "c0");
    await a.views.settled();
    let heard = 0;
    const writes: Promise<unknown>[] = [];
    a.views.subscribe(() => {
      heard += 1;
      if (heard > 20) return; // a loop must fail the assertion, not hang the run
      writes.push(
        a.db.batch([
          {
            sql: "UPDATE records SET stamp_o = stamp_o, stamp_r = stamp_r, body_sha256 = body_sha256, seen_o = seen_o, first_o = first_o",
          },
          {
            sql: "UPDATE stream_state SET complete = complete, head_version = head_version, head_blob = head_blob",
          },
        ]),
      );
    });
    await a.db.batch([
      { sql: "UPDATE records SET body_sha256 = 'changed' WHERE stream = 's0'" },
    ]);
    await a.views.settled();
    await Promise.all(writes);
    await a.views.settled();
    expect(heard).toBe(1);
    expect(writes).toHaveLength(1);
  });

  it("(n) a populated database on the previous schema upgrades silently and then hears every change", async () => {
    const s = shared();
    const old = await device(s, "a");
    await collect(old, "c0");
    await old.cycle();
    await collect(old, "c1");
    await old.cycle();
    const raw = old.raw;
    drivers.splice(drivers.indexOf(old.db), 1); // the reopened device owns the close
    // Put the file back as the previous build left it: no counters, no triggers.
    const added = await raw.query<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'view\\_%' ESCAPE '\\'",
    );
    expect(added.length).toBeGreaterThan(0);
    // The view counters came with one migration; the build before it had none
    // of that migration or of any after it (the log's tables are later).
    const viewMigration = MIGRATIONS.findIndex((statements) =>
      statements.some((sql) => sql.includes("CREATE TABLE view_versions")),
    );
    expect(viewMigration).toBeGreaterThan(0);
    await raw.batch([
      ...added.map((t) => ({ sql: `DROP TRIGGER ${t.name}` })),
      { sql: "DROP TABLE view_versions" },
      // Later migrations add the apply_partial column and the log's tables.
      { sql: "ALTER TABLE connections DROP COLUMN apply_partial" },
      // A later migration's trigger can sit on a table that stays.
      ...MIGRATIONS.slice(viewMigration + 1)
        .flat()
        .flatMap((sql) => /^CREATE TRIGGER (\w+)/.exec(sql)?.[1] ?? [])
        .map((trigger) => ({ sql: `DROP TRIGGER IF EXISTS ${trigger}` })),
      // Likewise a later migration's index on a table that stays.
      ...MIGRATIONS.slice(viewMigration + 1)
        .flat()
        .flatMap(
          (sql) => /^CREATE (?:UNIQUE )?INDEX (\w+)/.exec(sql)?.[1] ?? [],
        )
        .map((index) => ({ sql: `DROP INDEX IF EXISTS ${index}` })),
      // A table built under another name and renamed onto one that stays
      // (the rowid `records`) has no table of its own to drop.
      ...MIGRATIONS.slice(viewMigration + 1)
        .flat()
        .flatMap((sql) => /^CREATE TABLE (\w+)/.exec(sql)?.[1] ?? [])
        .filter(
          (table) =>
            !MIGRATIONS.flat().some((sql) =>
              sql.startsWith(`ALTER TABLE ${table} RENAME TO `),
            ),
        )
        .map((table) => ({ sql: `DROP TABLE IF EXISTS ${table}` })),
      // Publish while collecting adds columns after the view counters too.
      { sql: "ALTER TABLE runs DROP COLUMN admitting" },
      { sql: "ALTER TABLE run_streams DROP COLUMN unadmitted" },
      { sql: "ALTER TABLE connections DROP COLUMN tombstone_wm_o" },
      { sql: "ALTER TABLE connections DROP COLUMN tombstone_wm_r" },
      // The log's typed deletion keys are columns on tables that stay.
      { sql: "ALTER TABLE run_rows DROP COLUMN pk_values" },
      // A later migration's partial index names the column dropped next.
      { sql: "DROP INDEX IF EXISTS record_changes_untyped_deletes" },
      { sql: "ALTER TABLE record_changes DROP COLUMN pk_values" },
      { sql: "ALTER TABLE stream_state DROP COLUMN key_types" },
      // The batch ordinal that orders two bodies of a key at one stamp.
      { sql: "ALTER TABLE records DROP COLUMN stamp_n" },
      // The stream meta the log said at each local version.
      { sql: "ALTER TABLE stream_versions DROP COLUMN primary_key" },
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_key" },
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_version" },
      { sql: "ALTER TABLE record_changes DROP COLUMN publish_blocked_reason" },
      { sql: "ALTER TABLE run_streams DROP COLUMN publish_blocked_reason" },
      ...dropRawEndSchema,
      ...dropJoinSchema,
      { sql: `PRAGMA user_version = ${viewMigration}` },
    ]);
    const records = await raw.query("SELECT count(*) AS n FROM records");

    const upgraded = await device(s, "a", { driver: raw });
    const { seen } = listen(upgraded); // a baseline over a table the upgrade just made
    await upgraded.views.settled();
    expect(
      await upgraded.db.query("SELECT count(*) AS n FROM records"),
    ).toEqual(records);
    expect(seen).toEqual([]); // the upgrade is not a change
    // The previous build kept no log state, so the first cycle reads the
    // registry's log again: that is a sync, and it is heard. The next one is idle.
    await upgraded.cycle();
    await upgraded.views.settled();
    seen.length = 0;
    await upgraded.cycle(); // idle
    await upgraded.views.settled();
    expect(seen).toEqual([]);
    await collect(upgraded, "c0", 2); // a change to a connection with no counter yet
    await upgraded.views.settled();
    expect(new Set(ids(seen).flat())).toEqual(new Set(["pdpp.c0~"]));
  });

  it("(o) a populated database at the version that made records a rowid table upgrades to the last migration with its log intact", async () => {
    const s = shared();
    const old = await device(s, "a");
    await collect(old, "c0");
    await old.cycle();
    await collect(old, "c1");
    await old.cycle();
    const raw = old.raw;
    drivers.splice(drivers.indexOf(old.db), 1); // the reopened device owns the close
    // The build whose last migration rebuilt `records` as a rowid table. Its
    // database is at that migration's version; the log's later migrations
    // come after it.
    const rowidVersion =
      MIGRATIONS.findIndex((statements) =>
        statements.some((sql) => sql.includes("CREATE TABLE records_rowid")),
      ) + 1;
    expect(rowidVersion).toBeGreaterThan(0);
    expect(rowidVersion).toBeLessThan(MIGRATIONS.length);
    const before = {
      records: await raw.query(
        "SELECT connection_id, stream, pk_hash, body FROM records ORDER BY connection_id, stream, pk_hash",
      ),
      log: await raw.query("SELECT * FROM log_state ORDER BY connection_id"),
    };
    expect(before.records.length).toBeGreaterThan(0);
    expect(before.log.length).toBe(2);
    // Put the file back as that build left it. It still created the tables of
    // the per-stream head path and the consumed-head columns, and its version
    // rows had no stream meta.
    await raw.batch([
      ...dropRawEndSchema,
      ...dropJoinSchema,
      ...dropBootstrapSchema,
      ...dropStampIndexSchema,
      ...dropRetainedPiecesSchema,
      { sql: "ALTER TABLE stream_versions DROP COLUMN primary_key" },
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_key" },
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_version" },
      // The mark of a stream's changes came after that build too.
      { sql: "DROP TRIGGER stream_change_marks_ai" },
      { sql: "DROP TABLE stream_change_marks" },
      {
        sql: `CREATE TABLE head_parts (
  connection_id TEXT NOT NULL, stream TEXT NOT NULL,
  prefix TEXT NOT NULL CHECK (prefix NOT GLOB '*[^01]*' AND length(prefix) <= 16),
  seq INTEGER NOT NULL, part_hash TEXT NOT NULL, bytes INTEGER NOT NULL, count INTEGER NOT NULL,
  PRIMARY KEY (connection_id, stream, prefix, seq)) WITHOUT ROWID`,
      },
      {
        sql: `CREATE TABLE publish_spool (
  attempt TEXT NOT NULL, connection_id TEXT NOT NULL, pk_hash TEXT NOT NULL,
  stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL, first_o INTEGER,
  body_sha256 TEXT NOT NULL, body_bytes INTEGER NOT NULL, body TEXT NOT NULL,
  PRIMARY KEY (attempt, pk_hash)) WITHOUT ROWID`,
      },
      {
        sql: "CREATE INDEX publish_spool_by_connection ON publish_spool(connection_id)",
      },
      {
        sql: `CREATE TABLE log_replay (
  connection_id TEXT PRIMARY KEY, position INTEGER NOT NULL, last_ref TEXT) WITHOUT ROWID`,
      },
      {
        sql: "INSERT INTO head_parts VALUES ('pdpp.c0~', 's0', '0', 0, '0x00', 1, 1)",
      },
      { sql: "INSERT INTO log_replay VALUES ('pdpp.c0~', 1, NULL)" },
      {
        sql: "ALTER TABLE stream_state ADD COLUMN consumed_version INTEGER NOT NULL DEFAULT 0",
      },
      {
        sql: "ALTER TABLE stream_state ADD COLUMN consumed_generation INTEGER",
      },
      { sql: "ALTER TABLE stream_state ADD COLUMN consumed_data_hash TEXT" },
      { sql: "ALTER TABLE record_changes DROP COLUMN publish_blocked_reason" },
      { sql: "ALTER TABLE run_streams DROP COLUMN publish_blocked_reason" },
      { sql: `PRAGMA user_version = ${rowidVersion}` },
    ]);

    const upgraded = await device(s, "a", { driver: raw });
    expect(await upgraded.db.query("PRAGMA user_version")).toEqual([
      { user_version: MIGRATIONS.length },
    ]);
    const tables = (
      await upgraded.db.query<{ name: string; sql: string }>(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table'",
      )
    ).reduce<Record<string, string>>(
      (all, t) => ({ ...all, [t.name]: t.sql }),
      {},
    );
    // The head path's tables are gone; the rowid records table and the log's
    // tables are both there.
    for (const name of ["head_parts", "publish_spool", "log_replay"])
      expect(tables[name]).toBeUndefined();
    expect(tables.records).toBeDefined();
    expect(tables.records).not.toMatch(/WITHOUT ROWID/);
    for (const name of ["log_state", "log_tombstones", "log_keyed_pending"])
      expect(tables[name]).toBeDefined();
    expect(
      await upgraded.db.query(
        "SELECT connection_id, stream, pk_hash, body FROM records ORDER BY connection_id, stream, pk_hash",
      ),
    ).toEqual(before.records);
    expect(
      await upgraded.db.query("SELECT * FROM log_state ORDER BY connection_id"),
    ).toEqual(before.log);
    // Every version row gets the stream meta it had no column for.
    expect(
      await upgraded.db.query(
        `SELECT COUNT(*) AS n FROM stream_versions v JOIN stream_state s
           ON s.connection_id = v.connection_id AND s.stream = v.stream
         WHERE v.primary_key IS NOT s.primary_key
            OR v.profile_key IS NOT s.profile_key
            OR v.profile_version IS NOT s.profile_version`,
      ),
    ).toEqual([{ n: 0 }]);
    expect(
      await upgraded.db.query("SELECT COUNT(*) AS n FROM stream_versions"),
    ).not.toEqual([{ n: 0 }]);

    // The upgraded device publishes a change through its log, and another
    // device reads it.
    await upgraded.cycle();
    await collect(upgraded, "c0", 2);
    await upgraded.cycle();
    const b = await device(s, "b");
    await b.cycle();
    const shown = await b.query.listRecords({
      connectionId: "pdpp.c0~",
      stream: "s0",
    });
    expect(JSON.parse(shown.records[0]!.body)).toMatchObject({ version: 2 });
  });

  it("(p) a migration whose statement fails leaves the file at its version with no table changed", async () => {
    const s = shared();
    const old = await device(s, "a");
    await collect(old, "c0");
    await old.cycle();
    const raw = old.raw;
    // The migration that adds the stream meta to the version rows, in three
    // statements. The file goes back to the version before it, and it already
    // has the third column, so the third statement fails after the first two
    // ran in the same batch.
    const metaMigration = MIGRATIONS.findIndex((statements) =>
      statements.some((sql) =>
        sql.includes("ALTER TABLE stream_versions ADD COLUMN profile_key"),
      ),
    );
    expect(MIGRATIONS[metaMigration]).toHaveLength(3);
    await raw.batch([
      ...dropRawEndSchema,
      ...dropJoinSchema,
      ...dropBootstrapSchema,
      ...dropStampIndexSchema,
      ...dropRetainedPiecesSchema,
      { sql: "ALTER TABLE stream_versions DROP COLUMN primary_key" },
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_key" },
      // A later migration made the mark of a stream's changes.
      { sql: "DROP TRIGGER stream_change_marks_ai" },
      { sql: "DROP TABLE stream_change_marks" },
      // A later migration recorded why eligible work waits.
      { sql: "ALTER TABLE record_changes DROP COLUMN publish_blocked_reason" },
      { sql: "ALTER TABLE run_streams DROP COLUMN publish_blocked_reason" },
      { sql: `PRAGMA user_version = ${metaMigration}` },
    ]);
    const state = async () => ({
      version: await raw.query("PRAGMA user_version"),
      schema: await raw.query(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name",
      ),
      columns: await raw.query("PRAGMA table_info(stream_versions)"),
      versions: await raw.query(
        "SELECT * FROM stream_versions ORDER BY connection_id, stream, version",
      ),
      records: await raw.query(
        "SELECT connection_id, stream, pk_hash, body FROM records ORDER BY connection_id, stream, pk_hash",
      ),
      log: await raw.query("SELECT * FROM log_state ORDER BY connection_id"),
    });
    const before = await state();
    expect(before.versions.length).toBeGreaterThan(0);
    expect(
      (before.columns as { name: string }[]).map((c) => c.name),
    ).not.toContain("primary_key");

    await expect(migrate(raw)).rejects.toThrow(/duplicate column/);
    expect(await state()).toEqual(before);
    expect(before.version).toEqual([{ user_version: metaMigration }]);

    // The same file upgrades once the third column is not there.
    await raw.batch([
      { sql: "ALTER TABLE stream_versions DROP COLUMN profile_version" },
    ]);
    await migrate(raw);
    expect(await raw.query("PRAGMA user_version")).toEqual([
      { user_version: MIGRATIONS.length },
    ]);
  });

  it("(g) a listener that syncs or reads does not loop, and sees the commit", async () => {
    const { a, b } = await converged("c0");
    await collect(a, "c0", 2);
    await a.cycle();
    const calls: Promise<unknown>[] = [];
    let heard = 0;
    b.views.subscribe(() => {
      heard += 1;
      calls.push(
        b.cycle(),
        b.query.listRecords({ connectionId: "pdpp.c0~", stream: "s0" }),
      );
    });
    await b.cycle();
    await b.views.settled();
    const afterApply = heard;
    expect(afterApply).toBeGreaterThan(0);
    // Each listener call ran one idle cycle and one read: none of them moved
    // the view, so none of them is heard.
    await Promise.all(calls);
    await b.views.settled();
    expect(heard).toBe(afterApply);
    const shown = await b.query.listRecords({
      connectionId: "pdpp.c0~",
      stream: "s0",
    });
    expect(JSON.parse(shown.records[0]!.body)).toMatchObject({ version: 2 });
  });

  it("(h) close clears, a reopened database takes a new baseline, and listeners carry over", async () => {
    const s = shared();
    const views = createViewChanges();
    const first = await device(s, "a", { views });
    const { seen } = listen({ views });
    await collect(first, "c0");
    await views.settled();
    const before = seen.length;
    expect(before).toBeGreaterThan(0);
    await first.db.close();
    drivers.splice(drivers.indexOf(first.db), 1);
    const second = await device(s, "b", { views }); // same recorder, new database
    await views.settled();
    expect(seen).toHaveLength(before); // attaching is a baseline, not a change
    await collect(second, "c1");
    await views.settled();
    expect(seen.length).toBeGreaterThan(before);
    expect(new Set(ids(seen.slice(before)).flat())).toEqual(
      new Set(["pdpp.c1~"]),
    );
  });

  it("with no listener nothing reads the counters after the baseline", async () => {
    const a = await device(shared(), "a");
    await a.views.settled();
    const baseline = a.counterReads();
    expect(baseline).toBe(1);
    await collect(a, "c0");
    await a.views.settled();
    expect(a.counterReads()).toBe(baseline);
    const { seen } = listen(a); // takes a fresh baseline, silently
    await a.views.settled();
    expect(a.counterReads()).toBe(baseline + 1);
    expect(seen).toEqual([]);
  });

  it("unsubscribe stops delivery, and a throwing listener does not hurt the others", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    const first: ViewChange[] = [];
    const second: ViewChange[] = [];
    const off = b.views.subscribe((c) => first.push(c));
    b.views.subscribe(() => {
      throw new Error("listener bug");
    });
    b.views.subscribe((c) => second.push(c));
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    await b.views.settled();
    expect(first.length).toBeGreaterThanOrEqual(1);
    expect(second).toHaveLength(first.length);
    off();
    off(); // a second call is harmless
    const delivered = first.length;
    await collect(a, "c0", 2);
    await a.cycle();
    await b.cycle();
    await b.views.settled();
    expect(first).toHaveLength(delivered);
    expect(second.length).toBeGreaterThan(delivered);
  });

  it("an event carries connection ids only", async () => {
    const s = shared();
    const a = await device(s, "a");
    const b = await device(s, "b");
    const { seen } = listen(b);
    await collect(a, "c0");
    await a.cycle();
    await b.cycle();
    await b.views.settled();
    expect(Object.keys(seen[0]!)).toEqual(["connectionIds"]);
  });
});
