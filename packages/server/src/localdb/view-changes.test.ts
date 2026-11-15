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
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import { unwriteRefusedRun } from "../../../core/src/localdb/unwrite.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const STREAMS = ["s0", "s1"];
/** A second namespace of one connector: 16 lowercase hex characters. */
const OTHER_NS = "ffffffffffffffff";
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
    declaredStreams: () => streams,
    olderVersionReads: () => true,
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
  await sync.intake.end(runId, {
    outcome: "succeeded",
    coveredStreams: streams,
    lastBatch: 0,
  });
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
    const { a, before, other, seen } = await twoNamespaces();
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
    await raw.batch([
      ...added.map((t) => ({ sql: `DROP TRIGGER ${t.name}` })),
      { sql: "DROP TABLE view_versions" },
      { sql: `PRAGMA user_version = ${MIGRATIONS.length - 1}` },
    ]);
    const records = await raw.query("SELECT count(*) AS n FROM records");

    const upgraded = await device(s, "a", { driver: raw });
    const { seen } = listen(upgraded); // a baseline over a table the upgrade just made
    await upgraded.views.settled();
    expect(
      await upgraded.db.query("SELECT count(*) AS n FROM records"),
    ).toEqual(records);
    expect(seen).toEqual([]); // the upgrade is not a change
    await upgraded.cycle(); // idle
    await upgraded.views.settled();
    expect(seen).toEqual([]);
    await collect(upgraded, "c0", 2); // a change to a connection with no counter yet
    await upgraded.views.settled();
    expect(new Set(ids(seen).flat())).toEqual(new Set(["pdpp.c0~"]));
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
