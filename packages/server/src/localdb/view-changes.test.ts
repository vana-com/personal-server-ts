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
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const STREAMS = ["s0", "s1"];
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
  /** Reads of the counter table the recorder made on this device. */
  readonly counterReads: () => number;
};

async function device(
  shared: Shared,
  id: string,
  hooks: {
    streams?: string[];
    views?: ViewChangeRecorder;
    blobs?: (inner: StreamSyncBlobs, db: SqlDriver) => StreamSyncBlobs;
  } = {},
): Promise<Device> {
  const streams = hooks.streams ?? STREAMS;
  const raw = await openLocalDb(openBetterSqlite3(":memory:"), {
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
    now: () => 1000,
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
    expect(ids(seen)).toEqual([["pdpp.c0~"]]);
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

  it("(f) an idle cycle, a publish-only cycle and head or watermark moves emit nothing", async () => {
    const { a, b } = await converged("c0");
    await collect(a, "c0", 2); // the view already shows run 2
    const { seen } = listen(a);
    await a.cycle(); // publishes run 2: bookkeeping only
    await b.cycle();
    await a.cycle();
    await a.db.batch([
      {
        sql: "UPDATE stream_state SET head_version = head_version + 1, publish_watermark = publish_watermark + 1",
      },
    ]);
    await a.views.settled();
    await b.views.settled();
    expect(seen).toEqual([]);
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
