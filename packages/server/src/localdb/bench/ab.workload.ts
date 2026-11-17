// A/B decision dry sample. The fixture is the publisher's actual encrypted
// 198001-row, --runs 64 log, exported by first-load-bench.workload.ts.
import Database from "better-sqlite3";
import {
  bootstrapSchema,
  swapBootstrapRecords,
} from "../../../../core/src/localdb/bootstrap-swap.js";
import { serialize } from "node:v8";
import { createStatementCache } from "../statement-cache.cjs";
import { BootstrapKeys } from "../../../../core/src/localdb/bootstrap-keys.js";
import { createLocalResolver } from "../../../../core/src/localdb/resolve.js";
import { createRecordQuery } from "../../../../core/src/localdb/query.js";
import { partialRowStatement } from "../../../../core/src/localdb/partial-load.js";
import { connectionQueue } from "../../../../core/src/localdb/queue.js";
import assert from "node:assert/strict";
import { createHash, getHashes } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadavg } from "node:os";
import { performance } from "node:perf_hooks";
import { decodeSegment } from "@opendatalabs/personal-server-ts-stream-sync";
import { createStreamSyncKeyPorts } from "../../../../core/src/stream-sync/crypto.js";
import { openLocalDb } from "../../../../core/src/localdb/open.js";
import {
  applyBatch,
  operationStatements,
  prepareOperations,
  streamStateStatement,
} from "../../../../core/src/localdb/log-batch.js";
import {
  BOOTSTRAP_HEAP,
  appendBootstrapRows,
} from "../../../../core/src/localdb/log-bootstrap-stage.js";
import { withOrigin } from "../../../../core/src/localdb/merge.js";
import type { LocalSyncDeps } from "../../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../../core/src/localdb/driver.js";
import { nodeStreamCrypto } from "../../stream-sync/node-stream-crypto.js";

const fixture = process.argv[2]!,
  mode = process.argv[3]!;
assert(["A", "B", "C"].includes(mode));
const manifest = JSON.parse(readFileSync(join(fixture, "index.json"), "utf8"));
assert.equal(manifest.runs, 64);
const out = join(fixture, "decision.db");
for (const suffix of ["", "-journal", "-wal", "-shm"])
  rmSync(out + suffix, { force: true });
const native = new Database(out);
const cache = createStatementCache(native);
native.pragma("page_size=65536");
native.pragma("temp_store=MEMORY");
const raw: SqlDriver = {
  info: {
    host: "web",
    persistent: true,
    sqliteVersion: native.prepare("SELECT sqlite_version() v").get().v,
  },
  async query(sql, params = []) {
    const q = cache.prepare(sql);
    if (q.reader) return q.all(...params) as never;
    q.run(...params);
    return [];
  },
  async batch(statements) {
    const own = !native.inTransaction;
    if (own) native.exec("BEGIN IMMEDIATE");
    try {
      const changes = statements.map((st) => {
        const q = cache.prepare(st.sql);
        return q.reader
          ? (q.all(...(st.params ?? [])), 0)
          : q.run(...(st.params ?? [])).changes;
      });
      if (own) native.exec("COMMIT");
      return { changes };
    } catch (e) {
      if (own && native.inTransaction) native.exec("ROLLBACK");
      throw e;
    }
  },
  async close() {
    native.close();
  },
};
const db = await openLocalDb(raw, {
  owner: "owner",
  network: "test",
  deviceId: "decision",
});
const connectionId = "pdpp.fixture~";
await db.batch([
  {
    sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture','',1,'active',1)",
    params: [connectionId],
  },
]);
const indexes = await db.query<{ name: string; sql: string }>(
  "SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name='records' AND name<>'records_key'",
);
const keys = createStreamSyncKeyPorts(
  `0x${"ab".repeat(64)}1b`,
  nodeStreamCrypto,
);
const io = () =>
  +readFileSync("/proc/self/io", "utf8").match(/^wchar: (\d+)/m)![1]!;
let nextOp = 0,
  peakPayload = 0,
  peakRss = process.memoryUsage().rss,
  peakHeap = 0,
  rows = 0,
  previous = 0;
const queue = connectionQueue();
const deps = {
  db,
  queue,
  progressiveFirstLoad: true,
  logger: { warn() {}, info() {} },
  newOp: () => `op-${++nextOp}`,
} as unknown as LocalSyncDeps;
// An owner read joins the already-running synthetic apply, as in the product.
void queue.run(connectionId, "apply", () => new Promise<void>(() => {}));
const resolver = createLocalResolver(deps, { query: createRecordQuery(db) });
const swapSchema = mode === "C" ? await bootstrapSchema(db) : null;
const keyIndex = new BootstrapKeys(
  db,
  mode === "C"
    ? async (seq) => {
        const [row] = await db.query(
          seq > 0
            ? "SELECT rowid seq,connection_id,stream,pk_hash,'u' kind,1 rank,stamp_o,stamp_r,stamp_n,body_sha256 FROM bootstrap_records WHERE rowid=?"
            : "SELECT -rowid seq,connection_id,stream,pk_hash,'d' kind,rank,stamp_o,stamp_r,0 stamp_n,NULL body_sha256 FROM bootstrap_deletions WHERE rowid=?",
          [Math.abs(seq)],
        );
        return row;
      }
    : undefined,
);
let totalBootstrapRows = 0,
  supersededRows = 0,
  removedKeys = 0,
  opsPerFinalKey = 0;
let lastStageRow = 0,
  keyArrayPeakBytes = 0,
  serializedKeyArrayBytes = 0,
  stagingLookupMs = 0,
  stagingRowReads = 0;
let ownerFirstRowMs = 0;
const mark = () => {
  const m = process.memoryUsage();
  peakRss = Math.max(peakRss, m.rss);
  peakHeap = Math.max(peakHeap, m.heapUsed);
};
const hostBefore = loadavg(),
  w0 = io(),
  t0 = performance.now();
console.log(
  "[start]",
  JSON.stringify({
    mode,
    node: process.version,
    nativeKeccak: getHashes().includes("keccak-256"),
    runs: manifest.runs,
    hostBefore,
    cache: native.pragma("cache_size", { simple: true }),
    page: native.pragma("page_size", { simple: true }),
  }),
);
if (mode !== "C")
  await db.batch(
    indexes
      .filter((i) => i.name !== "records_by_key")
      .map((i) => ({ sql: `DROP INDEX ${i.name}` })),
  );
if (mode === "C") await db.batch([{ sql: swapSchema.table }]);
if (mode === "A") await db.batch([{ sql: BOOTSTRAP_HEAP }]);
let previewMs = 0,
  installStart = 0;
try {
  for (const entry of manifest.entries) {
    const cipher = readFileSync(join(fixture, entry.file));
    const scope = entry.key.slice(0, entry.key.lastIndexOf("/"));
    const clear = await keys.decrypt(scope, cipher);
    const decoded = decodeSegment(clear);
    assert.equal(decoded.kind, "ok");
    const segment = decoded.segment;
    assert.equal(segment.position, previous + 1);
    previous = segment.position;
    const prepared = await prepareOperations(
      segment.streams,
      segment.operations,
    );
    const bodyBytes = prepared.reduce(
      (n, op) => n + (op.kind === "upsert" ? Buffer.byteLength(op.body) : 0),
      0,
    );
    peakPayload = Math.max(
      peakPayload,
      cipher.byteLength + clear.byteLength + bodyBytes,
    );
    mark();
    if (previous === 1) {
      const hash = "0x" + entry.key.slice(entry.key.lastIndexOf("/s-") + 3);
      const identities = segment.streams.map((meta) => ({
        connectionId,
        stream: meta.stream,
        version: 1,
        generation: segment.generation,
        dataHash: hash,
        headBlob: entry.key.slice(entry.key.lastIndexOf("/") + 1),
        observedAt: segment.observedAt,
      }));
      await db.batch(
        segment.streams.flatMap((meta, i) => [
          streamStateStatement(connectionId, meta),
          partialRowStatement(identities[i]!, 0, manifest.entries.length, 0),
        ]),
      );
      await applyBatch(
        deps,
        connectionId,
        segment,
        { dataHash: hash, blobName: identities[0]!.headBlob },
        undefined,
        new Map(
          segment.streams.map((meta, i) => [
            meta.stream,
            {
              begin: true,
              final: false,
              held: [],
              row: {
                head: identities[i]!,
                applied: 1,
                total: manifest.entries.length,
              },
            },
          ]),
        ),
      );
      const owner = await resolver.resolve({
        scope: `pdpp.fixture.${segment.streams[0].stream}`,
        connection: null,
        cursor: null,
        legacyFile: false,
        isOwnerView: true,
      });
      assert.equal(owner.kind, "view");
      const body = await new Response(owner.body).json();
      assert(
        body.data.records.length > 0,
        "preview must be returned by owner resolver",
      );
      assert.equal(body.data.records[0].id.startsWith("m-"), true);
      ownerFirstRowMs = performance.now() - t0;
      previewMs = performance.now() - t0;
      if (mode !== "C") await db.batch([{ sql: "DROP INDEX records_by_key" }]);
      if (mode === "B") native.exec("BEGIN IMMEDIATE");
    }
    if (mode === "A") {
      await db.batch(appendBootstrapRows(connectionId, prepared));
      const staged = await db.query(
        "SELECT seq,connection_id,stream,pk_hash,kind,rank,stamp_o,stamp_r,stamp_n,body_sha256 FROM bootstrap_rows WHERE seq>? ORDER BY seq",
        [lastStageRow],
      );
      for (const row of staged) await keyIndex.add(row);
      lastStageRow = staged.at(-1)?.seq ?? lastStageRow;
      keyArrayPeakBytes = Math.max(keyArrayPeakBytes, keyIndex.keyPayloadBytes);
    } else if (mode === "C") {
      const columns = [
        "connection_id",
        "stream",
        "pk_hash",
        "record_key",
        "stamp_o",
        "stamp_r",
        "stamp_n",
        "body",
        "body_sha256",
        "first_o",
        "body_bytes",
      ];
      native.exec("BEGIN IMMEDIATE");
      const insert = cache.prepare(
        `INSERT INTO bootstrap_records(${columns.join(",")}) VALUES(${columns.map(() => "?").join(",")})`,
      );
      const meta = [];
      for (const op of prepared) {
        if (op.kind === "upsert") {
          const id = Number(
            insert.run(
              connectionId,
              op.stream,
              op.pkHash,
              op.recordKey,
              op.stampO,
              op.stampR,
              op.ordinal,
              op.body,
              op.bodySha256,
              op.firstO,
              Buffer.byteLength(op.body),
            ).lastInsertRowid,
          );
          totalBootstrapRows++;
          meta.push({
            seq: id,
            connection_id: connectionId,
            stream: op.stream,
            pk_hash: op.pkHash,
            kind: "u",
            rank: 1,
            stamp_o: op.stampO,
            stamp_r: op.stampR,
            stamp_n: op.ordinal,
            body_sha256: op.bodySha256,
          });
        } else {
          const entries = op.kind === "complete" ? op.omitted : [op];
          for (const key of entries) {
            const id = Number(
              cache
                .prepare(
                  "INSERT INTO bootstrap_deletions VALUES(?,?,?,?,?,?,?,?,?)",
                )
                .run(
                  connectionId,
                  op.stream,
                  key.pkHash,
                  key.recordKey,
                  op.stampO,
                  op.stampR,
                  op.kind === "delete" ? 2 : 0,
                  segment.position,
                  prepared.indexOf(op),
                ).lastInsertRowid,
            );
            meta.push({
              seq: -id,
              connection_id: connectionId,
              stream: op.stream,
              pk_hash: key.pkHash,
              kind: "d",
              rank: op.kind === "delete" ? 2 : 0,
              stamp_o: op.stampO,
              stamp_r: op.stampR,
              stamp_n: 0,
              body_sha256: null,
            });
          }
        }
      }
      native.exec("COMMIT");
      for (const row of meta) await keyIndex.add(row);
      keyArrayPeakBytes = Math.max(keyArrayPeakBytes, keyIndex.keyPayloadBytes);
    } else {
      const op = deps.newOp();
      await db.batch(
        withOrigin("remote", [
          ...segment.streams.map((meta) =>
            streamStateStatement(connectionId, meta),
          ),
          ...operationStatements(connectionId, op, prepared),
        ]),
      );
    }
    rows += prepared.filter((op) => op.kind === "upsert").length;
    mark();
  }
  installStart = performance.now() - t0;
  if (mode === "A") {
    const groups = await keyIndex.sorted();
    serializedKeyArrayBytes = serialize(groups).byteLength;
    mark();
    native.exec("BEGIN IMMEDIATE");
    native.exec("UPDATE write_ctx SET origin='remote' WHERE id=1");
    const fields = [
      "connection_id",
      "stream",
      "pk_hash",
      "record_key",
      "stamp_o",
      "stamp_r",
      "stamp_n",
      "body",
      "body_sha256",
      "first_o",
      "body_bytes",
    ];
    const get = cache.prepare("SELECT * FROM bootstrap_rows WHERE seq=?");
    const insert = cache.prepare(
      `INSERT OR IGNORE INTO records(${fields.join(",")}) VALUES(${fields.map(() => "?").join(",")})`,
    );
    const update = cache.prepare(
      `UPDATE records SET ${fields
        .slice(3)
        .map((f) => `${f}=?`)
        .join(
          ",",
        )} WHERE connection_id=? AND stream=? AND pk_hash=? AND (stamp_o IS NOT ? OR stamp_r IS NOT ? OR stamp_n IS NOT ? OR body_sha256 IS NOT ? OR first_o IS NOT ?)`,
    );
    for (const group of groups)
      for (const [hash, upsert, deletion] of group.keys) {
        if (deletion) {
          const t = performance.now();
          const row = get.get(deletion);
          stagingLookupMs += performance.now() - t;
          stagingRowReads++;
          cache
            .prepare(
              "INSERT OR REPLACE INTO log_tombstones(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank) VALUES(?,?,?,?,?,?,?)",
            )
            .run(
              row.connection_id,
              row.stream,
              row.pk_hash,
              row.record_key,
              row.stamp_o,
              row.stamp_r,
              row.rank,
            );
        }
        if (!upsert) {
          cache
            .prepare(
              "DELETE FROM records WHERE connection_id=? AND stream=? AND pk_hash=?",
            )
            .run(group.connectionId, group.stream, hash);
          continue;
        }
        const t = performance.now();
        const row = get.get(upsert);
        stagingLookupMs += performance.now() - t;
        stagingRowReads++;
        const changed = insert.run(...fields.map((f) => row[f])).changes;
        if (!changed)
          update.run(
            ...fields.slice(3).map((f) => row[f]),
            row.connection_id,
            row.stream,
            row.pk_hash,
            row.stamp_o,
            row.stamp_r,
            row.stamp_n,
            row.body_sha256,
            row.first_o,
          );
      }
  }
  if (mode === "C") {
    const groups = await keyIndex.sorted();
    serializedKeyArrayBytes = serialize(groups).byteLength;
    mark();
    const live = groups.flatMap((g) =>
      g.keys.filter((k) => k[1] > 0).map((k) => k[1]),
    );
    supersededRows = totalBootstrapRows - live.length;
    removedKeys = groups.reduce(
      (n, g) => n + g.keys.filter((k) => !k[1]).length,
      0,
    );
    opsPerFinalKey = totalBootstrapRows / live.length;
    native.exec("BEGIN IMMEDIATE");
    if (supersededRows) {
      native.exec(
        "CREATE TEMP TABLE bootstrap_live(row_id INTEGER PRIMARY KEY)",
      );
      const insert = cache.prepare("INSERT INTO temp.bootstrap_live VALUES(?)");
      for (const id of live) insert.run(id);
      native.exec(
        "DELETE FROM bootstrap_records WHERE rowid NOT IN(SELECT row_id FROM temp.bootstrap_live)",
      );
      native.exec("DROP TABLE temp.bootstrap_live");
    }
    for (const group of groups)
      for (const [, , deletion] of group.keys)
        if (deletion) {
          const row = cache
            .prepare("SELECT * FROM bootstrap_deletions WHERE rowid=?")
            .get(-deletion);
          cache
            .prepare(
              "INSERT OR REPLACE INTO log_tombstones(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,rank) VALUES(?,?,?,?,?,?,?)",
            )
            .run(
              row.connection_id,
              row.stream,
              row.pk_hash,
              row.record_key,
              row.stamp_o,
              row.stamp_r,
              row.rank,
            );
        }
    await db.batch(swapBootstrapRecords(swapSchema, connectionId));
    await db.batch([
      { sql: "DELETE FROM record_changes" },
      { sql: "DROP TABLE bootstrap_deletions" },
    ]);
  }
  await db.batch(
    withOrigin("remote", [
      ...(mode !== "C" ? indexes.map((i) => ({ sql: i.sql })) : []),
      { sql: "DELETE FROM record_changes" },
      ...(mode === "A" ? [{ sql: "DELETE FROM bootstrap_rows" }] : []),
    ]),
  );
  native.exec("COMMIT");
  const wallMs = performance.now() - t0,
    pageWrites = Math.round((io() - w0) / 65536);
  mark();
  for (const row of cache
    .prepare("SELECT body,body_sha256 FROM records")
    .iterate())
    assert.equal(
      createHash("sha256").update(row.body).digest("hex"),
      row.body_sha256,
    );
  const resultRows = await db.query(
    "SELECT pk_hash,body_sha256,stamp_o,stamp_r,stamp_n,first_o FROM records ORDER BY connection_id,stream,pk_hash",
  );
  const fingerprint = createHash("sha256")
    .update(JSON.stringify(resultRows))
    .digest("hex");
  assert.equal(fingerprint, manifest.expectedFingerprint);
  assert.equal(resultRows.length, manifest.rows);
  assert.equal(native.pragma("integrity_check", { simple: true }), "ok");
  console.log(
    "[result]",
    JSON.stringify({
      mode,
      rows,
      segments: previous,
      pageWrites,
      totalBootstrapRows,
      supersededRows,
      removedKeys,
      opsPerFinalKey,
      previewCommitMs: previewMs,
      ownerFirstRowMs,
      wallMs,
      keyArrayPeakBytes,
      serializedKeyArrayBytes,
      stagingRowReads,
      stagingLookupMs,
      installMs: wallMs - installStart,
      peakRetainedPayloadBytes: peakPayload,
      peakRssBytes: peakRss,
      peakHeapBytes: peakHeap,
      hostBefore,
      hostAfter: loadavg(),
      fingerprint,
    }),
  );
} finally {
  if (native.inTransaction) native.exec("ROLLBACK");
  await db.close();
}
