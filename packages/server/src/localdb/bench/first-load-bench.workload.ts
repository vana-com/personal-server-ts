// Local reproduction of a large first load: one publisher, then N fresh
// readers (own file DB each) over the same published blobs. Generic synthetic
// stream, no connector knowledge. Usage:
//   npx tsx packages/server/src/localdb/bench/first-load-bench.workload.ts \
//     --rows 198001 --progressive off --readers 3 --get-ms 250 --node-crypto on
// Run it under `nice -n 19 ionice -c3`. `--dir` holds the databases, which
// are removed afterwards. The default is a fresh directory under the OS temp
// directory; pass a disk-backed `--dir` when that is in memory.
import { firstOwnerRow } from "./owner-row.js";
import { createHash, getHashes } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3";
import { mkdirSync, mkdtempSync, rmSync, createWriteStream } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { loadavg, freemem } from "node:os";
import { partialPage } from "../../../../core/src/localdb/partial-read.js";
import { createRecordQuery } from "../../../../core/src/localdb/query.js";
import { Session } from "node:inspector/promises";
import { readFileSync, writeFileSync } from "node:fs";
import {
  controlHashes,
  deriveKeyCheck,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  connectionQueue,
  createLocalSync,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../../core/src/localdb/index.js";
import {
  createGatewayStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../../core/src/stream-sync/index.js";
import { createLocalListing } from "../../../../core/src/localdb/listing.js";
import { endRequest } from "../../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "../better-sqlite3-driver.js";
import { createFakeGateway } from "../fake-gateway.js";
import { createStreamSyncKeyPorts } from "../../../../core/src/stream-sync/crypto.js";
import { nobleStreamCrypto } from "../../../../core/src/stream-sync/crypto-port.js";
import { nodeStreamCrypto as hostCrypto } from "../../stream-sync/node-stream-crypto.js";

const arg = (name: string, d: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? d : process.argv[i + 1]!;
};
const ROWS = Number(arg("rows", "20000"));
const PROGRESSIVE = arg("progressive", "on") === "on";
// `--keyed off` loads segment by segment even when the key-ordered load would apply.
const KEYED = arg("keyed", "on") === "on";
const READERS = Number(arg("readers", "1"));
const ROW_BYTES = Number(arg("rowbytes", "2200"));
const BATCH_ROWS = Number(arg("batchrows", "2000"));
// "on" seals and opens segments with the ports the Node host wires
// (`bootstrap.ts`: `nodeStreamCrypto`); `--realcrypto on` uses the pure-JS ones.
const NODE_CRYPTO = arg("node-crypto", "off") === "on";
// "noble" keeps the pure-JS Keccak-256 in the host port: the before of the change that added the native one.
const nodeStreamCrypto =
  arg("keccak", "native") === "noble"
    ? { ...hostCrypto, keccak256: nobleStreamCrypto.keccak256 }
    : hostCrypto;
const REAL_CRYPTO = NODE_CRYPTO || arg("realcrypto", "off") === "on";
const CAPTURE = arg("capture", "");
// "on" opens the reader as the Web host does: 64 KiB pages and TRUNCATE journaling
// (`openLocalDb` picks the journal from `driver.info.host`). The page-write oracle
// below counts bytes written to the file and its journal over the reader's cycle.
const WEB = arg("web", "off") === "on";
const PAGE_SIZE = 65536;
// Default exercises the shared disk-backed front end. --defer off is the
// ordinary reference; --finish copy forces the common-table shadow candidate.
const DEFER = arg("defer", "swap");
if (!["swap", "off"].includes(DEFER))
  throw new Error("--defer must be swap or off");
const ioBytes = () => {
  const text = readFileSync("/proc/self/io", "utf8");
  const pick = (k: string) => Number(new RegExp(`${k}: (\\d+)`).exec(text)![1]);
  return { read: pick("rchar"), written: pick("wchar") };
};
// A directory: write a main-thread CPU profile of each reader cycle there.
const PROF = arg("prof", "");
// A reader's GET takes this long (a store's latency), so GET and apply can overlap.
const GET_MS = Number(arg("get-ms", "0"));
// The work directory: the bench writes large SQLite files there. By default a
// fresh one under the OS temp directory; pass --dir (or set TMPDIR) for a
// disk-backed one when the temp directory is in memory.
const DIR = arg("dir", "") || mkdtempSync(join(tmpdir(), "first-load-bench-"));
const realKeys = REAL_CRYPTO
  ? createStreamSyncKeyPorts(
      `0x${"ab".repeat(64)}1b`,
      ...(NODE_CRYPTO ? [nodeStreamCrypto] : []),
    )
  : null;
const OWNER = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "fixture";
const CONNECTION_ID = `pdpp.${CONNECTOR}~`;
const STREAM = "memories";

// deterministic text with ~realistic entropy
let seed = 12345;
const rnd = () =>
  (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const vocab = Array.from({ length: 4000 }, () =>
  Array.from({ length: 3 + Math.floor(rnd() * 8) }, () =>
    String.fromCharCode(97 + Math.floor(rnd() * 26)),
  ).join(""),
);
const text = (bytes: number) => {
  let s = "";
  while (s.length < bytes) s += vocab[Math.floor(rnd() * vocab.length)] + " ";
  return s.slice(0, bytes);
};

const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
const gateway = createFakeGateway({
  owner: OWNER,
  isTombstone: (v) =>
    v.dataHash === hashes.tombstoneData &&
    v.metadataHash === hashes.tombstoneMetadata,
});
const store = new Map<string, Uint8Array>();
// Bytes the reader may hold in flight (default: the store's own).
const MAX_BYTES = Number(arg("max-bytes", "0"));
const governor = createMemoryStreamSyncBlobs(
  MAX_BYTES > 0 ? { maxBytesInFlight: MAX_BYTES } : {},
).governor;

function makeDeps(
  db: SqlDriver,
  deviceId: string,
  timing: Timing | null,
): LocalSyncDeps {
  let op = 0;
  return {
    db,
    bootstrapFirstLoad: timing !== null && DEFER === "swap",
    ...(timing && DEFER === "swap"
      ? {
          bootstrapFirstLoad: true,
          ...(arg("finish", "auto") === "copy"
            ? { bootstrapFirstLoadFinish: "copy" as const }
            : {}),
        }
      : {}),
    queue: connectionQueue(),
    registry: createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test",
      ownerAddress: OWNER,
      fetch: gateway.fetch,
    }),
    blobs: {
      governor,
      async get(key) {
        timing?.inflight(+1);
        try {
          if (GET_MS > 0 && timing)
            await new Promise((r) => setTimeout(r, GET_MS));
        } finally {
          timing?.inflight(-1);
        }
        const t = performance.now();
        const v = store.get(key) ?? null;
        timing?.add("blob_get", performance.now() - t);
        if (timing) {
          if (timing.marks["first_blob_get_done"] === undefined)
            timing.mark("first_blob_get_done");
          timing.mark("last_blob_get_done");
        }
        return v;
      },
      exists: async (key) => store.has(key),
      put: async (key, bytes) => {
        store.set(key, bytes.slice());
      },
    },
    ownerAddress: OWNER,
    keys: {
      namespaceHmac: async (m) =>
        realKeys ? realKeys.namespaceHmac(m) : new Uint8Array(32),
      encrypt: async (s, b) => (realKeys ? realKeys.encrypt(s, b) : b),
      encryptPart: async (s, b) => (realKeys ? realKeys.encryptPart(s, b) : b),
      decrypt: async (s, b) => {
        const t = performance.now();
        const r = realKeys ? await realKeys.decrypt(s, b) : b;
        timing?.add("decrypt", performance.now() - t);
        return r;
      },
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => Date.now(),
    newOp: () => `${deviceId}-${++op}`,
    ...(NODE_CRYPTO ? { streamCrypto: nodeStreamCrypto } : {}),
    ...(PROGRESSIVE && timing ? { progressiveFirstLoad: true } : {}),
    ...(KEYED ? {} : { keyedFirstLoad: false }),
  } as LocalSyncDeps;
}

class Timing {
  t0 = performance.now();
  marks: Record<string, string> = {};
  mark(k: string) {
    this.marks[k] = `${((performance.now() - this.t0) / 1000).toFixed(2)}s`;
  }
  gets = 0;
  maxGets = 0;
  inflight(d: number) {
    this.gets += d;
    this.maxGets = Math.max(this.maxGets, this.gets);
  }
  total = new Map<string, number>();
  count = new Map<string, number>();
  add(k: string, ms: number) {
    this.total.set(k, (this.total.get(k) ?? 0) + ms);
    this.count.set(k, (this.count.get(k) ?? 0) + 1);
  }
  maxima = new Map<string, number>();
  max(k: string, v: number) {
    this.maxima.set(k, Math.max(this.maxima.get(k) ?? 0, v));
  }
  report() {
    const out: Record<string, string> = {
      max_gets_in_flight: String(this.maxGets),
      ...this.marks,
    };
    for (const [k, v] of this.maxima) out[k] = v.toFixed(0);
    for (const [k, v] of this.total)
      out[k] = `${(v / 1000).toFixed(2)}s over ${this.count.get(k)} calls`;
    return out;
  }
}

function instrument(
  db: SqlDriver,
  timing: Timing,
  capture?: ReturnType<typeof createWriteStream>,
) {
  const d = db as unknown as {
    batch: SqlDriver["batch"];
    query: SqlDriver["query"];
  };
  const batch = d.batch.bind(d);
  let applyStarted = false;
  d.batch = async (statements) => {
    if (
      !applyStarted &&
      statements.some((st) => st.sql.includes("INSERT INTO temp.incoming"))
    ) {
      applyStarted = true;
      timing.mark("apply_phase_starts_at");
    }
    if (capture) capture.write(JSON.stringify({ statements }) + "\n");
    const t = performance.now();
    const w0 = ioBytes().written;
    const r = await batch(statements);
    const ms = performance.now() - t;
    const kind = statements.some((st) =>
      st.sql.includes("INSERT INTO log_stage_"),
    )
      ? "stage"
      : statements.some((st) => st.sql.includes("INSERT INTO temp.incoming"))
        ? "apply"
        : "other";
    timing.add(`pages(${kind})`, ((ioBytes().written - w0) / PAGE_SIZE) * 1000);
    timing.add("db.batch", ms);
    timing.max("db.batch.max_ms", ms);
    const big = statements.length > 50 ? "db.batch(big)" : "db.batch(small)";
    timing.add(big, ms);
    timing.add("statements", statements.length);
    return r;
  };
}

mkdirSync(DIR, { recursive: true });
console.log(
  "[runtime]",
  JSON.stringify({
    node: process.version,
    openssl: process.versions.openssl,
    nativeKeccak: getHashes().includes("keccak-256"),
    mode: DEFER,
    rows: ROWS,
    runs: Number(arg("runs", "64")),
    readers: READERS,
    getMs: GET_MS,
  }),
);

async function fingerprint(db: SqlDriver) {
  const rows = await db.query(
    "SELECT pk_hash, body_sha256, stamp_o, stamp_r, stamp_n, first_o FROM records ORDER BY connection_id, stream, pk_hash",
  );
  return createHash("sha256").update(JSON.stringify(rows)).digest("hex");
}
let expectedFingerprint = "";
let expectedPosition = 0;
// ---- publisher
{
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: OWNER,
    network: "test",
    deviceId: "pub",
  });
  const deps = makeDeps(db, "pub", null);
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: [
        {
          name: STREAM,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory" as const,
        },
      ],
    }),
  });
  const t0 = performance.now();
  const RUNS = Number(arg("runs", "64"));
  const perRun = Math.ceil(ROWS / RUNS);
  let tIntake = 0;
  let tCycle = 0;
  for (let run = 0; run < RUNS; run++) {
    const runId = `run-${run + 1}`;
    const ta = performance.now();
    await sync.intake.begin(runId, {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: RUNS === 1,
      observedAt: 1000 + run,
      owner: { address: OWNER, leaseId: null },
    });
    let b = 0;
    for (
      let i = run * perRun;
      i < Math.min(ROWS, (run + 1) * perRun);
      i += BATCH_ROWS
    ) {
      const records = [];
      for (
        let j = i;
        j < Math.min(ROWS, (run + 1) * perRun, i + BATCH_ROWS);
        j++
      )
        records.push({
          stream: STREAM,
          data: {
            id: `m-${String(j).padStart(8, "0")}`,
            created: 1700000000 + j,
            content: text(ROW_BYTES),
          },
        });
      await sync.intake.batch(runId, { batch: b++, records });
    }
    await sync.intake.end(
      runId,
      endRequest({
        lastBatch: b - 1,
        live: [STREAM],
        ...(RUNS === 1 ? { provenFullStreams: [STREAM] } : {}),
      }),
    );
    const tb = performance.now();
    const report = await sync.cycle();
    const err = report.connections.find((c) => c.error !== null);
    if (err) throw new Error(`publish cycle failed: ${err.error}`);
    tIntake += tb - ta;
    tCycle += performance.now() - tb;
  }
  const t1 = t0 + tIntake;
  const t2 = t1 + tCycle;
  let bytes = 0;
  for (const v of store.values()) bytes += v.byteLength;
  console.log(
    `[publisher] rows=${ROWS} intake=${((t1 - t0) / 1000).toFixed(1)}s publish-cycle=${((t2 - t1) / 1000).toFixed(1)}s blobs=${store.size} bytes=${(bytes / 1e6).toFixed(1)}MB`,
  );
  expectedFingerprint = await fingerprint(db);
  expectedPosition = (
    await db.query<{ position: number }>(
      "SELECT position FROM log_state WHERE connection_id=?",
      [CONNECTION_ID],
    )
  )[0]!.position;
  const exportFixture = arg("export-fixture", "");
  if (exportFixture) {
    mkdirSync(exportFixture, { recursive: true });
    const entries = [...store].map(([key, bytes], i) => {
      const file = `${i}.bin`;
      writeFileSync(join(exportFixture, file), bytes);
      return { key, file };
    });
    writeFileSync(
      join(exportFixture, "index.json"),
      JSON.stringify({ rows: ROWS, runs: RUNS, expectedFingerprint, entries }),
    );
  }
  await db.close();
}

// ---- readers
const results: number[] = [];
for (let r = 0; r < READERS; r++) {
  const path = `${DIR}/reader-${r}.db`;
  for (const s of ["", "-wal", "-shm", ".lock"])
    rmSync(path + s, { force: true });
  const raw = openBetterSqlite3(path);
  if (WEB) {
    await raw.query(`PRAGMA page_size = ${PAGE_SIZE}`);
    await raw.query("PRAGMA temp_store = MEMORY");
    Object.defineProperty(raw, "info", {
      value: { ...raw.info, host: "web" },
    });
  }
  const timing = new Timing();
  const cap = CAPTURE && r === 0 ? createWriteStream(CAPTURE) : undefined;
  instrument(raw, timing, cap);
  const db = await openLocalDb(raw, {
    owner: OWNER,
    network: "test",
    deviceId: `reader-${r}`,
  });
  const deps = makeDeps(db, `reader-${r}`, timing);
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: [
        {
          name: STREAM,
          semantics: "mutable_state" as const,
          primaryKey: ["id"],
          coverageStrategy: "full_inventory" as const,
        },
      ],
    }),
  });
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  const originalBatch = db.batch.bind(db);
  let stagedSegments = 0;
  db.batch = async (statements) => {
    if (
      statements.some((st) => st.sql.includes("INSERT INTO bootstrap_segments"))
    )
      stagedSegments++;
    const finish = statements.some((st) => st.sql === "DROP TABLE records")
      ? "swap"
      : statements.some((st) => st.sql === "DROP TABLE bootstrap_records")
        ? "copy"
        : null;
    if (finish) timing.mark(`${finish}_batch_start`);
    const result = await originalBatch(statements);
    if (finish) timing.mark(`${finish}_batch_end`);
    return result;
  };
  console.log(
    `[host ${r}] load=${JSON.stringify(loadavg())} freeGB=${(freemem() / 1e9).toFixed(2)} defer=${DEFER}`,
  );
  const readSamples: unknown[] = [];
  // Memory the reader adds: the sampled peak above what the process held at the start.
  const before = process.memoryUsage();
  let peakRss = before.rss;
  let peakHeap = before.heapUsed;
  const sampler = setInterval(() => {
    const m = process.memoryUsage();
    peakRss = Math.max(peakRss, m.rss);
    peakHeap = Math.max(peakHeap, m.heapUsed);
  }, 20);
  const session = PROF ? new Session() : null;
  if (session) {
    session.connect();
    await session.post("Profiler.enable");
    await session.post("Profiler.setSamplingInterval", { interval: 500 });
    await session.post("Profiler.start");
  }
  timing.t0 = performance.now();
  const io0 = ioBytes();
  const t0 = performance.now();
  // What a user sees first: the source in the owner's listing, and the first
  // stored row. Polled on the same thread as the load, as a page would be.
  const listing = createLocalListing(deps as never);
  let polling = true;
  const poll = (async () => {
    let listed = false;
    let row = false;
    while (polling) {
      if (!listed) {
        const scopes = await listing.listScopes({
          canRead: () => true,
          includeLoading: true,
        });
        if (
          scopes.some((scope) => scope.scope === `pdpp.${CONNECTOR}.${STREAM}`)
        ) {
          listed = true;
          timing.mark("listed_at");
        }
      }
      if (!row) {
        const ownerRow = await firstOwnerRow(
          deps,
          `pdpp.${CONNECTOR}.${STREAM}`,
        );
        if (ownerRow !== null) {
          if (typeof ownerRow.id !== "string" || !ownerRow.id.startsWith("m-"))
            throw new Error("unexpected owner row");
          row = true;
          timing.mark("first_row_at");
        }
      }
      if (row) {
        const [p] = await db.query<{
          stream: string;
          version: number;
          generation: number;
          data_hash: string;
        }>(
          "SELECT stream,version,generation,data_hash FROM stream_partial WHERE connection_id=? LIMIT 1",
          [CONNECTION_ID],
        );
        if (p) {
          const q = partialPage(
            {
              connectionId: CONNECTION_ID,
              stream: p.stream,
              version: p.version,
              generation: p.generation,
              dataHash: p.data_hash,
            },
            undefined,
          );
          let t = performance.now();
          const page = await db.query(q.sql, q.params);
          timing.max("partial_read_ms", performance.now() - t);
          if (!page.some((x) => x.pk_hash !== null))
            throw new Error("partial view lost its rows");
          if (readSamples.length === 0) timing.mark("first_partial_page_at");
          t = performance.now();
          const list = await createRecordQuery(db).listRecords({
            connectionId: CONNECTION_ID,
            stream: STREAM,
          });
          timing.max("record_list_ms", performance.now() - t);
          if (!list.records.length) throw new Error("record list lost rows");
          t = performance.now();
          const found = await createRecordQuery(db).getRecord({
            connectionId: CONNECTION_ID,
            stream: STREAM,
            recordKey: list.records[0]!.recordKey,
          });
          timing.max("record_get_ms", performance.now() - t);
          if (!found) throw new Error("getRecord lost its row");
          if (readSamples.length < 4)
            readSamples.push({
              partialPlan: await db.query(
                "EXPLAIN QUERY PLAN " + q.sql,
                q.params,
              ),
            });
        }
      }
      await new Promise((resolve) => setTimeout(resolve, row ? 250 : 20));
    }
  })();
  const report = await sync.cycle();
  const wall = (performance.now() - t0) / 1000;
  timing.mark("cycle_done_at");
  polling = false;
  await poll;
  const io1 = ioBytes();
  console.log(
    `[reader ${r}] io: page_writes=${Math.round((io1.written - io0.written) / PAGE_SIZE)} page_reads=${Math.round((io1.read - io0.read) / PAGE_SIZE)} (bytes written ${((io1.written - io0.written) / 1e6).toFixed(0)} MB, read ${((io1.read - io0.read) / 1e6).toFixed(0)} MB; page size ${PAGE_SIZE})`,
  );
  if (session) {
    const { profile } = await session.post("Profiler.stop");
    mkdirSync(PROF, { recursive: true });
    writeFileSync(
      `${PROF}/reader-${r}-main.cpuprofile`,
      JSON.stringify(profile),
    );
    session.disconnect();
  }
  clearInterval(sampler);
  const mb = (n: number) => (n / 1048576).toFixed(0);
  console.log(
    `[reader ${r}] memory: rss +${mb(peakRss - before.rss)} MB (peak ${mb(peakRss)}), heap +${mb(peakHeap - before.heapUsed)} MB`,
  );
  const err = report.connections.find((c) => c.error !== null);
  if (err) throw new Error(`reader cycle failed: ${err.error}`);
  const [{ n }] = await db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM records",
  );
  results.push(wall);
  console.log(
    `[reader ${r}] wall=${wall.toFixed(1)}s records=${n} progressive=${PROGRESSIVE}`,
    timing.report(),
  );
  console.log(
    `[proof ${r}]`,
    JSON.stringify({
      load: loadavg(),
      readSamples,
      stagedSegments,
      indexes: await db.query(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='records'",
      ),
      integrity: await db.query("PRAGMA integrity_check"),
    }),
  );
  if ((await fingerprint(db)) !== expectedFingerprint)
    throw new Error("final state differs from publisher");
  const [cursor] = await db.query<{ position: number }>(
    "SELECT position FROM log_state WHERE connection_id=?",
    [CONNECTION_ID],
  );
  if (cursor?.position !== expectedPosition)
    throw new Error("final log cursor differs from publication");
  if ((await db.query("SELECT 1 FROM stream_partial")).length)
    throw new Error("load ended with partial markers");
  if (n !== ROWS) throw new Error(`wrong row count: ${n}`);

  await db.close();
  if (arg("keep", "off") !== "on")
    for (const s of ["", "-wal", "-shm", ".lock"])
      rmSync(path + s, { force: true });
}
if (results.length > 0) {
  results.sort((a, b) => a - b);
  console.log(
    `[summary] n=${results.length} p50=${results[Math.floor(results.length / 2)]!.toFixed(1)}s all=${results.map((x) => x.toFixed(1)).join(",")}`,
  );
}
