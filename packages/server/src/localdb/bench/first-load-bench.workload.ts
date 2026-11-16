// Local reproduction of a large first load: one publisher, then N fresh
// readers (own file DB each) over the same published blobs. Generic synthetic
// stream, no connector knowledge. Usage:
//   npx tsx packages/server/src/localdb/bench/first-load-bench.workload.ts \
//     --rows 198001 --progressive off --readers 3 --get-ms 250 --node-crypto on
// Run it under `nice -n 19 ionice -c3`. `--dir` holds the databases and is
// removed afterwards; the default is on disk, since /tmp may be memory.
import { keccak_256 } from "@noble/hashes/sha3";
import { mkdirSync, rmSync, createWriteStream } from "node:fs";
import { performance } from "node:perf_hooks";
import { Session } from "node:inspector/promises";
import { writeFileSync } from "node:fs";
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
// A directory: write a main-thread CPU profile of each reader cycle there.
const PROF = arg("prof", "");
// A reader's GET takes this long (a store's latency), so GET and apply can overlap.
const GET_MS = Number(arg("get-ms", "0"));
const DIR = arg("dir", `${process.env.HOME}/.tmp/first-load-bench`);
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
  } as LocalSyncDeps;
}

class Timing {
  t0 = performance.now();
  marks: Record<string, string> = {};
  mark(k: string) {
    this.marks[k] = `${((performance.now() - this.t0) / 1000).toFixed(1)}s`;
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
  report() {
    const out: Record<string, string> = {
      max_gets_in_flight: String(this.maxGets),
      ...this.marks,
    };
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
    const r = await batch(statements);
    const ms = performance.now() - t;
    timing.add("db.batch", ms);
    const big = statements.length > 50 ? "db.batch(big)" : "db.batch(small)";
    timing.add(big, ms);
    timing.add("statements", statements.length);
    return r;
  };
}

mkdirSync(DIR, { recursive: true });

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
    declaredStreams: () => [STREAM],
  });
  const t0 = performance.now();
  const RUNS = Number(arg("runs", "1"));
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
    await sync.intake.end(runId, {
      outcome: "succeeded",
      coveredStreams: [STREAM],
      lastBatch: b - 1,
      ...(RUNS === 1 ? { provenFullStreams: [STREAM] } : {}),
    });
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
  await db.close();
}

// ---- readers
const results: number[] = [];
for (let r = 0; r < READERS; r++) {
  const path = `${DIR}/reader-${r}.db`;
  for (const s of ["", "-wal", "-shm", ".lock"])
    rmSync(path + s, { force: true });
  const raw = openBetterSqlite3(path);
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
    declaredStreams: () => [STREAM],
  });
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
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
  const t0 = performance.now();
  const report = await sync.cycle();
  const wall = (performance.now() - t0) / 1000;
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
  await db.close();
  for (const s of ["", "-wal", "-shm", ".lock"])
    rmSync(path + s, { force: true });
}
results.sort((a, b) => a - b);
console.log(
  `[summary] n=${results.length} p50=${results[Math.floor(results.length / 2)]!.toFixed(1)}s all=${results.map((x) => x.toFixed(1)).join(",")}`,
);
