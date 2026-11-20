// Isolated offline reproduction. Crypto calibration is a separate opt-in case.
import Database from "better-sqlite3";
import { createStatementCache } from "../../packages/server/src/localdb/statement-cache.cjs";
import { randomUUID } from "node:crypto";
import { createSqlWorkspaceValues } from "../../packages/core/src/localdb/workspace-values.js";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  readdirSync,
  unlinkSync,
} from "node:fs";
import { join } from "node:path";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  LOG,
  OWNER,
} from "../../packages/server/src/localdb/log-world.test-utils.js";
import { createMemoryStreamSyncBlobs } from "../../packages/core/src/stream-sync/index.js";
import { readLogState } from "../../packages/core/src/localdb/log-state.js";
import { rebaseOnLog } from "../../packages/core/src/localdb/log-rebase.js";
import { planCompaction } from "./compaction-eligibility-only";
import { fetchSegment } from "../../packages/core/src/localdb/log-apply.js";
import { loadBootstrap } from "../../packages/core/src/localdb/log-bootstrap.js";
import { bootstrapSchema } from "../../packages/core/src/localdb/bootstrap-swap.js";
import { connectionQueue } from "../../packages/core/src/localdb/queue.js";
import {
  sealBytes,
  openBytes,
} from "../../packages/core/src/stream-sync/stream-aead.js";
import { createStreamSyncKeyPorts } from "../../packages/core/src/stream-sync/crypto.js";
import { nobleStreamCrypto } from "../../packages/core/src/stream-sync/crypto-port.js";
import { randomBytes } from "node:crypto";
import { createHash } from "node:crypto";
import {
  deriveKeyCheck,
  encodeSegment,
  digestSegment,
  decodeSnapshotPart,
  canonicalJson,
} from "../../packages/stream-sync/src/index.js";
import { uploadOutputs } from "../../packages/core/src/localdb/log-output.js";
import { endRequest } from "../../packages/core/src/test-utils/run-end.js";
const dir = process.env.MEMORY_DIR;
const mode = process.env.MEMORY_CASE;
const n = Number(process.env.MEMORY_N ?? 200),
  pad = Number(process.env.MEMORY_PAD ?? 1024);
const C = 2 * 1024 * 1024,
  frame = 4 * 1024 * 1024;
let active = false,
  queryBytes = 0,
  metadataBytes = 0,
  batchBytes = 0,
  peak = 0,
  livePeak = 0,
  decoded = [];
let operationBytes = 0,
  foldInputBytes = 0,
  candidateBytes = 0,
  uploadBarriers = 0,
  plans = new Map();
let heavyFolds = 0,
  maxHeavyFolds = 0;
const identityKeys = {
  namespaceHmac: async () => new Uint8Array(32),
  encrypt: async (_s, b) => b,
  encryptPart: async (_s, b) => b,
  decrypt: async (_s, b) => b,
};
// Public deterministic test signature, also used by crypto.test.ts. Key derivation,
// STREAM parts and legacy control encryption use the production key port.
const signature =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";
globalThis.memoryKeys =
  mode === "crypto"
    ? {
        ...createStreamSyncKeyPorts(signature),
        // Keep the test gateway's precomputed namespace/key-check binding unchanged.
        namespaceHmac: identityKeys.namespaceHmac,
      }
    : identityKeys;
globalThis.memoryForcePublicationCompaction = false;
globalThis.memoryFoldInput = async (parts, segments) => {
  if (!active) return;
  foldInputBytes = Math.max(
    foldInputBytes,
    [...parts, ...segments].reduce((n, p) => n + bytes(p), 0),
  );
  heavyFolds++;
  maxHeavyFolds = Math.max(maxHeavyFolds, heavyFolds);
  await new Promise((r) => setImmediate(r));
  global.gc?.();
  sample();
  heavyFolds--;
};
globalThis.memoryCandidate = async (candidate) => {
  if (!active) return;
  const size =
    candidate.cipher.length +
    candidate.objects.reduce((n, o) => n + o.cipher.length, 0);
  candidateBytes = Math.max(candidateBytes, size);
  if (mode === "slow-upload") {
    uploadBarriers++;
    await new Promise((r) => setTimeout(r, 100));
    global.gc?.();
    sample();
  }
};
const gcEvery = Number(process.env.MEMORY_GC_EVERY ?? 1);
let commits = 0;
globalThis.memoryOperations = (ops) => {
  if (active) {
    let total = 0;
    for (const op of ops.values()) total += bytes(op);
    operationBytes = Math.max(operationBytes, total);
  }
};
/** Bytes of every typed array reachable from `root` by properties (closures are
 * not reachable: a descriptor holds none of the data). */
function reachableBytes(root) {
  const seen = new Set();
  let total = 0;
  const walk = (v) => {
    if (v === null || typeof v !== "object" || seen.has(v)) return;
    seen.add(v);
    if (ArrayBuffer.isView(v)) {
      total += v.byteLength;
      return;
    }
    for (const key of Object.keys(v)) walk(v[key]);
  };
  walk(root);
  return total;
}
const bytes = (v) =>
  Buffer.byteLength(
    JSON.stringify(v, (_, x) => (typeof x === "bigint" ? String(x) : x)),
  );
const sample = () => {
  if (active) peak = Math.max(peak, process.memoryUsage().rss);
};
let seenBodies = new WeakSet();
globalThis.memoryDecoded = (unit) => {
  if (!active) return;
  // A last-naming wrapper can keep operations/values after the original part
  // object dies. Observe bodies themselves, once per object, with no strong root.
  for (const op of unit.entries ?? unit.operations) {
    if (op.kind !== "upsert" || seenBodies.has(op.value)) continue;
    seenBodies.add(op.value);
    decoded.push({ ref: new WeakRef(op.value), bytes: bytes(op.value) });
  }
};
const nativeDBs = new Map();
globalThis.memoryDriver = (id) => {
  const db = new Database(join(dir, id + ".db"));
  nativeDBs.set(id, db);
  db.pragma("journal_mode=WAL");
  db.pragma("synchronous=NORMAL");
  db.pragma("mmap_size=0");
  db.pragma("cache_size=-8192");
  db.pragma("temp_store=FILE");
  const statements = createStatementCache(db);
  const driver = {
    info: {
      sqliteVersion: db.prepare("select sqlite_version() v").get().v,
      host: "node",
      persistent: true,
    },
    async query(sql, params = []) {
      const q = statements.prepare(sql);
      const rows = q.reader ? q.all(...params) : (q.run(...params), []);
      if (active) {
        if (/^\s*SELECT/i.test(sql)) {
          const plan = db
            .prepare("EXPLAIN QUERY PLAN " + sql)
            .all(...params)
            .map((r) => r.detail);
          const key = JSON.stringify(plan);
          const prior = plans.get(key);
          if (!prior || prior.rows < rows.length)
            plans.set(key, { plan, rows: rows.length, bytes: bytes(rows) });
        }
        const size = bytes(rows);
        queryBytes = Math.max(queryBytes, size);
        if (!/\bbody\b/i.test(sql))
          metadataBytes = Math.max(metadataBytes, size);
        sample();
      }
      return rows;
    },
    async batch(ss) {
      const result = db.transaction(() => ({
        changes: ss.map(
          (s) => statements.prepare(s.sql).run(...(s.params ?? [])).changes,
        ),
      }))();
      if (active) {
        batchBytes = Math.max(batchBytes, bytes(ss));
        // The decoded graphs are judged at the commit barriers of the load; the
        // rebase and progressive modes judge them at every write.
        const barrier = ss.some((s) =>
          /INSERT OR IGNORE INTO workspace_receipts|INSERT OR REPLACE INTO log_state/.test(
            s.sql,
          ),
        );
        await new Promise((r) => setImmediate(r));
        if (
          (barrier || mode === "rebase" || mode === "progressive") &&
          ++commits % gcEvery === 0
        ) {
          global.gc?.();
          livePeak = Math.max(
            livePeak,
            decoded.reduce((n, x) => n + (x.ref.deref() ? x.bytes : 0), 0),
          );
        }
        sample();
      }
      return result;
    },
    async close() {
      statements.clear();
      db.close();
    },
  };
  return {
    ...driver,
    boundedValues: createSqlWorkspaceValues(driver, randomUUID),
  };
};
const blobs = join(dir, "blobs");
mkdirSync(blobs);
const file = (key) => join(blobs, Buffer.from(key).toString("hex"));
// Content is on disk; each GET allocates fresh bytes, never an in-memory fixture cache.
globalThis.memoryBlobs = {
  governor: createMemoryStreamSyncBlobs().governor,
  put: async (k, b) => {
    if (active && mode === "slow-upload")
      await new Promise((r) => setTimeout(r, 25));
    writeFileSync(file(k), b);
  },
  get: async (k) =>
    existsSync(file(k)) ? new Uint8Array(readFileSync(file(k))) : null,
  exists: async (k) => existsSync(file(k)),
  keys: () => readdirSync(blobs).map((k) => Buffer.from(k, "hex").toString()),
  delete: (k) => {
    if (existsSync(file(k))) unlinkSync(file(k));
  },
};
const w = await world({
  streams: mode === "many-streams" ? 512 : 1,
  partTargetBytes: C,
  keyTypes: ["integer"],
});
const a = await w.device("a");
const streamNames = w.names;
let observation = 1000;
async function intake(run, v, count = n) {
  await a.sync.intake.begin(run, {
    connector: "fixture",
    artifactDigest: "fixture",
    observedAt: ++observation,
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  let batch = 0;
  for (let i = 0; i < count; i += 500)
    await a.sync.intake.batch(run, {
      batch: batch++,
      records: Array.from({ length: Math.min(500, count - i) }, (_, j) => ({
        stream: streamNames[(i + j) % streamNames.length],
        data: { id: i + j, v, pad: "p".repeat(pad) },
      })),
    });
  await a.sync.intake.end(
    run,
    endRequest({
      lastBatch: batch - 1,
      streams: streamNames,
      live: streamNames,
      provenFullStreams: streamNames,
    }),
  );
}
async function phase(name, fn) {
  queryBytes = metadataBytes = batchBytes = livePeak = peak = 0;
  decoded = [];
  seenBodies = new WeakSet();
  operationBytes = foldInputBytes = candidateBytes = uploadBarriers = 0;
  plans = new Map();
  global.gc?.();
  const baseline = process.memoryUsage().rss;
  active = true;
  const timer = setInterval(sample, 100);
  let result;
  try {
    result = await fn();
  } finally {
    sample();
    active = false;
    clearInterval(timer);
  }
  const receipt = {
    phase: name,
    gcEvery,
    n,
    pad,
    baseline,
    peak,
    operationBytes,
    foldInputBytes,
    candidateBytes,
    uploadBarriers,
    explain: [...plans.values()],
    queryBytes,
    metadataBytes,
    batchBytes,
    liveDecodedBytes: livePeak,
    livenessProbe:
      "distinct decoded body objects; retained logical canonical bytes",
    ledger: {
      host: "desktop host",
      Bdb: 8388608,
      P: 65536,
      H0: 1048576,
      R: pad + 1024,
      C,
      T: frame,
      Bcrypto: null,
      bR: null,
      bC: null,
      bT: null,
    },
  };
  console.log(JSON.stringify({ ...receipt, ...result }));
}
try {
  await intake(
    "initial",
    1,
    ["crypto", "jobs", "receipts"].includes(mode) ? 1 : n,
  );
  await a.cycle();
  if (mode === "compaction" || mode === "history" || mode === "slow-output")
    await phase(mode === "history" ? "compaction" : mode, async () => {
      let log = await readLogState(a.deps, CONNECTION_ID);
      if (mode === "history") log = await inflatedHistory(log, 10);
      const p = await planCompaction(a.deps, {
        connector: "fixture",
        ns: "",
        generation: 1,
        keyCheck: await deriveKeyCheck(async () => new Uint8Array(32)),
        scope: LOG,
        log,
      });
      if (!p) throw Error("planner did not run");
      const reader = mode === "history" ? await w.device("history-reader") : null;
      const applyPart =
        mode === "history"
          ? (await import("../../packages/core/src/localdb/log-apply.js"))
              .applySnapshotPart
          : null;
      // The plan holds a workspace handle, never ciphertext: what it keeps
      // reachable is what a retained candidate costs.
      const retainedBytes = reachableBytes(p);
      let outputBytes = 0,
        objects = 0,
        largest = 0,
        inFlight = 0,
        peakInFlight = 0;
      // The one upload loop reads one sealed value into one buffer at a time. A
      // slow store only lengthens the loop: nothing queues behind it.
      await uploadOutputs(a.deps, p.outputs, async (name, bytes) => {
        inFlight++;
        peakInFlight = Math.max(peakInFlight, inFlight);
        if (mode === "slow-output")
          await new Promise((resolve) => setTimeout(resolve, 5));
        outputBytes += bytes.length;
        largest = Math.max(largest, bytes.length);
        objects++;
        if (reader && name.startsWith("q-")) {
          const decoded = decodeSnapshotPart(bytes);
          if (decoded.kind !== "ok") throw Error("snapshot decode");
          await applyPart(reader.deps, CONNECTION_ID, decoded.part);
        }
        inFlight--;
      });
      if (reader && JSON.stringify(await reader.rows()) !== JSON.stringify(await a.rows()))
        throw Error("history changed fixed winners");
      return { outputBytes, objects, largest, peakInFlight, retainedBytes };
    });
  if (mode === "rebase")
    await phase("rebase", async () => {
      const log = await readLogState(a.deps, CONNECTION_ID);
      await rebaseOnLog(
        a.deps,
        CONNECTION_ID,
        {
          connector: "fixture",
          ns: "",
          generation: 1,
          keyCheck: await deriveKeyCheck(async () => new Uint8Array(32)),
        },
        log,
        [],
      );
      return { position: (await readLogState(a.deps, CONNECTION_ID)).position };
    });
  if (mode === "slow-upload") {
    await a.run("next", [{ stream: "s0", id: n }], { full: false });
    globalThis.memoryForcePublicationCompaction = true;
    await phase("slow-upload", async () => {
      await a.cycle();
      return { completed: true };
    });
    const b = await w.device("uploaded-reader");
    await b.cycle();
    if (JSON.stringify(await a.rows()) !== JSON.stringify(await b.rows()))
      throw Error("slow upload semantic mismatch");
  }
  if (mode === "progressive") {
    // Produce a large snapshot through the real publication path, then a removal tail.
    globalThis.memoryForcePublicationCompaction = true;
    for (let i = 0; i < 3; i++) {
      await a.run("tail" + i, [{ stream: "s0", id: n + i }], { full: false });
      await a.cycle();
      globalThis.memoryForcePublicationCompaction = false;
    }
    await intake("omit", 2, Math.max(1, Math.floor(n / 2)));
    await a.cycle();
    const b = await w.device("b", {
      progressiveFirstLoad: true,
      keyedFirstLoad: false,
      maxBytesInFlight: C,
    });
    await phase("progressive", async () => {
      await b.cycle();
      return {
        snapshot: (await readLogState(a.deps, CONNECTION_ID)).snapshot !== null,
      };
    });
    if (JSON.stringify(await a.rows()) !== JSON.stringify(await b.rows()))
      throw Error("progressive row equivalence");
  }
  if (mode === "jobs") await jobProbe();
  if (mode === "receipts") await receiptProbe();
  if (mode === "many-streams")
    await phase("many-streams", async () => {
      const b = await w.device("many-reader");
      await b.cycle();
      if (JSON.stringify(await a.rows()) !== JSON.stringify(await b.rows()))
        throw Error("stream directory lost rows");
      const complete = await b.db.query(
        "SELECT stream,complete FROM stream_state ORDER BY stream",
      );
      if (complete.length !== 512 || complete.some((r) => r.complete !== 1))
        throw Error("stream directory completion");
      return { streams: complete.length, equivalent: true };
    });
  if (mode === "crypto") await cryptoProbe();
  if (mode === "replace" || mode === "metadata") {
    await intake("changed", 2);
    await phase("covered-replace", () => a.cycle().then(() => ({})));
    if (mode === "metadata") await indexedProbe();
    const [changed] = await a.db.query(
      "SELECT COUNT(*) AS n FROM records WHERE stamp_r='changed'",
    );
    if (changed.n !== n)
      throw Error("replacement did not change every source record");
    await intake("omitted", 3, 1);
    await phase("omission", () => a.cycle().then(() => ({})));
    const [remaining] = await a.db.query("SELECT COUNT(*) AS n FROM records");
    if (remaining.n !== 1)
      throw Error("replacement did not publish every omission");
    const b = await w.device("b");
    await b.cycle();
    if (JSON.stringify(await a.rows()) !== JSON.stringify(await b.rows()))
      throw Error("replacement row equivalence");
  }
} finally {
  await closeWorldDrivers();
}

async function inflatedHistory(log, copies) {
  if (log.snapshot) throw Error("history fixture requires unsnapshotted seed");
  const context = {
    connector: "fixture",
    ns: "",
    keyCheck: await deriveKeyCheck(identityKeys.namespaceHmac),
  };
  const refs = [];
  for (let copy = 0; copy <= copies; copy++)
    for (const ref of log.refs) {
      const { segment } = await fetchSegment(
        a.deps,
        LOG,
        context,
        ref.dataHash,
        ref.position,
      );
      const operations = segment.operations.map((op) =>
        copy === copies
          ? op
          : op.kind === "complete"
            ? { ...op, cutoff: { ...op.cutoff, o: op.cutoff.o - 100 } }
            : {
                ...op,
                stamp: { ...op.stamp, o: op.stamp.o - 100 },
                ...(op.kind === "upsert"
                  ? { value: { ...op.value, v: 0 } }
                  : {}),
              },
      );
      const position = refs.length + 1;
      const next = {
        ...segment,
        position,
        refs: [...refs],
        base: 0,
        snapshot: null,
        operations,
      };
      const clear = encodeSegment(next);
      const digest = await digestSegment(
        async (b) => nobleStreamCrypto.keccak256(b),
        clear,
      );
      await globalThis.memoryBlobs.put(LOG + "/" + digest.blobName, clear);
      refs.push({ position, dataHash: digest.dataHash, bytes: clear.length });
    }
  return { position: refs.length, base: 0, snapshot: null, refs };
}
async function jobProbe() {
  await phase("queued-cancelled-jobs", async () => {
    const queue = connectionQueue();
    const log = await readLogState(a.deps, CONNECTION_ID);
    const input = {
      connector: "fixture",
      ns: "",
      generation: 1,
      keyCheck: await deriveKeyCheck(identityKeys.namespaceHmac),
      scope: LOG,
      log,
    };
    maxHeavyFolds = 0;
    // Real planners enter the decoded-input ownership barrier concurrently.
    // A future heavy-job admission owner must guard this path; ordinary light
    // connection callbacks remain free to run concurrently.
    await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        queue.run("heavy-" + i, "publish", () => planCompaction(a.deps, input)),
      ),
    );
    let release;
    const barrier = new Promise((r) => (release = r));
    const blocked = queue.run("cancelled", "publish", () => barrier);
    let cancelledStarted = 0;
    const waiters = [];
    for (let i = 0; i < 16; i++) {
      const signal = new AbortController();
      const waiter = queue.run("cancelled", "publish", async () => {
        if (signal.signal.aborted) throw new Error("caller-aborted");
        cancelledStarted++;
        return planCompaction(a.deps, input);
      });
      signal.abort();
      waiters.push(waiter);
    }
    // The queue owns no AbortSignal API: the caller checks cancellation before
    // building. This equality check ensures rejected jobs do not poison its tail.
    release();
    await blocked;
    const outcomes = await Promise.allSettled(waiters);
    const cancelled = outcomes.filter(
      (x) =>
        x.status === "rejected" && String(x.reason).includes("caller-aborted"),
    ).length;
    if (cancelled !== 16 || cancelledStarted !== 0)
      throw Error("queued cancellation allocated a plan");
    if ((await queue.run("cancelled", "publish", async () => 42)) !== 42)
      throw Error("cancelled tail poisoned next job");
    return {
      maxHeavyJobs: maxHeavyFolds,
      cancelled,
      cancelledStarted,
      settled: true,
    };
  });
}
async function receiptProbe() {
  const b = await w.device("receipts");
  const [connection] = await a.db.query(
    "SELECT connection_id,connector,ns,generation,control_state,control_version FROM connections WHERE connection_id=?",
    [CONNECTION_ID],
  );
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES(?,?,?,?,?,?)",
      params: [
        connection.connection_id,
        connection.connector,
        connection.ns,
        connection.generation,
        connection.control_state,
        connection.control_version,
      ],
    },
  ]);
  const schema = await bootstrapSchema(b.db, false);
  const meta = {
    stream: "s0",
    primaryKey: ["id"],
    profile: { key: null, version: "1" },
    complete: true,
  };
  const refs = Array.from({ length: 5000 }, (_, i) => ({
    position: i + 1,
    dataHash: "0x" + (i + 1).toString(16).padStart(64, "0"),
    bytes: 200,
    removes: false,
  }));
  await b.db.batch([
    { sql: schema.table },
    {
      sql: "INSERT INTO bootstrap_load(id,connection_id,generation,base,preview_done) VALUES(1,?,1,0,1)",
      params: [CONNECTION_ID],
    },
  ]);
  for (let i = 0; i < refs.length; i += 100)
    await b.db.batch(
      refs.slice(i, i + 100).map((ref) => ({
        sql: "INSERT INTO bootstrap_segments VALUES(?,?,1,0,1000,?,0)",
        params: [ref.position, ref.dataHash, JSON.stringify([meta])],
      })),
    );
  await phase("receipt-growth", async () => {
    const head = {
      format: 2,
      connector: "fixture",
      ns: "",
      generation: 1,
      keyCheck: await deriveKeyCheck(identityKeys.namespaceHmac),
      position: 5000,
      base: 0,
      snapshot: null,
      refs: refs.slice(0, -1),
      streams: [meta],
      observedAt: 1000,
      operations: [],
    };
    const result = await loadBootstrap({
      deps: b.deps,
      connectionId: CONNECTION_ID,
      generation: 1,
      base: 0,
      head,
      refs,
      fetch: async () => {
        throw Error("receipted unit fetched again");
      },
      state: { position: 5000, base: 0, snapshot: null, refs },
    });
    if (
      result !== 5000 ||
      (await readLogState(b.deps, CONNECTION_ID)).position !== 5000
    )
      throw Error("receipt replay failed");
    if ((await b.db.query("SELECT * FROM bootstrap_segments")).length !== 0)
      throw Error("receipt cleanup failed");
    return { receipts: 5000, committed: true };
  });
}
async function cryptoProbe() {
  await a.run(
    "encrypted-reference",
    [{ stream: "s0", id: 2, pad: C + 65536 }],
    { full: false },
  );
  await a.cycle();
  const receiver = await w.device("crypto-reader");
  await receiver.cycle();
  if (JSON.stringify(await a.rows()) !== JSON.stringify(await receiver.rows()))
    throw Error("encrypted receiver diverged");
  // Observe whole-unit allocations at actual codec/AEAD primitive boundaries.
  // These coefficients describe this Node fixture, not unseen native/browser copies.
  const snapshots = [];
  const capture = () => snapshots.push(process.memoryUsage());
  const port = {
    ...nobleStreamCrypto,
    seal: (...args) => {
      capture();
      const out = nobleStreamCrypto.seal(...args);
      capture();
      return out;
    },
    open: (...args) => {
      capture();
      const out = nobleStreamCrypto.open(...args);
      capture();
      return out;
    },
  };
  global.gc?.();
  const start = process.memoryUsage();
  const key = new Uint8Array(32);
  const record = { id: 1, pad: 'é\\"'.repeat(65536) };
  const recordWire = Buffer.from(canonicalJson(record));
  capture();
  const parsed = JSON.parse(recordWire.toString("utf8"));
  capture();
  const R = recordWire.length;
  const recordHeap =
    Math.max(...snapshots.map((x) => x.heapUsed)) - start.heapUsed;
  const recordExternal =
    Math.max(...snapshots.map((x) => x.arrayBuffers)) - start.arrayBuffers;
  snapshots.length = 0;
  global.gc?.();
  const partStart = process.memoryUsage();
  const clear = new Uint8Array(C);
  clear.set(recordWire);
  capture();
  const cipher = sealBytes(key, clear, randomBytes, port);
  capture();
  const back = openBytes(key, cipher, port);
  capture();
  if (
    !Buffer.from(back).equals(Buffer.from(clear)) ||
    parsed.pad !== record.pad
  )
    throw Error("real encryption roundtrip");
  const maxBuffers =
    Math.max(...snapshots.map((x) => x.arrayBuffers)) - partStart.arrayBuffers;
  const maxHeap =
    Math.max(...snapshots.map((x) => x.heapUsed)) - partStart.heapUsed;
  // The three deliberately retained whole buffers are C copies. Remaining
  // observed allocation (including collectible scratch) is charged to crypto.
  const streamScratch =
    Math.max(0, maxBuffers - (clear.length + cipher.length + back.length)) +
    Math.max(0, maxHeap);
  snapshots.length = 0;
  global.gc?.();
  const controlStart = process.memoryUsage();
  const control = randomBytes(1024 * 1024);
  capture();
  const encryptedControl = await globalThis.memoryKeys.encrypt(LOG, control);
  capture();
  const openedControl = await globalThis.memoryKeys.decrypt(
    LOG,
    encryptedControl,
  );
  capture();
  if (!Buffer.from(openedControl).equals(control))
    throw Error("real control encryption roundtrip");
  const controlBuffers =
    Math.max(...snapshots.map((x) => x.arrayBuffers)) -
    controlStart.arrayBuffers;
  const controlHeap =
    Math.max(...snapshots.map((x) => x.heapUsed)) - controlStart.heapUsed;
  const controlScratch =
    Math.max(
      0,
      controlBuffers -
        control.length -
        encryptedControl.length -
        openedControl.length,
    ) + Math.max(0, controlHeap);
  const Bcrypto = Math.max(streamScratch, controlScratch);
  const bC = (clear.length + cipher.length + back.length) / C;
  const bR = Math.max(0, recordHeap + recordExternal) / R;
  const ledger = {
    host: "desktop host",
    Bdb: 8388608,
    P: 65536,
    H0: 1048576,
    R,
    C,
    T: 0,
    Bcrypto,
    bR,
    bC,
    bT: 0,
  };
  console.log(
    JSON.stringify({
      phase: "crypto-calibration",
      n,
      pad,
      roundtrip: true,
      algorithm: "production STREAM ChaCha20-Poly1305 and OpenPGP control",
      encryptedObjects: globalThis.memoryBlobs
        .keys()
        .filter((k) => readFileSync(file(k))[0] === 0x56).length,
      ledger,
      observations: {
        streamScratch,
        controlScratch,
        controlBuffers,
        controlHeap,
        controlCipherBytes: encryptedControl.length,
        recordHeap,
        recordExternal,
        maxBuffers,
        maxHeap,
        samples: snapshots.length,
        transport: "direct SQLite; no serialized bridge frame",
      },
      scope:
        "observed allocation high-water at instrumented STREAM and control boundaries; not a universal peak guarantee",
    }),
  );
}

async function indexedProbe() {
  await phase("indexed-page-control", async () => {
    const sql =
      "SELECT pk_hash FROM records WHERE connection_id=? AND stream=? AND pk_hash>? ORDER BY pk_hash LIMIT 256";
    let after = "",
      count = 0,
      hash = createHash("sha256");
    for (;;) {
      const rows = await a.db.query(sql, [CONNECTION_ID, "s0", after]);
      for (const row of rows) {
        hash.update(row.pk_hash);
        count++;
      }
      if (rows.length < 256) break;
      after = rows.at(-1).pk_hash;
    }
    const expected = createHash("sha256");
    for (const row of nativeDBs
      .get("a")
      .prepare(
        "SELECT pk_hash FROM records WHERE connection_id=? AND stream=? ORDER BY pk_hash",
      )
      .iterate(CONNECTION_ID, "s0"))
      expected.update(row.pk_hash);
    if (hash.digest("hex") !== expected.digest("hex"))
      throw Error("indexed cursor changed keys");
    return { indexedCount: count, equivalent: true };
  });
}
