// Isolated offline reproduction. Identity crypto intentionally excludes crypto coefficients.
import Database from "better-sqlite3";
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
import { deriveKeyCheck } from "../../packages/stream-sync/src/index.js";
import { endRequest } from "../../packages/core/src/test-utils/run-end.js";
const dir = process.env.MEMORY_DIR;
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
let operationBytes = 0;
globalThis.memoryOperations = (ops) => {
  if (active) {
    let total = 0;
    for (const op of ops.values()) total += bytes(op);
    operationBytes = Math.max(operationBytes, total);
  }
};
const bytes = (v) =>
  Buffer.byteLength(
    JSON.stringify(v, (_, x) => (typeof x === "bigint" ? String(x) : x)),
  );
const sample = () => {
  if (active) peak = Math.max(peak, process.memoryUsage().rss);
};
globalThis.memoryDecoded = (value) => {
  if (active) decoded.push({ ref: new WeakRef(value), bytes: bytes(value) });
};
globalThis.memoryDriver = (id) => {
  const db = new Database(join(dir, id + ".db"));
  db.pragma("journal_mode=WAL");
  db.pragma("cache_size=-8192");
  db.pragma("temp_store=FILE");
  return {
    info: {
      sqliteVersion: db.prepare("select sqlite_version() v").get().v,
      host: "node",
      persistent: true,
    },
    async query(sql, params = []) {
      const q = db.prepare(sql);
      const rows = q.reader ? q.all(...params) : (q.run(...params), []);
      if (active) {
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
          (s) => db.prepare(s.sql).run(...(s.params ?? [])).changes,
        ),
      }))();
      if (active) {
        batchBytes = Math.max(batchBytes, bytes(ss));
        await new Promise((r) => setImmediate(r));
        global.gc?.();
        livePeak = Math.max(
          livePeak,
          decoded.reduce((n, x) => n + (x.ref.deref() ? x.bytes : 0), 0),
        );
        sample();
      }
      return result;
    },
    async close() {
      db.close();
    },
  };
};
const blobs = join(dir, "blobs");
mkdirSync(blobs);
const file = (key) => join(blobs, Buffer.from(key).toString("hex"));
// Content is on disk; each GET allocates fresh bytes, never an in-memory fixture cache.
globalThis.memoryBlobs = {
  governor: createMemoryStreamSyncBlobs().governor,
  put: async (k, b) => {
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
  streams: 1,
  partTargetBytes: C,
  keyTypes: ["integer"],
});
const a = await w.device("a");
async function intake(run, v, count = n) {
  await a.sync.intake.begin(run, {
    connector: "fixture",
    artifactDigest: "fixture",
    wantFull: true,
    owner: { address: OWNER, leaseId: null },
  });
  let batch = 0;
  for (let i = 0; i < count; i += 50)
    await a.sync.intake.batch(run, {
      batch: batch++,
      records: Array.from({ length: Math.min(50, count - i) }, (_, j) => ({
        stream: "s0",
        data: { id: i + j, v, pad: "p".repeat(pad) },
      })),
    });
  await a.sync.intake.end(
    run,
    endRequest({
      lastBatch: batch - 1,
      streams: ["s0"],
      live: ["s0"],
      provenFullStreams: ["s0"],
    }),
  );
}
async function phase(name, fn) {
  queryBytes = metadataBytes = batchBytes = livePeak = peak = 0;
  decoded = [];
  operationBytes = 0;
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
    n,
    pad,
    baseline,
    peak,
    operationBytes,
    queryBytes,
    metadataBytes,
    batchBytes,
    liveDecodedBytes: livePeak,
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
  await intake("initial", 1);
  await a.cycle();
  const mode = process.env.MEMORY_CASE;
  if (mode === "compaction")
    await phase("compaction", async () => {
      const log = await readLogState(a.deps, CONNECTION_ID);
      const p = await planCompaction(a.deps, {
        connector: "fixture",
        ns: "",
        generation: 1,
        keyCheck: await deriveKeyCheck(async () => new Uint8Array(32)),
        scope: LOG,
        log,
      });
      if (!p) throw Error("planner did not run");
      return {
        outputBytes: p.objects.reduce((n, o) => n + o.cipher.length, 0),
        objects: p.objects.length,
      };
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
  if (mode === "progressive") {
    // Produce a large snapshot through the real publication path, then a removal tail.
    for (let i = 0; i < 20; i++) {
      await a.run("tail" + i, [{ stream: "s0", id: n + i }], { full: false });
      await a.cycle();
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
  if (mode === "replace" || mode === "metadata") {
    await intake("changed", 2);
    await phase("covered-replace", () => a.cycle().then(() => ({})));
    await intake("omitted", 3, 1);
    await phase("omission", () => a.cycle().then(() => ({})));
    const b = await w.device("b");
    await b.cycle();
    if (JSON.stringify(await a.rows()) !== JSON.stringify(await b.rows()))
      throw Error("replacement row equivalence");
  }
} finally {
  await closeWorldDrivers();
}
