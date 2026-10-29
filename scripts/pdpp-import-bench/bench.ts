/**
 * Times the Lite import encoder on a real spool, the way the phone drives it
 * (unity-surfaces `ps_bundle/src/native-import-jobs.js`): the engine stages
 * each batch's encoded entries into the native store, and the encoder reads
 * the job's staged view through the bridge.
 *
 *   npx tsx scripts/pdpp-import-bench/bench.ts --spool <dir with spool.json
 *     and import-spools/> --db <sqlite path> [--batched 0|1] [--call-ms 0.5]
 *     [--records N] [--reference 1]
 *
 * The native store is `host-double.ts`. Reported: encoder CPU (process CPU
 * during encoding, less the double's SQLite time), modeled bridge time of
 * the encoder's reads, and their sum, which the 60 s target bounds.
 * `--reference 1` also saves each batch with Lite's own `commitLocal` into a
 * second store and compares the canonical entries after publication.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { open } from "node:fs/promises";
import { join } from "node:path";
import {
  createPdppImportJobs,
  importSpool,
  ImportJobError,
  PDPP_IMPORT_JOB_CONTRACT_VERSION,
  type ImportBatchReceipt,
  type ImportJobRecord,
  type PdppImportJobCapability,
} from "../../packages/core/src/storage/pdpp-import-job/index.js";
import type { DeclarationBinding } from "../../packages/core/src/replication/envelope.js";
import { createLiteCanonicalStore } from "../../packages/lite/src/canonical-store.js";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "../../packages/lite/src/canonical-persistence.js";
import { createLiteCanonicalImportEncoder } from "../../packages/lite/src/import-job.js";
import { createImportHostDouble } from "./host-double.js";

const args: Record<string, string> = {};
for (let i = 2; i < process.argv.length; i += 2)
  args[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
const spoolDir = args.spool;
const spooled = JSON.parse(readFileSync(join(spoolDir, "spool.json"), "utf8"));
const spoolPath = join(spoolDir, "import-spools", `${spooled.spool.id}.ndjson`);
const batched = args.batched !== "0";
const callMs = Number(args["call-ms"] ?? 0.5);

const OWNER = "0x00000000000000000000000000000000000b3c4e";
const INSTANCE = "bench-connection";
const METHOD = spooled.namespace as string;
const SOURCE = `https://registry.pdpp.dev/sources/${METHOD}`;
const streams = spooled.streams as string[];
const bindings = new Map<string, DeclarationBinding>(
  streams.map((stream) => [
    stream,
    {
      digest: `sha256:${createHash("sha256").update(`${METHOD}/${stream}`).digest("hex")}`,
      version: "1.0.0",
      stream,
      semantics: "mutable_state",
      primaryKey: ["id"],
      schemaDigest: `sha256:${"b".repeat(64)}`,
    },
  ]),
);
const context = () => ({
  owner: OWNER,
  declarations: streams.map((stream) => ({
    sourceId: SOURCE,
    binding: bindings.get(stream)!,
    validateData: () => true,
  })),
});
const ids = (prefix: string) => {
  let n = 0;
  return () => `${prefix}-${n++}`;
};

for (const suffix of ["", "-wal", "-shm"])
  if (existsSync(args.db + suffix)) rmSync(args.db + suffix);
const host = createImportHostDouble(args.db, callMs);

type Host = ReturnType<typeof createImportHostDouble>;

/** Lite's own persistence over a double's canonical table (setup and reference). */
function canonicalPersistence(target: Host): LiteCanonicalPersistence {
  return {
    async transaction(run) {
      const writes = new Map<string, string | null>();
      const tx: LiteCanonicalTransaction = {
        get: async (key) =>
          writes.has(key)
            ? (writes.get(key) ?? undefined)
            : target.canonical.get(key),
        put: async (key, value) => void writes.set(key, value),
        delete: async (key) => void writes.set(key, null),
        scan: async (prefix, after) => {
          // Merge the transaction's writes over the canonical prefix.
          const merged = new Map<string, string>();
          let cursor: string | undefined;
          do {
            const page = target.canonical.page(prefix, cursor);
            for (const entry of page.entries)
              merged.set(entry.key, entry.value);
            cursor = page.after;
          } while (cursor !== undefined);
          for (const [key, value] of writes)
            if (key.startsWith(prefix))
              if (value === null) merged.delete(key);
              else merged.set(key, value);
          const sorted = [...merged]
            .filter(([key]) => after === undefined || key > after)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
          const entries = sorted
            .slice(0, 100)
            .map(([key, value]) => ({ key, value }));
          return entries.length < sorted.length
            ? { entries, after: entries.at(-1)!.key }
            : { entries };
        },
        attachBlob: () => Promise.reject(new Error("no blobs")),
        blob: async () => undefined,
      };
      const result = await run(tx);
      target.canonical.write(writes);
      return result;
    },
    stageBlob: () => Promise.reject(new Error("no blobs")),
    readBlob: () => {
      throw new Error("no blobs");
    },
  };
}

const liteOver = (target: Host, newId: () => string) =>
  createLiteCanonicalStore({
    persistence: canonicalPersistence(target),
    context,
    authenticateReplica: () => undefined,
    enabled: true,
    newId,
  });

/** The provisioned, registered connection an import starts from. */
async function provision(target: Host) {
  const lite = liteOver(target, ids("setup"));
  await lite.provisionConnection(INSTANCE, {
    sourceId: SOURCE,
    methodId: METHOD,
  });
  await lite.commitLocal("register", [
    {
      owner: OWNER,
      sourceId: SOURCE,
      connectionId: INSTANCE,
      methodId: METHOD,
      generation: 1,
      kind: "connection-register",
    },
  ]);
}
await provision(host);

/** The native capability, as `native-import-jobs.js` reaches it, in memory. */
const jobs = new Map<string, ImportJobRecord>();
const receipts = new Map<string, ImportBatchReceipt>();
const spoolFile = await open(spoolPath, "r");
const capability: PdppImportJobCapability = {
  contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,
  publication: { mode: "native-staged-copy", outbox: "by-reference" },
  readBinding: async () => ({
    sourceId: SOURCE,
    method: METHOD,
    generation: 1,
    deleted: false,
  }),
  createJob: async (job) => {
    jobs.set(job.jobId, structuredClone(job));
    return structuredClone(job);
  },
  readJob: async (jobId) => structuredClone(jobs.get(jobId)),
  async stageBatch({ job, receipt, canonical }) {
    if (!canonical) throw new ImportJobError("invalid_request");
    host.stage(job.jobId, canonical.entries);
    receipts.set(`${job.jobId}\0${receipt.seq}`, receipt);
    // The engine passes the job as it is after this batch.
    jobs.set(job.jobId, structuredClone(job));
    return receipt;
  },
  readBatchReceipt: async (jobId, seq) => receipts.get(`${jobId}\0${seq}`),
  async publish(input) {
    host.publish(input.job.jobId);
    const job = jobs.get(input.job.jobId)!;
    jobs.set(job.jobId, { ...job, state: "committed" });
    return {
      jobId: job.jobId,
      contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,
      instance: INSTANCE,
      generation: 1,
      batches: job.nextSeq,
      records: job.records,
      operations: 0,
      accepted: 0,
      unchanged: 0,
      rejected: job.rejected,
      completedStreams: [],
      connectorStateSha256: input.connectorStateSha256,
      committedAt: input.committedAt,
    };
  },
  abort: async (jobId) => jobs.get(jobId),
  readConnectorState: async () => undefined,
  async readSpool(_spool, offset, maxBytes) {
    const buffer = Buffer.alloc(maxBytes);
    const { bytesRead } = await spoolFile.read(buffer, 0, maxBytes, offset);
    return new Uint8Array(buffer.subarray(0, bytesRead));
  },
};

const encoder = createLiteCanonicalImportEncoder({ context, newId: ids("op") });
const bindingFor = (stream: string) => bindings.get(stream);
const reference: { id: string; operations: unknown[] }[][] = [];
let encodeCpuMs = 0;
let encodeWallMs = 0;
let parts = 0;
const engine = createPdppImportJobs({
  capability,
  declarations: {
    forInstance: (instance, stream) =>
      instance === INSTANCE && bindings.has(stream)
        ? { semantics: "mutable_state", primaryKey: ["id"] }
        : undefined,
  },
  owner: OWNER,
  async encodeBatch({ job, seq, operations }) {
    const cpu = process.cpuUsage();
    const wall = performance.now();
    const sqliteBefore = [...host.stats.values()].reduce(
      (sum, s) => sum + s.sqliteMs,
      0,
    );
    const batchParts = encoder.importBatchParts({
      job,
      seq,
      operations,
      bindingFor,
    });
    parts += batchParts.length;
    if (args.reference === "1") reference.push(structuredClone(batchParts));
    const { entries, fence } = await encoder.encode(
      host.view(job.jobId, batched),
      batchParts,
    );
    const used = process.cpuUsage(cpu);
    const sqliteMs =
      [...host.stats.values()].reduce((sum, s) => sum + s.sqliteMs, 0) -
      sqliteBefore;
    encodeCpuMs += (used.user + used.system) / 1000 - sqliteMs;
    encodeWallMs += performance.now() - wall;
    return { entries, fence };
  },
});

const jobId = `bench-${spooled.spool.id}`;
const started = performance.now();
let peakHeap = 0;
const sampler = setInterval(() => {
  peakHeap = Math.max(peakHeap, process.memoryUsage().heapUsed);
}, 250);
await engine.begin({
  jobId,
  binding: {
    owner: OWNER,
    instance: INSTANCE,
    sourceId: SOURCE,
    method: METHOD,
    generation: 1,
  },
  spool: spooled.spool,
  streams,
});
const status = await importSpool(engine, jobId, capability.readSpool!);
const stageMs = performance.now() - started;
clearInterval(sampler);
await engine.commit({ jobId, batches: status.job.nextSeq });

function digestCanonical(db: typeof host.db) {
  const hash = createHash("sha256");
  let count = 0;
  for (const row of db
    .prepare("SELECT k, v FROM canonical_kv ORDER BY k")
    .iterate() as IterableIterator<{ k: string; v: string }>) {
    hash.update(`${row.k}\0${row.v}\n`);
    count++;
  }
  return { count, sha256: hash.digest("hex") };
}

const bridgeMs = host.bridgeMs();
const result: Record<string, unknown> = {
  spool: spooled.spool.id,
  records: status.job.records,
  batches: status.job.nextSeq,
  parts,
  batchedReads: batched,
  callMs,
  stageWallMs: Math.round(stageMs),
  encodeWallMs: Math.round(encodeWallMs),
  encodeCpuMs: Math.round(encodeCpuMs),
  bridgeMs: Math.round(bridgeMs),
  encodePlusReadsMs: Math.round(encodeCpuMs + bridgeMs),
  peakJsHeapMb: Math.round(peakHeap / 1024 / 1024),
  calls: Object.fromEntries(
    [...host.stats].map(([op, s]) => [
      op,
      { calls: s.calls, items: s.items, sqliteMs: Math.round(s.sqliteMs) },
    ]),
  ),
  canonical: digestCanonical(host.db),
};

if (args.reference === "1") {
  // Lite's own save of the same parts, with the same ids, into a fresh store.
  const referenceDb = `${args.db}.reference`;
  for (const suffix of ["", "-wal", "-shm"])
    if (existsSync(referenceDb + suffix)) rmSync(referenceDb + suffix);
  const other = createImportHostDouble(referenceDb, callMs);
  await provision(other);
  const lite = liteOver(other, ids("op"));
  for (const batch of reference)
    for (const part of batch)
      await lite.commitLocal(part.id, part.operations as never);
  const expected = digestCanonical(other.db);
  result.reference = {
    ...expected,
    identical:
      expected.sha256 === (result.canonical as { sha256: string }).sha256,
  };
}

if (process.env.BENCH_SHAPES)
  result.scanShapes = Object.fromEntries(
    [...host.shapes].sort((a, b) => b[1].ms - a[1].ms).slice(0, 15),
  );
console.log(JSON.stringify(result, null, 2));
