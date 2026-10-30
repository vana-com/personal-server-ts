import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  IMPORT_VECTOR_INSTANCE as INSTANCE,
  IMPORT_VECTOR_METHOD as METHOD,
  IMPORT_VECTOR_OWNER as OWNER,
  IMPORT_VECTOR_SOURCE as SOURCE,
  PDPP_IMPORT_SPOOL_FORMAT,
  type ImportJobBeginInput,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";

/**
 * Peak memory of an import is bounded by the batch and the largest record,
 * not by the export. Each size runs in a child whose V8 heap is capped well
 * below the spool size, so any whole-file read or whole-job buffer fails.
 *
 * CI runs one 32 MB spool. The full proof sets
 * `PDPP_IMPORT_MEMORY_SIZES_MB=32,128,313` (and a disk-backed TMPDIR).
 */
const SIZES_MB = (process.env.PDPP_IMPORT_MEMORY_SIZES_MB ?? "32")
  .split(",")
  .map(Number);
/** Heap cap for the child: idle runtime + batches in flight + one giant record. */
const HEAP_CAP_MB = 160;
/** RSS growth allowed over idle: the heap cap plus native SQLite and buffers. */
const RSS_GROWTH_MB = 352;
const GIANT_RECORD_BYTES =
  Number(process.env.PDPP_IMPORT_MEMORY_GIANT_MB ?? "12") * 1024 * 1024;

const dir = mkdtempSync(join(tmpdir(), "pdpp-import-memory-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const TEXTS = [
  "Grüße aus München — straße, Øresund, naïve café",
  "こんにちは世界、今日はいい天気ですね。データの持ち運び",
  "👋🏽 emoji 🚀 mixed with ASCII and ‘quotes’ and “more”",
  "Привет, как дела? Ελληνικά κείμενα. עברית. العربية",
];

/**
 * Writes a synthetic export of about `targetBytes`: many small non-ASCII
 * messages, one giant conversation, append-only events and, in the second
 * half, a delete-heavy delta (two of every five earlier messages deleted,
 * one re-upserted). Returns the spool handle.
 */
function writeSyntheticSpool(path: string, targetBytes: number) {
  const fd = openSync(path, "w");
  const hash = createHash("sha256");
  let written = 0;
  let pending: string[] = [];
  let pendingBytes = 0;
  let records = 0;
  const flush = () => {
    const chunk = Buffer.from(pending.join(""), "utf8");
    hash.update(chunk);
    writeSync(fd, chunk);
    written += chunk.byteLength;
    pending = [];
    pendingBytes = 0;
  };
  const emit = (record: unknown) => {
    const line = JSON.stringify(record) + "\n";
    pending.push(line);
    pendingBytes += line.length;
    records += 1;
    if (pendingBytes > 1 << 20) flush();
  };
  const at = (n: number) =>
    new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
  const message = (i: number, text: string) => ({
    stream: "messages",
    key: `m${i}`,
    data: {
      id: `m${i}`,
      conversation_id: `c${i >> 6}`,
      author: i % 2 ? "user" : "assistant",
      text: `${TEXTS[i % TEXTS.length]} ${text} ${"·".repeat(200 + (i % 400))}`,
    },
    emitted_at: at(i),
  });

  const half = targetBytes / 2;
  let i = 0;
  let giantWritten = false;
  while (written + pendingBytes < half) {
    emit(message(i, "first"));
    if (i % 64 === 0)
      emit({
        stream: "conversations",
        key: `c${i >> 6}`,
        data: { id: `c${i >> 6}`, title: `${TEXTS[i % 4].slice(0, 12)} ${i}` },
        emitted_at: at(i),
      });
    if (i % 16 === 0)
      emit({
        stream: "events",
        key: `e${i}`,
        data: { id: `e${i}`, kind: "opened" },
        emitted_at: at(i),
      });
    if (!giantWritten && written + pendingBytes > half / 2) {
      // One giant conversation: thousands of nested nodes on a single line.
      const nodes = [];
      let size = 0;
      for (let n = 0; size < GIANT_RECORD_BYTES; n++) {
        const node = { id: `n${n}`, parent: `n${n - 1}`, text: TEXTS[n % 4] };
        nodes.push(node);
        size += JSON.stringify(node).length * 2;
      }
      emit({
        stream: "conversations",
        key: "giant",
        data: { id: "giant", title: "giant", mapping: nodes },
        emitted_at: at(i),
      });
      giantWritten = true;
    }
    i += 1;
  }
  const firstHalf = i;
  for (let j = 0; written + pendingBytes < targetBytes; j++) {
    const k = j % firstHalf;
    if (k % 5 < 2)
      emit({
        stream: "messages",
        key: `m${k}`,
        op: "delete",
        emitted_at: at(i + j),
      });
    else if (k % 5 === 2) emit(message(k, "edited"));
    else emit(message(firstHalf + j, "new"));
  }
  flush();
  closeSync(fd);
  return {
    records,
    handle: {
      id: "spool",
      format: PDPP_IMPORT_SPOOL_FORMAT,
      byteLength: written,
      sha256: hash.digest("hex"),
    },
  };
}

interface ChildResult {
  batches: number;
  records: number;
  rejected: number;
  operations: number;
  idleHeapUsed: number;
  peakHeapUsed: number;
  idleRss: number;
  maxRss: number;
}

function runChild(
  dbPath: string,
  spoolPath: string,
  begin: ImportJobBeginInput,
) {
  const adapterUrl = new URL("./pdpp-import-jobs-sqlite.ts", import.meta.url)
    .href;
  const storeUrl = new URL("./pdpp-records-sqlite-store.ts", import.meta.url)
    .href;
  const code = `
    import Database from 'better-sqlite3';
    import {createSqliteRecordStore} from '${storeUrl}';
    import {createSqliteImportJobCapability} from '${adapterUrl}';
    import {createPdppImportJobs, importSpool, importVectorDeclarations} from '@opendatalabs/personal-server-ts-core/storage/pdpp-import-job';
    const db = new Database(${JSON.stringify(dbPath)});
    db.pragma('journal_mode = WAL');
    const store = createSqliteRecordStore(db);
    store.registerConnection({instance: '${INSTANCE}', sourceId: '${SOURCE}', method: '${METHOD}', label: 'bench'});
    const capability = createSqliteImportJobCapability(db, store, {spoolPath: () => ${JSON.stringify(spoolPath)}});
    const jobs = createPdppImportJobs({capability, declarations: importVectorDeclarations, owner: '${OWNER}'});
    globalThis.gc();
    const idleHeapUsed = process.memoryUsage().heapUsed;
    const idleRss = process.memoryUsage().rss;
    let peakHeapUsed = idleHeapUsed;
    const sample = () => { peakHeapUsed = Math.max(peakHeapUsed, process.memoryUsage().heapUsed); };
    await jobs.begin(${JSON.stringify(begin)});
    const status = await importSpool(jobs, 'job-1', capability.readSpool, {onBatch: sample});
    sample();
    const receipt = await jobs.commit({jobId: 'job-1', batches: status.job.nextSeq, connectorState: '{"cursor":"end"}'});
    sample();
    process.stdout.write(JSON.stringify({
      batches: receipt.batches, records: receipt.records, rejected: receipt.rejected,
      operations: receipt.operations, idleHeapUsed, peakHeapUsed, idleRss,
      maxRss: process.resourceUsage().maxRSS * 1024,
    }));
  `;
  const child = spawnSync(
    process.execPath,
    [
      `--max-old-space-size=${HEAP_CAP_MB}`,
      "--expose-gc",
      "--import",
      "tsx",
      "--input-type=module",
      "-e",
      code,
    ],
    { encoding: "utf8", timeout: 900_000, maxBuffer: 1 << 20 },
  );
  if (child.status !== 0)
    throw new Error(
      `child failed (${child.signal ?? child.status}): ${child.stderr}`,
    );
  return JSON.parse(child.stdout) as ChildResult;
}

const mb = (bytes: number) => Math.round((bytes / (1 << 20)) * 10) / 10;

const peaks: number[] = [];

describe("import job memory", () => {
  it.each(SIZES_MB.map((size) => ({ size })))(
    "imports a $size MB export under a $size-independent heap cap",
    ({ size }) => {
      const spoolPath = join(dir, `spool-${size}.ndjson`);
      const dbPath = join(dir, `records-${size}.db`);
      const spool = writeSyntheticSpool(spoolPath, size * (1 << 20));
      const result = runChild(dbPath, spoolPath, {
        jobId: "job-1",
        binding: {
          owner: OWNER,
          instance: INSTANCE,
          sourceId: SOURCE,
          method: METHOD,
          generation: 1,
        },
        spool: spool.handle,
        streams: ["conversations", "events", "messages"],
      });
      rmSync(spoolPath, { force: true });
      rmSync(dbPath, { force: true });
      rmSync(`${dbPath}-wal`, { force: true });
      rmSync(`${dbPath}-shm`, { force: true });
      const line =
        `${size} MB: ${result.records} records, ${result.batches} batches, ` +
        `${result.operations} operations; heap idle ${mb(result.idleHeapUsed)} MB, ` +
        `peak sampled ${mb(result.peakHeapUsed)} MB (cap ${HEAP_CAP_MB} MB); ` +
        `rss idle ${mb(result.idleRss)} MB, max ${mb(result.maxRss)} MB\n`;
      if (process.env.PDPP_IMPORT_MEMORY_REPORT)
        appendFileSync(process.env.PDPP_IMPORT_MEMORY_REPORT, line);
      expect(result.records).toBe(spool.records);
      expect(result.rejected).toBe(0);
      // The child finished under the heap cap, and RSS growth is bounded.
      expect(result.maxRss - result.idleRss).toBeLessThan(
        RSS_GROWTH_MB * (1 << 20),
      );
      peaks.push(result.maxRss);
    },
    900_000,
  );

  it("keeps peak RSS flat as the export grows", () => {
    if (peaks.length < 2) return;
    expect(Math.max(...peaks) - Math.min(...peaks)).toBeLessThan(
      64 * (1 << 20),
    );
  });
});
