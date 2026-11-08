/**
 * Lane P1 (§2.6, memory rule "Reduce a bucket"): the real stream-sync writer
 * (full-server fs files) publishes a large stream with repeated keys, and the
 * publish stays within a stated memory budget.
 *
 * The source is an NDJSON file generated once, deterministically, and read
 * line by line, so the source is never resident. Ciphertext goes to disk
 * files, so the blob store does not count against the writer.
 *
 * Measure: live bytes = `heapUsed + arrayBuffers`, above a forced-GC baseline.
 * Sampled on a timer and after every append. A forced full GC runs only when
 * a raw reading is more than 8 MiB above the last live reading. Without that,
 * uncollected spool-flush buffers read as live. The reported peak can
 * therefore exceed live bytes by at most 8 MiB.
 *
 * Budget (stated before measuring): BUDGET = 6 × P + one record, with
 * P = PART_LIMIT_BYTES (16 MiB). A publish holds one reduce group at a time
 * (about P of winner text, bounded at 2P as UTF-16), one clear part (P) and
 * one cipher part (P). The rest is spool flush buffers (8 MiB each) and read
 * chunks. Winners total more than P in every case here, so the reducer has to
 * split and reduce bucket by bucket to stay in budget.
 *
 * Run with `--expose-gc`. The 312 MiB case runs only with
 * `STREAM_SYNC_P1_BIG=1`. The smaller cases run in CI time.
 * `P1_RESULT=<file>` appends each case's summary as a JSON line.
 */

import { createReadStream, createWriteStream } from "node:fs";
import {
  appendFile,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { describe, expect, it } from "vitest";
import {
  type StreamSyncBlobs,
  StreamSyncWriter,
  createStreamSyncKeyPorts,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  PART_LIMIT_BYTES,
  decodeHead,
  streamScope,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";
import {
  OWNER,
  OWNER_SIGNATURE,
  SERVER_KEY,
  SHAPE,
  accountSigner,
  createFakeStreamSyncRegistry,
  finishedOutcome,
  testStreamSyncHome,
} from "./oracle.test-utils.js";

const NS = "";
const CONNECTOR = "p1-bounded";
const STREAM = "items";
const RECORD_BYTES = 4096;
const P = PART_LIMIT_BYTES;
const BUDGET_BYTES = 6 * P + RECORD_BYTES;
const MiB = 1024 * 1024;
const BIG = process.env.STREAM_SYNC_P1_BIG === "1";

const dataRoot =
  process.env.STREAM_SYNC_P1_DATA_DIR ?? join(tmpdir(), "stream-sync-p1");

interface Case {
  readonly name: string;
  /** Records in the stream, in file order. */
  readonly records: number;
  /** Distinct primary keys. The winner of a key is its last record. */
  readonly distinct: number;
}

// 79,872 × 4 KiB = 312 MiB. Each key appears 2 or 3 times, so the winners
// (32,768 × ~4 KiB ≈ 128 MiB) are more than P and must be reduced bucket by
// bucket.
const REPEATED_BIG: Case = {
  name: "repeated keys, 312 MiB",
  records: 79_872,
  distinct: 32_768,
};
// 10,240 × 4 KiB = 40 MiB with 5,120 keys (winners 20 MiB > P).
const REPEATED_SMALL: Case = {
  name: "repeated keys, 40 MiB",
  records: 10_240,
  distinct: 5_120,
};
// Every key unique: winners equal the stream. 5,120 × 4 KiB = 20 MiB > P.
const UNIFORM_TWIN: Case = {
  name: "uniform keys twin, 20 MiB",
  records: 5_120,
  distinct: 5_120,
};

function recordId(index: number, distinct: number): string {
  return `k${String(index % distinct).padStart(8, "0")}`;
}

/** Deterministic NDJSON: every line is exactly RECORD_BYTES incl. "\n". */
async function ensureSource(path: string, c: Case): Promise<void> {
  const probe = `{"id":"k00000000","seq":"000000000","pad":""}`;
  const padLen = RECORD_BYTES - 1 - Buffer.byteLength(probe);
  const pad = "p".repeat(padLen);
  const expectedSize = c.records * RECORD_BYTES;
  try {
    if ((await stat(path)).size === expectedSize) return;
  } catch {
    // Missing: generate below.
  }
  const out = createWriteStream(path);
  for (let i = 0; i < c.records; i += 1) {
    const line = `${JSON.stringify({
      id: recordId(i, c.distinct),
      seq: String(i).padStart(9, "0"),
      pad,
    })}\n`;
    if (!out.write(line)) await new Promise((r) => out.once("drain", r));
  }
  await new Promise<void>((resolve, reject) => {
    out.end((error?: Error | null) => (error ? reject(error) : resolve()));
  });
  const size = (await stat(path)).size;
  if (size !== expectedSize) {
    throw new Error(
      `source ${path} is ${size} bytes, expected ${expectedSize}`,
    );
  }
}

/** Disk-backed blob store: ciphertext lives in files, not in the heap. */
function diskBlobs(dir: string): StreamSyncBlobs {
  const file = (key: string) => join(dir, encodeURIComponent(key));
  return {
    async put(key, bytes) {
      await writeFile(file(key), bytes);
    },
    async get(key) {
      try {
        return new Uint8Array(await readFile(file(key)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    },
  };
}

/** Live bytes the writer can hold: JS heap plus ArrayBuffer backing stores. */
function liveBytes(): number {
  const m = process.memoryUsage();
  return m.heapUsed + m.arrayBuffers;
}

/**
 * Peak live bytes above a forced-GC baseline. Raw readings include garbage
 * that V8 has not collected yet (an 8 MiB spool flush allocates and drops
 * several such buffers). So the sampler forces a full GC only when the raw
 * reading has risen more than GC_TRIGGER above the last live reading. The
 * peak is the larger of the post-GC readings and the raw readings below the
 * trigger, so it can exceed live bytes by at most GC_TRIGGER.
 */
const GC_TRIGGER = 8 * MiB;

function startSampler() {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (!gc) throw new Error("run with --expose-gc");
  gc();
  gc();
  const base = liveBytes();
  let liveLast = base;
  let peak = 0;
  let samples = 0;
  let forcedGcs = 0;
  const sample = () => {
    let reading = liveBytes();
    if (reading - liveLast > GC_TRIGGER) {
      gc();
      forcedGcs += 1;
      reading = liveBytes();
      liveLast = reading;
    }
    const v = reading - base;
    if (v > peak) peak = v;
    samples += 1;
  };
  const timer = setInterval(sample, 5);
  return {
    sample,
    stop() {
      clearInterval(timer);
      sample();
      return { peak, samples, forcedGcs, base };
    },
  };
}

async function publishStreamFromFile(
  c: Case,
  root: string,
  source: string,
): Promise<{
  head: Head;
  peak: number;
  samples: number;
  forcedGcs: number;
  elapsedMs: number;
}> {
  const registry = createFakeStreamSyncRegistry();
  const blobDir = join(root, "blobs");
  await mkdir(blobDir, { recursive: true });
  const writer = new StreamSyncWriter({
    ownerAddress: OWNER,
    registry,
    blobs: diskBlobs(blobDir),
    home: testStreamSyncHome(createFsStreamSyncFiles(join(root, "device"))),
    keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
    signer: accountSigner(SERVER_KEY),
  });
  const runId = `run-${c.distinct}-${c.records}`;
  const sampler = startSampler();
  const started = Date.now();
  await writer.refreshControls();
  await writer.beginRun({
    runId,
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.UTC(2026, 10, 1),
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream(runId, STREAM, SHAPE);
  const lines = createInterface({
    input: createReadStream(source, { highWaterMark: 64 * 1024 }),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    await writer.append(
      runId,
      STREAM,
      JSON.parse(line) as Record<string, unknown>,
    );
    sampler.sample();
  }
  await writer.finishRun(runId, {
    checkpointCandidate: { cursor: runId },
  });
  await writer.publishPending();
  const { peak, samples, forcedGcs } = sampler.stop();
  const elapsedMs = Date.now() - started;

  const status = await writer.status();
  expect(finishedOutcome(status, runId)?.outcome).toEqual({
    kind: "checkpointed",
    generation: 1,
  });

  // Structural read-back of the published head only (no record bodies).
  const scope = streamScope(CONNECTOR, NS, STREAM);
  const row = await registry.read(scope);
  if (!row.found) throw new Error("stream not published");
  const hex = row.dataHash.toLowerCase().replace(/^0x/, "");
  const cipher = await diskBlobs(blobDir).get(`${scope}/h-${hex}`);
  if (!cipher) throw new Error("head blob missing");
  const decoded = decodeHead(
    await createStreamSyncKeyPorts(OWNER_SIGNATURE).decrypt(scope, cipher),
  );
  if (decoded.kind !== "ok") throw new Error(`head: ${decoded.kind}`);
  return { head: decoded.head, peak, samples, forcedGcs, elapsedMs };
}

function describeCase(c: Case) {
  return `${c.name}: ${c.records} records, ${c.distinct} keys`;
}

function runCase(c: Case) {
  return async () => {
    const root = join(dataRoot, `run-${c.distinct}-${c.records}`);
    await rm(root, { recursive: true, force: true });
    await mkdir(root, { recursive: true });
    const source = join(dataRoot, `source-${c.distinct}-${c.records}.ndjson`);
    await mkdir(dataRoot, { recursive: true });
    await ensureSource(source, c);
    const winnerBytes = c.distinct * RECORD_BYTES;
    const streamBytes = c.records * RECORD_BYTES;

    const result = await publishStreamFromFile(c, root, source);
    const { head, peak, samples, forcedGcs, elapsedMs } = result;

    const summary = {
      case: c.name,
      streamMiB: +(streamBytes / MiB).toFixed(1),
      winnersMiB: +(winnerBytes / MiB).toFixed(1),
      parts: head.parts.length,
      recordCount: head.recordCount,
      maxPartMiB: +(Math.max(...head.parts.map((p) => p.bytes)) / MiB).toFixed(
        2,
      ),
      peakMiB: +(peak / MiB).toFixed(1),
      budgetMiB: +(BUDGET_BYTES / MiB).toFixed(1),
      samples,
      forcedGcs,
      elapsedS: +(elapsedMs / 1000).toFixed(1),
    };
    console.log(`P1 bounded publish ${JSON.stringify(summary)}`);
    if (process.env.P1_RESULT) {
      await appendFile(process.env.P1_RESULT, `${JSON.stringify(summary)}\n`);
    }

    // The workload really grows: winners exceed one part, so the reducer
    // has to split and reduce bucket by bucket.
    expect(winnerBytes).toBeGreaterThan(P);
    expect(head.parts.length).toBeGreaterThan(1);
    expect(head.complete).toBe(true);
    expect(head.recordCount).toBe(c.distinct);
    expect(head.parts.reduce((n, p) => n + p.count, 0)).toBe(c.distinct);
    for (const part of head.parts) expect(part.bytes).toBeLessThanOrEqual(P);

    // The bound itself.
    expect(peak).toBeLessThanOrEqual(BUDGET_BYTES);

    await rm(root, { recursive: true, force: true });
  };
}

describe("stream-sync publish memory is bounded by the part limit (P1)", () => {
  it.skipIf(!BIG)(
    describeCase(REPEATED_BIG),
    runCase(REPEATED_BIG),
    60 * 60 * 1000,
  );
  it.skipIf(BIG)(
    describeCase(REPEATED_SMALL),
    runCase(REPEATED_SMALL),
    10 * 60 * 1000,
  );
  it(describeCase(UNIFORM_TWIN), runCase(UNIFORM_TWIN), 10 * 60 * 1000);
});
