/**
 * Node runner for the bounded-memory oracle (lane P3).
 *
 * Drives the real `StreamSyncWriter` (core) over disk-backed files and blobs.
 * Disk stands in for the phone's native files and IndexedDB: their bytes are
 * not JS heap, so the measured heap is the writer's own working memory plus
 * the copies a Lite host makes at its boundary:
 *   - the clear part and the encrypted copy (both alive during `put`),
 *   - one bridge copy per blob `put` and `get` (the structured clone that
 *     crosses the WebView bridge; simulated with `slice()` / a fresh copy).
 *
 * Heap is sampled after a full GC at every file, blob and cipher boundary, so
 * the sampler needs `node --expose-gc`.
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import {
  StreamSyncWriter,
  bindStreamSyncHome,
  createStreamSyncKeyPorts,
  type StreamSyncBlobs,
  type StreamSyncFiles,
  type StreamSyncKeyPorts,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  decodeHead,
  decodeLine,
  partBlobName,
  streamScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  CONNECTOR,
  RUN_ID,
  STREAM,
  T0,
  expectedCount,
  expectedDigest,
  outputLine,
  recordAt,
  SetDigest,
  type ScenarioSpec,
} from "./stream-sync-heap-scenarios.js";

// Anvil test account #0. Synthetic owner only; never a real key.
const OWNER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const OWNER_SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b";
const NS = "";
const READ_CHUNK = 1024 * 1024;
const CONFIG = ServerConfigSchema.parse({});

export const MiB = 1024 * 1024;

export interface HeapPeak {
  /** Largest heapUsed after GC at any sampled boundary, bytes. */
  readonly peakBytes: number;
  /** Boundary where the peak was seen. */
  readonly peakAt: string;
  /** Largest reading including the uncollected shard reads (conservative). */
  readonly peakBytesUpperBound: number;
  /** Boundary of the upper-bound peak. */
  readonly peakUpperAt: string;
  /** Peak per boundary label, bytes. */
  readonly byLabel: Readonly<Record<string, number>>;
  readonly samples: number;
}

/** Heap plus ArrayBuffer backing stores, after GC has settled. */
function liveBytes(): number {
  const m = process.memoryUsage();
  return m.heapUsed + m.arrayBuffers;
}

/**
 * V8 frees ArrayBuffer backing stores lazily: one gc() leaves them allocated
 * (measured: 96 MiB raw -> 96 MiB after one gc -> 40 MiB after three). So GC
 * repeats until the reading stops falling.
 */
function settledLive(): number {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (!gc) throw new Error("run with node --expose-gc");
  let prev = Infinity;
  let cur = liveBytes();
  for (let i = 0; i < 8 && cur < prev; i += 1) {
    gc();
    prev = cur;
    cur = liveBytes();
  }
  return cur;
}

const GC_TRIGGER = 8 * 1024 * 1024;

export class HeapSampler {
  private peak = 0;
  private peakAt = "";
  private peakUpper = 0;
  private peakUpperAt = "";
  private readonly byLabel: Record<string, number> = {};
  private samples = 0;
  active = true;
  private lastLive = 0;
  private timer: ReturnType<typeof setInterval> | undefined;

  /**
   * Heap after a full GC at a part, blob or flush boundary. `collect: false`
   * is for per-shard reads, which fire hundreds of times per publish: a full
   * GC there costs more than the writer. Their reading is not collected, so
   * it is an upper bound and is reported separately (`peakBytesUpperBound`).
   */
  sample(label: string, options: { collect?: boolean } = {}): void {
    if (!this.active) return;
    const collect = options.collect ?? true;
    if (collect) {
      const used = settledLive();
      this.samples += 1;
      if (used > (this.byLabel[label] ?? 0)) this.byLabel[label] = used;
      if (used > this.peak) {
        this.peak = used;
        this.peakAt = label;
      }
      this.lastLive = used;
      return;
    }
    this.samples += 1;
    const used = liveBytes();
    if (used > this.peakUpper) {
      this.peakUpper = used;
      this.peakUpperAt = label;
    }
  }

  /**
   * Between-boundary sampling, the same method as the p1big lane (PS #565):
   * read raw live bytes on a timer; force a settled GC only when the raw
   * reading is more than GC_TRIGGER above the last settled reading. A raw
   * reading below the trigger can overstate live bytes by at most GC_TRIGGER.
   */
  startTimer(): void {
    this.lastLive = settledLive();
    this.timer = setInterval(() => {
      if (!this.active) return;
      const raw = liveBytes();
      if (raw - this.lastLive > GC_TRIGGER) {
        this.lastLive = settledLive();
        if (this.lastLive > this.peak) {
          this.peak = this.lastLive;
          this.peakAt = "timer";
        }
      } else if (raw > this.peak) {
        this.peak = raw;
        this.peakAt = "timer(raw, <=8MiB over)";
      }
    }, 5);
  }

  stopTimer(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  result(): HeapPeak {
    return {
      peakBytes: this.peak,
      peakAt: this.peakAt,
      peakBytesUpperBound: Math.max(this.peak, this.peakUpper),
      peakUpperAt: this.peakUpper > this.peak ? this.peakUpperAt : this.peakAt,
      byLabel: { ...this.byLabel },
      samples: this.samples,
    };
  }
}

/** Disk-backed `StreamSyncFiles` with the chunked semantics of the Lite adapter. */
export function diskFiles(root: string, sampler: HeapSampler): StreamSyncFiles {
  const abs = (path: string) => join(root, path);
  return {
    async write(path, bytes) {
      const file = abs(path);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(`${file}.tmp`, bytes);
      renameSync(`${file}.tmp`, file);
    },
    async read(path) {
      const file = abs(path);
      if (!existsSync(file)) return null;
      const buf = readFileSync(file);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    },
    async appendMany(entries) {
      sampler.sample("files.appendMany");
      for (const { path, bytes } of entries) {
        const file = abs(path);
        mkdirSync(dirname(file), { recursive: true });
        appendFileSync(file, bytes);
      }
    },
    async sync() {},
    async *readChunks(path) {
      const file = abs(path);
      if (!existsSync(file)) return;
      const size = statSync(file).size;
      const fd = openSync(file, "r");
      try {
        let pos = 0;
        while (pos < size) {
          const want = Math.min(READ_CHUNK, size - pos);
          const buf = Buffer.alloc(want);
          const got = readSync(fd, buf, 0, want, pos);
          if (got <= 0) break;
          pos += got;
          sampler.sample("files.readChunk", { collect: false });
          yield new Uint8Array(buf.buffer, buf.byteOffset, got);
        }
      } finally {
        closeSync(fd);
      }
    },
    async size(path) {
      const file = abs(path);
      return existsSync(file) ? statSync(file).size : 0;
    },
    async list(prefix) {
      const out: string[] = [];
      const walk = (dir: string, rel: string) => {
        if (!existsSync(dir)) return;
        for (const name of readdirSync(dir)) {
          const full = join(dir, name);
          const p = `${rel}/${name}`;
          if (statSync(full).isDirectory()) walk(full, p);
          else out.push(p);
        }
      };
      walk(abs(prefix), prefix);
      return out.sort();
    },
    async remove(prefix) {
      rmSync(abs(prefix), { recursive: true, force: true });
    },
  };
}

/**
 * Write-once blob store behind the bridge boundary. `put` makes the copy a
 * bridge message makes; `get` makes the copy that returns to the caller.
 */
export function bridgeBlobs(
  root: string,
  sampler: HeapSampler,
): StreamSyncBlobs & { keys(): string[] } {
  const keys = new Set<string>();
  return {
    keys: () => [...keys],
    async put(key, bytes) {
      const copy = bytes.slice(); // bridge copy; cipher and clear still alive
      sampler.sample("blobs.put");
      const file = join(root, key);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, copy);
      keys.add(key);
    },
    async get(key) {
      const file = join(root, key);
      if (!existsSync(file)) return null;
      const copy = new Uint8Array(readFileSync(file));
      sampler.sample("blobs.get");
      return copy;
    },
  };
}

/** Exclusive-version registry: POST at version+1 writes, identical replays. */
function fakeRegistry(): StreamSyncRegistry {
  const rows = new Map<string, { dataHash: string; metadataHash: string }[]>();
  return {
    async read(scope): Promise<ControlRead> {
      const versions = rows.get(scope);
      if (!versions || versions.length === 0) return { found: false };
      const head = versions[versions.length - 1]!;
      return {
        found: true,
        version: versions.length,
        dataHash: head.dataHash as `0x${string}`,
        metadataHash: head.metadataHash as `0x${string}`,
        deleted: false,
      } as ControlRead;
    },
    async post(request) {
      const versions = rows.get(request.scope) ?? [];
      const version = Number(request.expectedVersion);
      const existing = versions[version - 1];
      if (
        existing &&
        existing.dataHash === request.dataHash &&
        existing.metadataHash === request.metadataHash
      ) {
        return { kind: "committed" };
      }
      if (version !== versions.length + 1) {
        return { kind: "conflict", latestVersion: String(versions.length) };
      }
      versions.push({
        dataHash: request.dataHash,
        metadataHash: request.metadataHash,
      });
      rows.set(request.scope, versions);
      return { kind: "committed" };
    },
    async listControlRows() {
      return [];
    },
  };
}

export interface RunOptions {
  /** Writer target per part (bytes). Omit for the writer default. */
  readonly partTargetBytes?: number;
  /** Reduce budget per group (bytes). Omit for the writer default. */
  readonly reduceBudgetBytes?: number;
  /** Spool flush batch (bytes). Omit for the writer default. */
  readonly spoolFlushBytes?: number;
  /** Scratch root for this run's files and blobs; the caller removes it. */
  readonly dir: string;
}

export interface RunReport {
  readonly spec: ScenarioSpec;
  readonly heap: HeapPeak;
  readonly baselineBytes: number;
  readonly durationMs: number;
  readonly parts: number;
  readonly partBytesMax: number;
  readonly outputCount: number;
  readonly expectedCount: number;
  readonly digestOk: boolean;
  readonly countOk: boolean;
  readonly tooLargeSpooled: number;
  readonly outcome: string;
}

/**
 * Append every record of `spec` through the real writer, publish, then verify
 * the published output (decrypted head and parts) against the closed form.
 */
export async function runScenario(
  spec: ScenarioSpec,
  options: RunOptions,
): Promise<RunReport> {
  const sampler = new HeapSampler();
  const files = diskFiles(join(options.dir, "files"), sampler);
  const blobs = bridgeBlobs(join(options.dir, "blobs"), sampler);
  const baseKeys = createStreamSyncKeyPorts(OWNER_SIGNATURE);
  const keys: StreamSyncKeyPorts = {
    namespaceHmac: baseKeys.namespaceHmac,
    decrypt: baseKeys.decrypt,
    async encrypt(scope, clear) {
      const cipher = await baseKeys.encrypt(scope, clear);
      sampler.sample("keys.encrypt"); // clear part and cipher both alive
      return cipher;
    },
  };
  const account = privateKeyToAccount(OWNER_KEY);
  const signer = createServerSigner(
    {
      address: account.address,
      publicKey: account.publicKey,
      signTypedData: (p) =>
        account.signTypedData(p as Parameters<typeof account.signTypedData>[0]),
      signMessage: (message) => account.signMessage({ message }),
    },
    { chainId: CONFIG.gateway.chainId, contracts: CONFIG.gateway.contracts },
  );
  const registry = fakeRegistry();
  const writer = new StreamSyncWriter({
    ownerAddress: account.address,
    registry,
    blobs,
    home: bindStreamSyncHome({
      ownerAddress: account.address,
      network: "p3-oracle",
      open: () => files,
    }),
    keys,
    signer,
    partTargetBytes: options.partTargetBytes,
    reduceBudgetBytes: options.reduceBudgetBytes,
    spoolFlushBytes: options.spoolFlushBytes,
  });

  const baseline = await settledHeap();
  sampler.startTimer();
  const started = Date.now();
  await writer.refreshControls();
  await writer.beginRun({
    runId: RUN_ID,
    connector: CONNECTOR,
    userConnect: false,
    observedAt: T0,
    identity: "none",
  });
  await writer.declareStream(RUN_ID, STREAM, {
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
  });
  let tooLargeSpooled = 0;
  for (let seq = 0; seq < spec.records; seq += 1) {
    const result = await writer.append(
      RUN_ID,
      STREAM,
      recordAt(spec, seq) as unknown as Record<string, unknown>,
    );
    if (result === "too_large") tooLargeSpooled += 1;
  }
  await writer.finishRun(RUN_ID, { checkpointCandidate: null });
  sampler.sample("finishRun");
  const report = await writer.cycle();
  const durationMs = Date.now() - started;
  // Sampling stops with the publish; verification reads below are not measured.
  sampler.active = false;
  sampler.stopTimer();

  const outcome =
    report.runs.find((r) => r.runId === RUN_ID)?.streams[STREAM]?.state ??
    "missing";
  const scope = streamScope(CONNECTOR, NS, STREAM);
  const row = await registry.read(scope);
  const verified = await verify(scope, row, blobs, baseKeys);
  const expected = expectedDigest(spec);
  return {
    spec,
    heap: sampler.result(),
    baselineBytes: baseline,
    durationMs,
    parts: verified.parts,
    partBytesMax: verified.partBytesMax,
    outputCount: verified.outputCount,
    expectedCount: expectedCount(spec),
    digestOk: verified.digest === expected.digest,
    countOk: verified.outputCount === expected.count,
    tooLargeSpooled,
    outcome,
  };
}

async function verify(
  scope: string,
  row: ControlRead,
  blobs: StreamSyncBlobs & { keys(): string[] },
  keys: StreamSyncKeyPorts,
): Promise<{
  digest: string;
  parts: number;
  partBytesMax: number;
  outputCount: number;
}> {
  const digest = new SetDigest();
  let parts = 0;
  let partBytesMax = 0;
  let outputCount = 0;
  if (!row.found)
    return { digest: digest.hex(), parts, partBytesMax, outputCount };
  const headKey = blobs.keys().find((k) => k.startsWith(`${scope}/h-`));
  const headCipher = headKey ? await blobs.get(headKey) : null;
  if (!headCipher)
    return { digest: digest.hex(), parts, partBytesMax, outputCount };
  const decoded = decodeHead(await keys.decrypt(scope, headCipher));
  if (decoded.kind !== "ok")
    return { digest: digest.hex(), parts, partBytesMax, outputCount };
  for (const part of decoded.head.parts) {
    parts += 1;
    partBytesMax = Math.max(partBytesMax, part.bytes);
    const cipher = await blobs.get(
      `${scope}/${partBlobName(decoded.head.generation, part.hash)}`,
    );
    const clear = await keys.decrypt(scope, cipher!);
    for (const text of new TextDecoder().decode(clear).split("\n")) {
      if (text === "") continue;
      const line = decodeLine(text);
      digest.add(outputLine(line.o, line.r, line.v));
      outputCount += 1;
    }
  }
  return { digest: digest.hex(), parts, partBytesMax, outputCount };
}

async function settledHeap(): Promise<number> {
  return settledLive();
}
