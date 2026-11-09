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
  streamSyncHashes,
  type StreamSyncBlobs,
  type StreamSyncFiles,
  type StreamSyncKeyPorts,
  type StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  linesOfParts,
  deriveKeyCheck,
  isHeadLive,
  partBlobName,
  streamScope,
  verifyHead,
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
function settledLive(forced: boolean): number {
  if (!forced) return liveBytes();
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
/** P3_NO_FORCED_GC=1 reads raw live bytes (the phone-like peak: GC runs when V8 decides). */
const FORCE_GC = process.env.P3_NO_FORCED_GC !== "1";

export class HeapSampler {
  constructor(private readonly forced: boolean = FORCE_GC) {}
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
      const used = settledLive(this.forced);
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
    this.lastLive = settledLive(this.forced);
    this.timer = setInterval(() => {
      if (!this.active) return;
      const raw = liveBytes();
      if (raw - this.lastLive > GC_TRIGGER) {
        this.lastLive = settledLive(this.forced);
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

/**
 * Exclusive-version registry: POST at version+1 writes, identical replays.
 * `setDeleted` marks a scope's latest row deleted, as a registry delete does.
 */
function fakeRegistry(): StreamSyncRegistry & {
  setDeleted(scope: string): void;
} {
  const rows = new Map<string, { dataHash: string; metadataHash: string }[]>();
  const deleted = new Set<string>();
  return {
    setDeleted(scope) {
      deleted.add(scope);
    },
    async read(scope): Promise<ControlRead> {
      const versions = rows.get(scope);
      if (!versions || versions.length === 0) return { found: false };
      const head = versions[versions.length - 1]!;
      return {
        found: true,
        version: versions.length,
        dataHash: head.dataHash as `0x${string}`,
        metadataHash: head.metadataHash as `0x${string}`,
        deleted: deleted.has(scope),
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
  /**
   * Force a settled GC at each sample (default: on, unless P3_NO_FORCED_GC=1).
   * Forcing needs `node --expose-gc`. A run that checks only outputs and
   * verdicts, not sampled memory, passes `false` so it does not need the flag.
   */
  readonly forcedGc?: boolean;
  /** Writer target per part (bytes). Omit for the writer default. */
  readonly partTargetBytes?: number;
  /** Reduce budget per group (bytes). Omit for the writer default. */
  readonly reduceBudgetBytes?: number;
  /** Spool flush batch (bytes). Omit for the writer default. */
  readonly spoolFlushBytes?: number;
  /** Scratch root for this run's files and blobs; the caller removes it. */
  readonly dir: string;
  /**
   * In-process only (not serializable, so not passed to the child). Runs after
   * publish and before verification, to build a wrong or corrupted published
   * state for the oracle's mutant tests.
   */
  readonly tamper?: (ctx: TamperContext) => Promise<void>;
}

export interface TamperContext {
  readonly scope: string;
  readonly registry: StreamSyncRegistry;
  readonly blobs: StreamSyncBlobs & { keys(): string[] };
  readonly keys: StreamSyncKeyPorts;
  /** Mark a scope's latest registry row deleted (`deleted: true` on read). */
  readonly setDeleted: (scope: string) => void;
}

/**
 * Allocation totals by site from V8's sampling heap profiler. Collected objects are
 * included, so this counts what was allocated, not what is live at the end.
 */
async function startAllocProfile(): Promise<{
  stop(records: number): Promise<{
    allocBytes: number;
    allocPerRecord: number;
    topAllocSites: { site: string; bytes: number; share: number }[];
  }>;
}> {
  const { Session } = await import("node:inspector/promises");
  const session = new Session();
  session.connect();
  await session.post("HeapProfiler.enable");
  await session.post("HeapProfiler.startSampling", {
    samplingInterval: 4096,
    includeObjectsCollectedByMajorGC: true,
    includeObjectsCollectedByMinorGC: true,
  });
  return {
    async stop(records: number) {
      const { profile } = (await session.post("HeapProfiler.stopSampling")) as {
        profile: { head: AllocNode };
      };
      session.disconnect();
      const bySite = new Map<string, number>();
      let total = 0;
      // Native frames (Array.prototype.join, TypedArray ops) have no url; attribute their bytes to
      // the nearest JS caller so the site names the code that asked for the allocation.
      const walk = (node: AllocNode, jsCaller: string) => {
        const f = node.callFrame;
        const isJs = f.url !== "";
        const site = isJs
          ? `${f.functionName || "(anonymous)"} ${f.url.split("/").slice(-2).join("/")}:${f.lineNumber + 1}`
          : jsCaller;
        const native = isJs ? "" : ` [native ${f.functionName || "?"}]`;
        if (node.selfSize > 0) {
          const key = isJs ? site : `${site}${native}`;
          bySite.set(key, (bySite.get(key) ?? 0) + node.selfSize);
          total += node.selfSize;
        }
        for (const child of node.children) walk(child, isJs ? site : jsCaller);
      };
      walk(profile.head, "(root)");
      const topAllocSites = [...bySite.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([site, bytes]) => ({
          site,
          bytes,
          share: total > 0 ? +(bytes / total).toFixed(3) : 0,
        }));
      return {
        allocBytes: total,
        allocPerRecord: records > 0 ? Math.round(total / records) : 0,
        topAllocSites,
      };
    },
  };
}

interface AllocNode {
  callFrame: { functionName: string; url: string; lineNumber: number };
  selfSize: number;
  children: AllocNode[];
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
  /** Sampled allocation totals (inspector sampling heap profile, collected objects included). */
  readonly allocBytes: number;
  readonly allocPerRecord: number;
  readonly topAllocSites: { site: string; bytes: number; share: number }[];
  readonly forcedGc: boolean;
}

/**
 * Append every record of `spec` through the real writer, publish, then verify
 * the published output (decrypted head and parts) against the closed form.
 */
export async function runScenario(
  spec: ScenarioSpec,
  options: RunOptions,
): Promise<RunReport> {
  const forced = options.forcedGc ?? FORCE_GC;
  const sampler = new HeapSampler(forced);
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
    async encryptPart(scope, clear) {
      const cipher = await baseKeys.encryptPart(scope, clear);
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

  const baseline = settledLive(forced);
  sampler.startTimer();
  const started = Date.now();
  const alloc = await startAllocProfile();
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
  const allocSummary = await alloc.stop(spec.records);
  const durationMs = Date.now() - started;
  // Sampling stops with the publish; verification reads below are not measured.
  sampler.active = false;
  sampler.stopTimer();

  const outcome =
    report.runs.find((r) => r.runId === RUN_ID)?.streams[STREAM]?.state ??
    "missing";
  const scope = streamScope(CONNECTOR, NS, STREAM);
  if (options.tamper) {
    await options.tamper({
      scope,
      registry,
      blobs,
      keys: baseKeys,
      setDeleted: (target) => registry.setDeleted(target),
    });
  }
  const row = await registry.read(scope);
  const verified = await verify(scope, row, blobs, baseKeys, registry);
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
    ...allocSummary,
    forcedGc: forced,
  };
}

/**
 * Verify the published stream the way a real reader does: the head is the one
 * the registry's dataHash names, checked by verifyHead; the head is live (the
 * control row is active at the head's generation and the stream row is not
 * tombstoned, by isHeadLive); every part is checked by linesOfParts (SHA-256,
 * byte length, line count, primary-key placement); and the verified line total
 * must equal the head's recordCount. Any failure throws, so a wrong published
 * state fails the run instead of reporting expected totals.
 */
async function verify(
  scope: string,
  row: ControlRead,
  blobs: StreamSyncBlobs & { keys(): string[] },
  keys: StreamSyncKeyPorts,
  registry: StreamSyncRegistry,
): Promise<{
  digest: string;
  parts: number;
  partBytesMax: number;
  outputCount: number;
}> {
  if (!row.found) throw new Error(`oracle: no registry row for ${scope}`);
  const headName = `h-${row.dataHash.toLowerCase().replace(/^0x/, "")}`;
  const headCipher = await blobs.get(`${scope}/${headName}`);
  if (!headCipher) throw new Error(`oracle: head ${headName} is missing`);
  const keyCheck = await deriveKeyCheck((m) => keys.namespaceHmac(m));
  const verified = await verifyHead(
    streamSyncHashes.keccak256,
    await keys.decrypt(scope, headCipher),
    {
      dataHash: row.dataHash,
      connector: CONNECTOR,
      ns: NS,
      stream: STREAM,
      keyCheck,
    },
  );
  if (verified.kind !== "ok") {
    throw new Error(`oracle: head rejected (${verified.kind})`);
  }
  const head = verified.head;
  const hashes = await controlHashes(streamSyncHashes.keccak256, keyCheck);
  const control = classifyControl(
    await registry.read(controlScope(CONNECTOR, NS)),
    hashes,
  );
  const streamRow = classifyStreamRow(row, hashes);
  if (!isHeadLive(control, streamRow, head.generation)) {
    throw new Error(
      `oracle: head of generation ${head.generation} is not live (control ${control.kind}, stream row ${streamRow})`,
    );
  }
  const digest = new SetDigest();
  let parts = 0;
  let partBytesMax = 0;
  let outputCount = 0;
  for (const part of head.parts) {
    parts += 1;
    partBytesMax = Math.max(partBytesMax, part.bytes);
  }
  // linesOfParts reads format 1 and format 2 parts alike and checks size,
  // SHA-256, key order, prefix and frame counts of every part it loads.
  for await (const line of linesOfParts(
    streamSyncHashes.sha256,
    head,
    async (part) => {
      const cipher = await blobs.get(
        `${scope}/${partBlobName(head.generation, part.hash)}`,
      );
      if (!cipher) throw new Error(`oracle: part ${part.hash} is missing`);
      return keys.decrypt(scope, cipher);
    },
  )) {
    digest.add(outputLine(line.o, line.r, line.v));
    outputCount += 1;
  }
  if (outputCount !== head.recordCount) {
    throw new Error(
      `oracle: head recordCount ${head.recordCount} != verified lines ${outputCount}`,
    );
  }
  return { digest: digest.hex(), parts, partBytesMax, outputCount };
}
