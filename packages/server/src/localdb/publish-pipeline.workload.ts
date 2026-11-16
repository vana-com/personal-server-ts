// Bench and profile of one first publish of a large stream, over real SQLite,
// the real encoder and the real storage client and send gate, against a fake
// storage whose every PUT takes a fixed real time. No personal data: rows are
// `rows` records of about `rowBytes` bytes of filler.
//
//   npx tsx packages/server/src/localdb/publish-pipeline.workload.ts \
//     --db ~/.tmp/<dir>/stream.sqlite --rows 198001 --row-bytes 2200 \
//     --put-ms 1200 (--production | --width 16) [--profile]
//
// `--production` runs under the store's default policy, whatever commit this is
// run at, which is what a release does. `--width N` runs N parts in flight with
// a budget sized for them.
//
// It prints one JSON object: the stream's own publish timings (`planMs`,
// `transferMs`, `uploadMs`, `totalMs`), when the first PUT started and the last
// one ended, and with `--profile` the time spent in each SQL statement shape
// and the connection's slot turns (wait and run).
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createStorageStreamSyncBlobs } from "../../../core/src/stream-sync/blobs.js";
import { createMemoryStreamSyncRegistry } from "../../../core/src/stream-sync/memory-registry.js";
import { DEFAULT_STORAGE_ACCESS_POLICY } from "../../../core/src/stream-sync/storage-retry.js";
import {
  parseRateLimitPolicy,
  type QuotaPolicies,
} from "../../../core/src/storage/adapters/rate-limit-policy.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const identity = {
  owner: "0x1111111111111111111111111111111111111111" as const,
  network: "test",
  deviceId: "publish-pipeline",
};
const CONNECTOR = "pipeline-source";
export const PIPELINE_CONNECTION = `pdpp.${CONNECTOR}~`;

/** Parent side: one finished run of `rows` records of about `rowBytes`, through the real intake. */
export async function buildStreamDb(
  path: string,
  rows: number,
  rowBytes: number,
): Promise<void> {
  const db = await openLocalDb(openBetterSqlite3(path), identity);
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry: createMemoryStreamSyncRegistry(),
    blobs: createStorageStreamSyncBlobs({} as never),
    ownerAddress: identity.owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => 1_000,
    newOp: (() => {
      let n = 0;
      return () => `pipeline-build-${++n}`;
    })(),
  };
  try {
    const sync = createLocalSync(deps, {
      resolveArtifact: (digest) => ({
        connector: digest,
        version: "1",
        streams: [
          { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
        ],
      }),
      declaredStreams: () => ["items"],
      olderVersionReads: () => true,
    });
    await sync.intake.begin("seed", {
      connector: CONNECTOR,
      artifactDigest: CONNECTOR,
      wantFull: true,
      owner: { address: identity.owner, leaseId: null },
    });
    const perBatch = 200;
    let batch = 0;
    for (let at = 0; at < rows; at += perBatch, batch++) {
      const records = [];
      for (let i = at; i < Math.min(rows, at + perBatch); i++) {
        records.push({
          stream: "items",
          data: { id: `row-${i}`, text: `${i}:`.padEnd(rowBytes, "x") },
        });
      }
      await sync.intake.batch("seed", { batch, records });
    }
    await sync.intake.end(
      "seed",
      endRequest({ lastBatch: batch - 1, live: ["items"] }),
    );
  } finally {
    await db.close();
  }
}

export interface PipelineBenchOptions {
  readonly path: string;
  /** Real milliseconds one PUT takes in storage. */
  readonly putMs: number;
  /** The send gate's window cap. The byte budget is sized to hold that many parts. */
  readonly width: number;
  /** Use the store's default policy as it is, and ignore `width`. */
  readonly production?: boolean;
  /** The storage guard: PUTs allowed per 60 s. None when absent. */
  readonly putsPerMinute?: number;
  readonly profile?: boolean;
  /** With `profile`: time a commit batch's statements one by one. */
  readonly profileStatements?: boolean;
  /** Queue a write to `records` as soon as the first PUT starts. */
  readonly writeDuringPublish?: boolean;
  /**
   * The `RateLimit-Policy` header the fake storage puts on every response
   * (for example `"put";q=600;w=60`). The gate learns it from the first
   * response, as it does from a real store.
   */
  readonly publishedQuota?: string;
  /**
   * The fake storage's uplink in bytes per second, shared evenly by the PUTs in
   * flight, plus `rttMs` of fixed latency per PUT. Without it every PUT takes
   * `putMs`.
   */
  readonly uplinkBytesPerSec?: number;
  readonly rttMs?: number;
}

export interface PipelineBenchResult {
  readonly outcome: string;
  readonly timings: Record<string, unknown> | null;
  /** From the start of `publishConnection`, in milliseconds. */
  readonly wallMs: number;
  readonly firstPutAtMs: number | null;
  readonly lastPutEndAtMs: number | null;
  readonly puts: number;
  readonly peakOnWire: number;
  /** PUT-seconds on the wire divided by the span from the first PUT's start to the last one's end. */
  readonly meanOnWire: number;
  /** Each PUT: start and end in ms from the publish's start. */
  readonly putSpans?: readonly (readonly [number, number])[];
  /** The most resident memory the process had while the publish ran, in MiB. */
  readonly peakRssMiB: number;
  /** The most buffer memory outside the JS heap, in MiB. */
  readonly peakExternalMiB: number;
  /** SHA-256 over the sorted names of every object stored: equal digests, equal parts and head. */
  readonly objectsDigest: string;
  readonly sql?: readonly {
    readonly shape: string;
    readonly n: number;
    readonly ms: number;
    readonly firstAtMs: number;
    readonly lastEndAtMs: number;
  }[];
  readonly slots?: readonly {
    readonly kind: string;
    readonly waitMs: number;
    readonly runMs: number;
    readonly startAtMs: number;
  }[];
}

/**
 * A PUT's time in the fake storage. Without an uplink every PUT takes
 * `putMs`. With one, the PUTs in flight share it evenly (processor sharing):
 * each takes `rttMs` and then moves its bytes at its share of the uplink.
 */
function createSharedUplink(
  uplinkBytesPerSec: number | undefined,
  rttMs: number,
  putMs: number,
): { send(bytes: number): Promise<void> } {
  if (uplinkBytesPerSec === undefined)
    return { send: () => new Promise((r) => setTimeout(r, putMs)) };
  interface Flow {
    left: number;
    done: () => void;
  }
  const flows = new Set<Flow>();
  let at = performance.now();
  let timer: NodeJS.Timeout | undefined;
  const advance = () => {
    const now = performance.now();
    if (flows.size > 0) {
      const each = (uplinkBytesPerSec * (now - at)) / 1000 / flows.size;
      for (const flow of flows) flow.left -= each;
    }
    at = now;
  };
  const schedule = () => {
    clearTimeout(timer);
    if (flows.size === 0) return;
    const least = Math.min(...[...flows].map((f) => f.left));
    const ms = (Math.max(0, least) * flows.size * 1000) / uplinkBytesPerSec;
    timer = setTimeout(() => {
      advance();
      for (const flow of [...flows])
        if (flow.left <= 1) {
          flows.delete(flow);
          flow.done();
        }
      schedule();
    }, ms);
  };
  return {
    send: (bytes) =>
      new Promise<void>((resolve) => {
        setTimeout(() => {
          advance();
          flows.add({ left: bytes, done: resolve });
          schedule();
        }, rttMs);
      }),
  };
}

const shapeOf = (sql: string) => sql.replace(/\s+/g, " ").trim().slice(0, 90);

export async function benchPublish(
  options: PipelineBenchOptions,
): Promise<PipelineBenchResult> {
  const driver = openBetterSqlite3(options.path);
  let t0 = performance.now();
  const at = () => performance.now() - t0;
  const sql = new Map<
    string,
    { n: number; ms: number; firstAtMs: number; lastEndAtMs: number }
  >();
  const note = (shape: string, started: number) => {
    const entry = sql.get(shape) ?? {
      n: 0,
      ms: 0,
      firstAtMs: started,
      lastEndAtMs: 0,
    };
    entry.n += 1;
    entry.ms += at() - started;
    entry.lastEndAtMs = at();
    sql.set(shape, entry);
  };
  const profiled: SqlDriver = options.profile
    ? {
        info: driver.info,
        reads: driver.reads,
        // Kept, so a profiled run takes the same frozen-view path as a plain one.
        ...(driver.snapshot
          ? {
              snapshot: async () => {
                const view = await driver.snapshot!();
                return {
                  release: () => view.release(),
                  query: async (text, params) => {
                    const started = at();
                    try {
                      return await view.query(text, params);
                    } finally {
                      note(`VIEW: ${shapeOf(text)}`, started);
                    }
                  },
                } as Awaited<ReturnType<NonNullable<SqlDriver["snapshot"]>>>;
              },
            }
          : {}),
        close: () => driver.close(),
        query: async (text, params) => {
          const started = at();
          try {
            return await driver.query(text, params);
          } finally {
            note(shapeOf(text), started);
          }
        },
        batch: async (statements) => {
          const started = at();
          // A commit batch is timed statement by statement (profiling only: the
          // pieces run one after another, not in one transaction; the
          // write_ctx origin is a table row, so it carries from the first
          // piece to the rest).
          if (
            options.profileStatements &&
            statements.length > 5 &&
            statements[0]?.sql.startsWith("UPDATE write_ctx")
          ) {
            const changes: number[] = [];
            for (const statement of statements) {
              const one = at();
              try {
                changes.push(...(await driver.batch([statement])).changes);
              } finally {
                note(`COMMIT: ${shapeOf(statement.sql)}`, one);
              }
            }
            return { changes };
          }
          try {
            return await driver.batch(statements);
          } finally {
            note(shapeOf(statements[0]?.sql ?? "(empty)"), started);
          }
        },
      }
    : driver;
  const db = await openLocalDb(profiled, identity);
  const slots: {
    kind: string;
    waitMs: number;
    runMs: number;
    startAtMs: number;
  }[] = [];
  const real = connectionQueue();
  let timings: Record<string, unknown> | null = null;
  const stats = {
    puts: 0,
    onWire: 0,
    peakOnWire: 0,
    firstPutAtMs: null as number | null,
    lastPutEndAtMs: null as number | null,
    putSeconds: 0,
    spans: [] as [number, number][],
  };
  const listeners = new Set<(quota: QuotaPolicies) => void>();
  const published = parseRateLimitPolicy(options.publishedQuota);
  const sharing = createSharedUplink(
    options.uplinkBytesPerSec,
    options.rttMs ?? 0,
    options.putMs,
  );
  let wrote = false;
  const stored: string[] = [];
  const key = randomBytes(32);
  const partBytes = 4 * 1024 * 1024;
  const blobs = createStorageStreamSyncBlobs(
    {
      urlForKey: (k: string) => k,
      exists: async () => false,
      download: async () => new Uint8Array(),
      delete: async () => true,
      onRateLimitPolicy: (listener: (quota: QuotaPolicies) => void) => {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
      upload: async (objectKey: string, bytes: Uint8Array) => {
        stored.push(objectKey);
        stats.puts += 1;
        stats.onWire += 1;
        stats.peakOnWire = Math.max(stats.peakOnWire, stats.onWire);
        const startedAt = at();
        stats.firstPutAtMs ??= startedAt;
        if (options.writeDuringPublish && !wrote) {
          wrote = true;
          void writeRecord(db);
        }
        await sharing.send(bytes.byteLength);
        stats.onWire -= 1;
        stats.lastPutEndAtMs = at();
        stats.putSeconds += (at() - startedAt) / 1000;
        stats.spans.push([startedAt, at()]);
        if (published) for (const listener of listeners) listener(published);
        return "";
      },
    } as never,
    options.production
      ? {
          ...DEFAULT_STORAGE_ACCESS_POLICY,
          ...(options.putsPerMinute
            ? { quota: { limit: options.putsPerMinute, windowMs: 60_000 } }
            : {}),
        }
      : {
          ...DEFAULT_STORAGE_ACCESS_POLICY,
          // `width` parts in flight and the part being built (two parts).
          partBytes,
          maxPartsInFlight: options.width,
          maxBytesInFlight: (options.width + 2) * partBytes,
        },
  );
  const deps: LocalSyncDeps = {
    db,
    queue: {
      async run(id, kind, fn) {
        const asked = at();
        return real.run(id, kind, async () => {
          const started = at();
          try {
            return await fn();
          } finally {
            slots.push({
              kind,
              waitMs: started - asked,
              runMs: at() - started,
              startAtMs: started,
            });
          }
        });
      },
    },
    registry: createMemoryStreamSyncRegistry(),
    blobs,
    ownerAddress: identity.owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, clear) => {
        const nonce = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", key, nonce);
        return Buffer.concat([nonce, cipher.update(clear), cipher.final()]);
      },
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: {
      info: (obj, msg) => {
        if (msg === "stream sync: stream publish timings") timings = obj;
      },
      warn: () => {},
    },
    now: () => Date.now(),
    newOp: (() => {
      let n = 0;
      return () => `pipeline-${++n}`;
    })(),
  };
  let peakRss = 0;
  let peakExternal = 0;
  const sample = () => {
    const use = process.memoryUsage();
    peakRss = Math.max(peakRss, use.rss);
    peakExternal = Math.max(peakExternal, use.external + use.arrayBuffers);
  };
  const sampler = setInterval(sample, 25);
  try {
    t0 = performance.now();
    const results = await publishConnection(deps, PIPELINE_CONNECTION);
    const wallMs = at();
    clearInterval(sampler);
    sample();
    return {
      outcome: results.map((r) => r.outcome).join(","),
      timings,
      wallMs,
      firstPutAtMs: stats.firstPutAtMs,
      lastPutEndAtMs: stats.lastPutEndAtMs,
      puts: stats.puts,
      peakOnWire: stats.peakOnWire,
      meanOnWire:
        stats.firstPutAtMs === null || stats.lastPutEndAtMs === null
          ? 0
          : stats.putSeconds /
            ((stats.lastPutEndAtMs - stats.firstPutAtMs) / 1000),
      ...(options.profile ? { putSpans: stats.spans } : {}),
      peakRssMiB: Math.round(peakRss / 1048576),
      peakExternalMiB: Math.round(peakExternal / 1048576),
      objectsDigest: createHash("sha256")
        .update([...stored].sort().join("\n"))
        .digest("hex"),
      ...(options.profile
        ? {
            sql: [...sql.entries()]
              .map(([shape, v]) => ({ shape, ...v }))
              .sort((a, b) => b.ms - a.ms)
              .slice(0, 24),
            slots,
          }
        : {}),
    };
  } finally {
    clearInterval(sampler);
    await db.close();
  }
}

/** A write to `records` that is not part of any run: the stamp-cutoff test's intruder. */
async function writeRecord(db: SqlDriver): Promise<void> {
  const body = JSON.stringify({ id: "intruder", text: "late" });
  await db.batch([
    {
      sql: `INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o)
            VALUES (?, 'items', ?, 'intruder', 99, 'late', ?, ?, NULL)`,
      params: [PIPELINE_CONNECTION, "7".repeat(64), body, "b".repeat(64)],
    },
  ]);
}

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const value = i >= 0 ? process.argv[i + 1] : fallback;
  if (value === undefined) throw new Error(`missing --${name}`);
  return value;
}

async function main(): Promise<void> {
  const path = arg("db");
  const rows = Number(arg("rows", "198001"));
  const rowBytes = Number(arg("row-bytes", "2200"));
  if (!existsSync(path)) {
    const started = performance.now();
    await buildStreamDb(path, rows, rowBytes);
    console.error(
      `built ${path} in ${Math.round(performance.now() - started)} ms`,
    );
  }
  if (process.argv.includes("--build-only")) return;
  const result = await benchPublish({
    path,
    putMs: Number(arg("put-ms", "1200")),
    width: Number(arg("width", "16")),
    production: process.argv.includes("--production"),
    ...(process.argv.includes("--published-quota")
      ? { publishedQuota: arg("published-quota") }
      : {}),
    ...(process.argv.includes("--uplink-mb-s")
      ? {
          uplinkBytesPerSec: Number(arg("uplink-mb-s")) * 1_000_000,
          rttMs: Number(arg("rtt-ms", "0")),
        }
      : {}),
    ...(process.argv.includes("--puts-per-minute")
      ? { putsPerMinute: Number(arg("puts-per-minute")) }
      : {}),
    profile: process.argv.includes("--profile"),
    profileStatements: process.argv.includes("--profile-statements"),
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1]?.endsWith("publish-pipeline.workload.ts")) {
  main().catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
}
