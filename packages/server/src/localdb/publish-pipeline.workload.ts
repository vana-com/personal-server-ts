// Bench and profile of one first publish of a large stream, over real SQLite,
// the real encoder and the real storage client and send gate, against a fake
// storage whose every PUT takes a fixed real time. No personal data: rows are
// `rows` records of about `rowBytes` bytes of filler.
//
//   npx tsx packages/server/src/localdb/publish-pipeline.workload.ts \
//     --db ~/.tmp/<dir>/stream.sqlite --rows 198001 --row-bytes 2200 \
//     --put-ms 1200 --width 16 [--profile]
//
// It prints one JSON object: the stream's own publish timings (`planMs`,
// `transferMs`, `uploadMs`, `totalMs`), when the first PUT started and the last
// one ended, and with `--profile` the time spent in each SQL statement shape
// and the connection's slot turns (wait and run).
import { createCipheriv, createHash, randomBytes } from "node:crypto";
import { createRequire, syncBuiltinESMExports } from "node:module";
import type * as WorkerThreadsModule from "node:worker_threads";
import type { Worker } from "node:worker_threads";
import { existsSync, statSync } from "node:fs";
import { sealBytes } from "../../../core/src/stream-sync/stream-aead.js";
import { createStorageStreamSyncBlobs } from "../../../core/src/stream-sync/blobs.js";
import { createMemoryStreamSyncRegistry } from "../../../core/src/stream-sync/memory-registry.js";
import { DEFAULT_STORAGE_ACCESS_POLICY } from "../../../core/src/stream-sync/storage-retry.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
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
    await sync.intake.end("seed", {
      outcome: "succeeded",
      coveredStreams: ["items"],
      lastBatch: batch - 1,
    });
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
  readonly profile?: boolean;
  readonly cipher?: "prod" | "aes";
  /** Who seals and hashes the parts: the pure-JS default, or the Node server's OpenSSL port. */
  readonly crypto?: "noble" | "node";
  /** Queue a write to `records` as soon as the first PUT starts. */
  readonly writeDuringPublish?: boolean;
  /**
   * `spool` hides the driver's frozen read view, so the publish copies rows
   * into the spool as before; `snapshot` (the default) reads `records` in a
   * view.
   */
  readonly variant?: "spool" | "snapshot";
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
  /** Largest size of the `-wal` file seen, sampled every 25 ms. */
  readonly walPeakBytes: number;
  /** CPU of the publish by thread, in milliseconds: main, each driver worker role, the rest, the process total. */
  readonly cpuMs: Record<string, number>;
  readonly partKeysSha256: string;
  /** Open to release of each frozen view, in milliseconds. */
  readonly snapshotHoldMs: readonly number[];
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

const shapeOf = (sql: string) => sql.replace(/\s+/g, " ").trim().slice(0, 90);

/**
 * Per-thread CPU: the driver's worker threads are wrapped so each one can be
 * asked for its CPU time (`Worker.cpuUsage`), and the main thread reports its
 * own (`process.threadCpuUsage`). Called before the driver opens.
 */
const workers: { role: string; worker: Worker }[] = [];
function trackWorkers(): void {
  const wt = createRequire(import.meta.url)(
    "node:worker_threads",
  ) as typeof WorkerThreadsModule;
  if ((wt.Worker as { tracked?: boolean }).tracked) return;
  const Original = wt.Worker;
  class Tracked extends Original {
    static tracked = true;
    constructor(...args: ConstructorParameters<typeof Original>) {
      super(...args);
      const data = args[1]?.workerData as { role?: string } | undefined;
      workers.push({ role: data?.role ?? "worker", worker: this });
    }
  }
  wt.Worker = Tracked;
  syncBuiltinESMExports();
}

const ms = (usage: { user: number; system: number }): number =>
  Math.round((usage.user + usage.system) / 1000);

async function cpuNow() {
  return {
    main: process.threadCpuUsage(),
    total: process.cpuUsage(),
    workers: await Promise.all(
      workers.map(async ({ role, worker }) => ({
        role,
        usage: await worker.cpuUsage().catch(() => ({ user: 0, system: 0 })),
      })),
    ),
  };
}

function cpuBetween(
  a: Awaited<ReturnType<typeof cpuNow>>,
  b: Awaited<ReturnType<typeof cpuNow>>,
) {
  const diff = (x: { user: number; system: number }, y: typeof x) => ({
    user: y.user - x.user,
    system: y.system - x.system,
  });
  const byRole: Record<string, number> = {};
  b.workers.forEach((w, i) => {
    byRole[w.role] =
      (byRole[w.role] ?? 0) +
      ms(diff(a.workers[i]?.usage ?? { user: 0, system: 0 }, w.usage));
  });
  const main = ms(diff(a.main, b.main));
  const total = ms(diff(a.total, b.total));
  const threads = main + Object.values(byRole).reduce((n, v) => n + v, 0);
  return {
    mainMs: main,
    ...Object.fromEntries(
      Object.entries(byRole).map(([k, v]) => [`${k}Ms`, v]),
    ),
    otherMs: total - threads,
    totalMs: total,
  };
}

export async function benchPublish(
  options: PipelineBenchOptions,
): Promise<PipelineBenchResult> {
  trackWorkers();
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
  const holds: number[] = [];
  const viewOf = async () => {
    const view = await driver.snapshot!();
    const opened = at();
    return {
      query: async (text, params) => {
        const started = at();
        try {
          return await view.query(text, params);
        } finally {
          if (options.profile) note(`view: ${shapeOf(text)}`, started);
        }
      },
      release: async () => {
        await view.release();
        holds.push(Math.round(at() - opened));
      },
    };
  };
  const frozen = options.variant === "spool" ? undefined : viewOf;
  const profiled: SqlDriver = options.profile
    ? {
        info: driver.info,
        reads: driver.reads,
        ...(frozen ? { snapshot: frozen } : {}),
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
          try {
            return await driver.batch(statements);
          } finally {
            note(shapeOf(statements[0]?.sql ?? "(empty)"), started);
          }
        },
      }
    : {
        info: driver.info,
        reads: driver.reads,
        ...(frozen ? { snapshot: frozen } : {}),
        close: () => driver.close(),
        query: (text, params) => driver.query(text, params),
        batch: (statements) => driver.batch(statements),
      };
  const db = await openLocalDb(profiled, identity);
  const slots: {
    kind: string;
    waitMs: number;
    runMs: number;
    startAtMs: number;
  }[] = [];
  const real = connectionQueue();
  let timings: Record<string, unknown> | null = null;
  const port =
    options.crypto === "node"
      ? (await import("../stream-sync/node-stream-crypto.js")).nodeStreamCrypto
      : undefined;
  const stats = {
    puts: 0,
    onWire: 0,
    peakOnWire: 0,
    firstPutAtMs: null as number | null,
    lastPutEndAtMs: null as number | null,
  };
  let wrote = false;
  const partKeys: string[] = [];
  const key = randomBytes(32);
  const partBytes = 4 * 1024 * 1024;
  const blobs = createStorageStreamSyncBlobs(
    {
      urlForKey: (k: string) => k,
      exists: async () => false,
      download: async () => new Uint8Array(),
      delete: async () => true,
      upload: async (key: string) => {
        if (key.includes("-p-")) partKeys.push(key);
        stats.puts += 1;
        stats.onWire += 1;
        stats.peakOnWire = Math.max(stats.peakOnWire, stats.onWire);
        stats.firstPutAtMs ??= at();
        if (options.writeDuringPublish && !wrote) {
          wrote = true;
          void writeRecord(db);
        }
        await new Promise((resolve) => setTimeout(resolve, options.putMs));
        stats.onWire -= 1;
        stats.lastPutEndAtMs = at();
        return "";
      },
    } as never,
    {
      ...DEFAULT_STORAGE_ACCESS_POLICY,
      // One part holds 2x its bytes (plain and ciphertext) while its PUT
      // runs, so the window cap is the budget over that.
      partBytes: 2 * partBytes,
      maxBytesInFlight: options.width * 2 * partBytes,
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
        if (options.cipher === "prod")
          return sealBytes(key, clear, randomBytes, port);
        const nonce = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", key, nonce);
        return Buffer.concat([nonce, cipher.update(clear), cipher.final()]);
      },
      decrypt: async (_s, b) => b,
    },
    ...(port ? { streamCrypto: port } : {}),
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
  let walPeak = 0;
  const sample = () => {
    try {
      walPeak = Math.max(walPeak, statSync(`${options.path}-wal`).size);
    } catch {}
  };
  const sampler = setInterval(sample, 25);
  try {
    const cpuBefore = await cpuNow();
    t0 = performance.now();
    const results = await publishConnection(deps, PIPELINE_CONNECTION);
    const wallMs = at();
    const cpuMs = cpuBetween(cpuBefore, await cpuNow());
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
      walPeakBytes: walPeak,
      cpuMs,
      /** SHA-256 of the sorted part blob names, which carry the part hashes: equal across code versions. */
      partKeysSha256: createHash("sha256")
        .update(partKeys.sort().join("\n"))
        .digest("hex"),
      snapshotHoldMs: holds,
      ...(options.profile
        ? {
            sql: [...sql.entries()]
              .map(([shape, v]) => ({ shape, ...v }))
              .sort((a, b) => b.ms - a.ms)
              .slice(0, 14),
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
    profile: process.argv.includes("--profile"),
    variant: arg("variant", "snapshot") === "spool" ? "spool" : "snapshot",
    cipher: arg("cipher", "aes") === "prod" ? "prod" : "aes",
    crypto: arg("crypto", "noble") === "node" ? "node" : "noble",
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1]?.endsWith("publish-pipeline.workload.ts")) {
  main().catch((error: unknown) => {
    console.error(error);
    process.exit(1);
  });
}
