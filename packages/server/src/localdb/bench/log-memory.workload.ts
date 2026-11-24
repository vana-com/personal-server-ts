// Memory of the stream-sync log's memory paths, one step per process (see
// scripts/log-memory/README.md for how to run it).
//
// Each measured step runs in a process of its own over state an earlier step
// left on disk: file SQLite databases, one file per blob, and the registry's
// rows in `state.json`. A step's process therefore holds only what the code
// under test holds. (One process for every step would carry the allocator's
// retained pages from the one before: a publish leaves ~700 MiB resident and a
// later step then reads as if it were nearly free.) A measured step settles
// the heap, resets the kernel's high-water mark (`/proc/self/clear_refs`) and
// reports the process peak (`VmHWM`) beside the resident size it began with.
// The kernel mark misses no synchronous allocation, which a sampling timer can.
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { deriveKeyCheck } from "@opendatalabs/personal-server-ts-stream-sync";
import { readLogState } from "../../../../core/src/localdb/log-state.js";
import * as compact from "../../../../core/src/localdb/log-compact.js";
import { endRequest } from "../../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "../better-sqlite3-driver.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  closeWorldDrivers,
  world,
  type WorldBlobStore,
} from "../log-world.test-utils.js";

const MiB = 1024 * 1024;
const TARGET = 2 * MiB;

/**
 * The steps, in the order a case runs them. `intake1` and `intake2` only
 * prepare state. The others are measured:
 * - `publish`: the first publish of the source (a writer);
 * - `restore`: a second device's default first load of the log;
 * - `compaction`: the log folded into a snapshot (forced, see `compaction`);
 * - `replace`: a covered replace of every key, published;
 * - `progressive`: a third device's first load with progressive mode on.
 */
export const STEPS = [
  "intake1",
  "publish",
  "restore",
  "compaction",
  "intake2",
  "replace",
  "progressive",
] as const;
export type Step = (typeof STEPS)[number];
const PREPARE: ReadonlySet<Step> = new Set(["intake1", "intake2"]);

export interface StepReport {
  readonly step: Step;
  /** Resident size after a full collection, when the step began. */
  readonly idleMiB: number;
  /** Process high-water mark during the step (kernel `VmHWM`). */
  readonly peakMiB: number;
  readonly aboveIdleMiB: number;
  readonly ms: number;
  readonly notes: Record<string, unknown>;
}

const statusKiB = (field: string): number => {
  const m = new RegExp(`^${field}:\\s+(\\d+) kB$`, "m").exec(
    readFileSync("/proc/self/status", "utf8"),
  );
  if (!m) throw new Error(`${field} missing from /proc/self/status`);
  return Number(m[1]);
};

async function settle(): Promise<void> {
  const gc = globalThis.gc;
  if (!gc) throw new Error("run with --expose-gc");
  for (let i = 0; i < 3; i += 1) gc();
  await new Promise((r) => setTimeout(r, 300));
  for (let i = 0; i < 2; i += 1) gc();
}

/** A blob store of one file per blob: every `get` reads fresh bytes. */
function diskBlobs(root: string): WorldBlobStore {
  mkdirSync(root, { recursive: true });
  const file = (key: string) => join(root, encodeURIComponent(key));
  return {
    put: async (key, bytes) => {
      writeFileSync(file(key), bytes);
    },
    get: async (key) =>
      existsSync(file(key)) ? new Uint8Array(readFileSync(file(key))) : null,
    exists: async (key) => existsSync(file(key)),
    keys: () => readdirSync(root).map(decodeURIComponent),
    delete: (key) => {
      rmSync(file(key), { force: true });
      return true;
    },
  };
}

export interface StepArgs {
  readonly step: Step;
  readonly dir: string;
  readonly records: number;
  readonly padBytes: number;
  /** Source per intake batch, in MiB (default 4). */
  readonly batchMiB?: number;
}

type StateFile = {
  versions: [string, { dataHash: string; metadataHash: string }[]][];
};

export async function runStep(args: StepArgs): Promise<StepReport | null> {
  mkdirSync(args.dir, { recursive: true });
  const statePath = join(args.dir, "state.json");
  const w = await world({
    streams: 1,
    partTargetBytes: TARGET,
    keyTypes: ["integer"],
    database: (id) => openBetterSqlite3(join(args.dir, `${id}.db`)),
    blobStore: diskBlobs(join(args.dir, "blobs")),
    opSalt: `-${args.step}`,
  });
  // Stamps must keep rising across processes: a replace is newer than its source.
  w.setClock(Date.now());
  if (existsSync(statePath)) {
    const saved = JSON.parse(readFileSync(statePath, "utf8")) as StateFile;
    for (const [scope, rows] of saved.versions)
      for (const row of rows) w.gateway.write(scope, row);
  }
  const saveState = () =>
    writeFileSync(
      statePath,
      JSON.stringify({ versions: [...w.gateway.versions.entries()] }),
    );

  let report: StepReport | null = null;
  const measured = async <T>(
    fn: () => Promise<T>,
    notes: (result: T) => Record<string, unknown> = () => ({}),
  ): Promise<T> => {
    await settle();
    const idle = statusKiB("VmRSS");
    writeFileSync("/proc/self/clear_refs", "5");
    const started = Date.now();
    // Where the peak lives: sampled maxima of V8's heap and of the Buffers
    // outside it (a lower bound; the kernel mark is the peak itself).
    let heapMax = 0;
    let externalMax = 0;
    const sample = setInterval(() => {
      const m = process.memoryUsage();
      heapMax = Math.max(heapMax, m.heapUsed);
      externalMax = Math.max(externalMax, m.external + m.arrayBuffers);
    }, 20);
    const result = await fn().finally(() => clearInterval(sample));
    const peak = statusKiB("VmHWM");
    report = {
      step: args.step,
      idleMiB: Math.round(idle / 1024),
      peakMiB: Math.round(peak / 1024),
      aboveIdleMiB: Math.max(0, Math.round((peak - idle) / 1024)),
      ms: Date.now() - started,
      notes: {
        sampledHeapMiB: Math.round(heapMax / MiB),
        sampledExternalMiB: Math.round(externalMax / MiB),
        ...notes(result),
      },
    };
    return result;
  };

  const perBatch = Math.max(
    1,
    Math.floor(((args.batchMiB ?? 4) * MiB) / (args.padBytes + 64)),
  );
  const pad = "p".repeat(args.padBytes);
  const intake = async (
    device: Awaited<ReturnType<typeof w.device>>,
    run: string,
    version: number,
  ) => {
    await device.begin(run);
    let batch = 0;
    for (let i = 0; i < args.records; i += perBatch) {
      await device.sync.intake.batch(run, {
        batch: batch++,
        records: Array.from(
          { length: Math.min(perBatch, args.records - i) },
          (_, j) => ({
            stream: "s0",
            data: { id: i + j, v: version, pad },
          }),
        ),
      });
    }
    await device.sync.intake.end(
      run,
      endRequest({
        lastBatch: batch - 1,
        streams: ["s0"],
        live: ["s0"],
        provenFullStreams: ["s0"],
      }),
    );
  };
  const logShape = async (device: Awaited<ReturnType<typeof w.device>>) => {
    const log = await readLogState(device.deps, CONNECTION_ID);
    return {
      position: log.position,
      refs: log.refs.length,
      snapshotParts: log.snapshot?.parts.length ?? 0,
    };
  };
  const rowCount = async (device: Awaited<ReturnType<typeof w.device>>) =>
    Number(
      (
        await device.db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM records",
        )
      )[0]!.n,
    );

  try {
    switch (args.step) {
      case "intake1":
        await intake(await w.device("a"), "r1", 1);
        break;
      case "intake2":
        await intake(await w.device("a"), "r2", 2);
        break;
      case "publish":
      case "replace": {
        const a = await w.device("a");
        await measured(() => a.cycle());
        saveState();
        report!.notes.log = await logShape(a);
        break;
      }
      case "restore": {
        rmSync(join(args.dir, "b.db"), { force: true });
        const b = await w.device("b");
        await measured(() => b.cycle());
        report!.notes.rows = await rowCount(b);
        report!.notes.log = await logShape(b);
        break;
      }
      case "progressive": {
        rmSync(join(args.dir, "c.db"), { force: true });
        const c = await w.device("c", { progressiveFirstLoad: true });
        await measured(() => c.cycle());
        report!.notes.rows = await rowCount(c);
        report!.notes.log = await logShape(c);
        break;
      }
      case "compaction": {
        // The cost model compacts only a log with a long tail, so the step
        // calls the compaction directly. Main's `planCompaction` has the gate
        // in front of it: the baseline run strips it (see run.sh).
        const a = await w.device("a");
        type Plan = {
          objects: readonly { name: string; cipher?: Uint8Array }[];
        } | null;
        const fn = ((compact as Record<string, unknown>).compactLog ??
          compact.planCompaction) as (
          deps: unknown,
          input: unknown,
        ) => Promise<Plan>;
        const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
        const log = await readLogState(a.deps, CONNECTION_ID);
        await measured(
          async () => {
            const plan = await fn(
              { ...a.deps, partTargetBytes: TARGET },
              {
                connector: CONNECTOR,
                ns: "",
                generation: 1,
                keyCheck,
                scope: LOG,
                log,
              },
            );
            return {
              objects: plan?.objects.length ?? 0,
              bytes:
                plan?.objects.reduce(
                  (n, o) => n + (o.cipher?.length ?? 0),
                  0,
                ) ?? 0,
            };
          },
          (r) => ({ objects: r.objects, retainedCipherBytes: r.bytes }),
        );
        break;
      }
    }
  } finally {
    await closeWorldDrivers();
  }
  return report;
}

const flag = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i < 0 ? fallback : process.argv[i + 1]!;
};

// Run: node --expose-gc --import tsx <this file> --step publish --dir <dir> \
//        --records N --pad BYTES
// It prints the step's report as one JSON line, or nothing for a prepare step.
if (process.argv[1]?.endsWith("log-memory.workload.ts")) {
  const step = flag("step", "") as Step;
  if (!STEPS.includes(step)) throw new Error(`--step is one of ${STEPS}`);
  const report = await runStep({
    step,
    dir: flag("dir", ""),
    records: Number(flag("records", "10000")),
    padBytes: Number(flag("pad", "1024")),
  });
  if (!PREPARE.has(step) && report)
    process.stdout.write(`${JSON.stringify(report)}\n`);
}
