import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import {
  mkdtemp,
  symlink,
  mkdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Explicitly opt in. Every measurement has a fresh process, database and disk blob store.
// Run this file alone: STREAM_SYNC_MEMORY=1 npm test -- log-bounded-memory --maxWorkers=4
const enabled = process.env.STREAM_SYNC_MEMORY === "1";
let scratch: string;
const receipts: unknown[] = [];
async function command(args: string[], env: NodeJS.ProcessEnv = process.env) {
  return new Promise<string>((resolve, reject) => {
    const child = spawn(
      "nice",
      ["-n", "19", "ionice", "-c3", process.execPath, ...args],
      { env },
    );
    let out = "",
      err = "",
      rss = 0;
    const deadline = setTimeout(() => child.kill("SIGTERM"), 600000);
    const timer = setInterval(() => {
      void readFile(`/proc/${child.pid}/status`, "utf8")
        .then((s) => {
          rss = Math.max(
            rss,
            Number(s.match(/VmRSS:\s+(\d+)/)?.[1] ?? 0) * 1024,
          );
        })
        .catch(() => {});
    }, 100);
    child.stdout.on("data", (b) => {
      out += b;
    });
    child.stderr.on("data", (b) => {
      err += b;
    });
    child.on("error", (error) => {
      clearInterval(timer);
      clearTimeout(deadline);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearInterval(timer);
      clearTimeout(deadline);
      receipts.push({ exitCode: code, signal, externalPeakRss: rss });
      if (code !== 0)
        reject(
          new Error(
            `subprocess exit ${code}, signal ${signal}: ${out}\n${err}`,
          ),
        );
      else {
        receipts.push({ args: args.slice(0, 1), externalPeakRss: rss });
        resolve(out);
      }
    });
  });
}
async function measure(mode: string, n: number, pad = 1024) {
  let available = 0;
  for (let attempt = 0; attempt < 60; attempt++) {
    available = Number(
      (await readFile("/proc/meminfo", "utf8")).match(
        /MemAvailable:\s+(\d+)/,
      )?.[1],
    );
    if (available >= 12 * 1024 * 1024) break;
    await new Promise((resolve) => setTimeout(resolve, 10000));
  }
  if (available < 12 * 1024 * 1024)
    throw Error("Need at least 12 GiB available before measurement");
  const dir = join(scratch, `${mode}-${n}-${pad}`);
  await mkdir(dir);
  try {
    const output = await command(
      [
        "--expose-gc",
        "--max-old-space-size=2048",
        join(scratch, "measure.mjs"),
      ],
      {
        ...process.env,
        MEMORY_DIR: dir,
        MEMORY_CASE: mode,
        MEMORY_N: String(n),
        MEMORY_PAD: String(pad),
      },
    );
    const rows = output
      .trim()
      .split("\n")
      .filter((s) => s.startsWith("{"))
      .map((s) => JSON.parse(s));
    if (rows.length === 0) throw Error("measurement produced no receipt");
    receipts.push(...rows);
    console.log(JSON.stringify(rows));
    return rows;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
describe.skipIf(!enabled).sequential("bounded log memory baseline", () => {
  beforeAll(async () => {
    // Small generated bundles only; databases stay in the supplied disk-backed directory.
    const parent = process.env.STREAM_SYNC_MEMORY_DIR;
    if (!parent || parent === tmpdir())
      throw Error("Set STREAM_SYNC_MEMORY_DIR to a disk-backed directory");
    scratch = await mkdtemp(join(parent, "log-memory-"));
    await symlink(
      join(process.cwd(), "node_modules"),
      join(scratch, "node_modules"),
      "dir",
    );
    await command([
      "scripts/log-memory/build.mjs",
      join(scratch, "measure.mjs"),
    ]);
  });
  afterAll(async () => {
    if (!scratch) return;
    await writeFile(
      join(process.env.STREAM_SYNC_MEMORY_DIR!, "baseline-receipts.json"),
      JSON.stringify(receipts, null, 2),
    );
    await rm(scratch, { recursive: true, force: true });
  });
  it("compaction retains at most one output unit before upload", async () => {
    const [r] = await measure("compaction", 10000);
    expect(
      r.outputBytes,
      "all ciphertext candidates remain reachable",
    ).toBeLessThanOrEqual(r.ledger.C);
  }, 900000);
  it("rebase retains only one fold unit during atomic seed", async () => {
    const [r] = await measure("rebase", 10000);
    expect(r.position).toBe(0);
    expect(r.liveDecodedBytes).toBeLessThanOrEqual(r.ledger.C * 2);
  }, 900000);
  it("10x keys and bytes retain a fixed unit budget at fixed R and C", async () => {
    for (const [small, large, pad] of [
      [10000, 100000, 1024],
      [200, 2000, 150000],
    ]) {
      const [a] = await measure("compaction", small, pad);
      const [b] = await measure("compaction", large, pad);
      // Declared before the large run; RSS is evidence, not a GC-sensitive pass/fail gate.
      expect
        .soft(b.outputBytes, "source-sized ciphertext retention")
        .toBeLessThanOrEqual(a.ledger.C);
      expect
        .soft(b.outputBytes)
        .toBeLessThanOrEqual(a.outputBytes + a.ledger.C);
    }
  }, 1500000);
  it("progressive commits release consumed decoded batches", async () => {
    const [r] = await measure("progressive", 10000);
    expect(r.snapshot, "scenario must contain a snapshot").toBe(true);
    expect(r.liveDecodedBytes).toBeLessThanOrEqual(r.ledger.C * 2);
  }, 900000);
  it("covered replacement preflight reads one bounded body unit", async () => {
    const rows = await measure("replace", 10000);
    expect(
      Math.max(...rows.map((r) => Math.max(r.operationBytes, r.queryBytes))),
    ).toBeLessThanOrEqual(rows[0].ledger.C);
  }, 900000);
  it("key metadata and finalize requests fit an encoded frame", async () => {
    const rows = await measure("metadata", 100000, 0);
    expect(
      Math.max(...rows.map((r) => Math.max(r.metadataBytes, r.batchBytes))),
    ).toBeLessThanOrEqual(rows[0].ledger.T);
  }, 1500000);
});
