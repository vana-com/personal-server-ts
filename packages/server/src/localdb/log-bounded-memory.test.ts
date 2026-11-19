import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { spawn, execFileSync } from "node:child_process";
import {
  mkdtemp,
  symlink,
  mkdir,
  readFile,
  rename,
  appendFile,
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
let bundleHash: string;
async function command(args: string[], env: NodeJS.ProcessEnv = process.env) {
  return new Promise<string>((resolve, reject) => {
    const memory = args.includes("--expose-gc");
    const nodeArgs = memory
      ? [...args.slice(0, -1), "scripts/log-memory/admit.mjs", args.at(-1)!]
      : args;
    const lock =
      env.STREAM_SYNC_MEMORY_LOCK ??
      join(env.STREAM_SYNC_MEMORY_DIR!, "core-suite.lock");
    const child = spawn(
      memory ? "flock" : "nice",
      [
        ...(memory
          ? [
              "--no-fork",
              "--nonblock",
              "--conflict-exit-code",
              "75",
              lock,
              "nice",
            ]
          : []),
        "-n",
        "19",
        "ionice",
        "-c3",
        process.execPath,
        ...nodeArgs,
      ],
      { env },
    );
    let out = "",
      err = "",
      rss = 0;
    const hostTimer = setInterval(() => {
      void observeHost("host-running");
    }, 60000);
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
      clearInterval(hostTimer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearInterval(timer);
      clearTimeout(deadline);
      clearInterval(hostTimer);
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
async function atomicJson(destination: string, value: unknown) {
  await writeFile(destination + ".tmp", JSON.stringify(value, null, 2));
  await rename(destination + ".tmp", destination);
}
async function saveReceipts() {
  const name = process.env.STREAM_SYNC_RECEIPT_NAME ?? "baseline-receipts";
  await atomicJson(
    join(process.env.STREAM_SYNC_MEMORY_DIR!, name + ".json"),
    receipts,
  );
}
async function observeHost(event = "host-admission") {
  const free = execFileSync("free", ["-g"], { encoding: "utf8" });
  const pressure = await readFile("/proc/pressure/memory", "utf8");
  const availableGiB = Number(
    free
      .split("\n")
      .find((s) => s.startsWith("Mem:"))
      ?.trim()
      .split(/\s+/)
      .at(-1),
  );
  const fullAvg60 = Number(pressure.match(/full .*?avg60=([\d.]+)/)?.[1]);
  const health = {
    event,
    at: new Date().toISOString(),
    availableGiB,
    fullAvg60,
    free,
    pressure,
  };
  await appendFile(
    join(process.env.STREAM_SYNC_MEMORY_DIR!, "host-health.jsonl"),
    JSON.stringify(health) + "\n",
  );
  receipts.push(health);
  console.log(JSON.stringify(health));
  return health;
}
async function healthyHost() {
  for (;;) {
    const health = await observeHost();
    await saveReceipts();
    if (health.availableGiB >= 12 && health.fullAvg60 < 1) return;
    await new Promise((resolve) => setTimeout(resolve, 60000));
  }
}
async function measure(mode: string, n: number, pad = 1024) {
  const completed = join(
    process.env.STREAM_SYNC_MEMORY_DIR!,
    `completed-${mode}-${n}-${pad}.json`,
  );
  if (process.env.STREAM_SYNC_MEMORY_RESUME === "1") {
    const cached = await readFile(completed, "utf8")
      .then((s) => JSON.parse(s))
      .catch((error) => {
        if (error.code === "ENOENT") return null;
        throw error;
      });
    if (cached?.bundleHash === bundleHash) {
      receipts.push(
        { event: "reused-completed-case", mode, n, pad, bundleHash },
        ...cached.rows,
      );
      await saveReceipts();
      return cached.rows;
    }
  }
  await healthyHost();
  const dir = join(scratch, `${mode}-${n}-${pad}`);
  await mkdir(dir);
  try {
    for (let attempt = 1; attempt <= 3;) {
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
        const decoded = output
          .trim()
          .split("\n")
          .filter((s) => s.startsWith("{"))
          .map((s) => ({ ...JSON.parse(s), case: mode, attempt }));
        const rows = decoded.filter((r) => r.phase);
        receipts.push(...decoded.filter((r) => !r.phase));
        if (rows.length === 0) throw Error("measurement produced no receipt");
        await atomicJson(completed, { bundleHash, rows });
        receipts.push(...rows);
        await saveReceipts();
        console.log(JSON.stringify(rows));
        return rows;
      } catch (error) {
        if (String(error).includes("subprocess exit 75,")) {
          receipts.push({
            event: "admission-deferred",
            mode,
            n,
            pad,
            reason: "shared lock busy or health changed after acquisition",
          });
          await saveReceipts();
          await new Promise((resolve) => setTimeout(resolve, 60000));
          await healthyHost();
          continue;
        }
        receipts.push({ mode, n, pad, attempt, error: String(error) });
        await saveReceipts();
        // Retry only process death, never an assertion or fixture/semantic failure.
        if (attempt === 3 || !/signal SIG[A-Z]+/.test(String(error)))
          throw error;
        attempt++;
        await rm(dir, { recursive: true, force: true });
        await mkdir(dir);
        await new Promise((resolve) => setTimeout(resolve, 60000));
        await healthyHost();
      }
    }
    throw Error("exhausted subprocess attempts");
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
    bundleHash = createHash("sha256")
      .update(await readFile(join(scratch, "measure.mjs")))
      .digest("hex");
    receipts.push({
      event: "harness-bundle",
      sha256: bundleHash,
      head: execFileSync("git", ["rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim(),
    });
  });
  afterAll(async () => {
    if (!scratch) return;
    await saveReceipts();
    await rm(scratch, { recursive: true, force: true });
  });
  it("compaction retains at most one output unit before upload", async () => {
    const [r] = await measure("compaction", 10000);
    expect
      .soft(r.outputBytes, "all ciphertext candidates remain reachable")
      .toBeLessThanOrEqual(r.ledger.C);
    const [history] = await measure("history", 1000);
    expect
      .soft(
        history.foldInputBytes,
        "old historical versions stay in the fold input",
      )
      .toBeLessThanOrEqual(history.ledger.C * 2);
    const [slow] = await measure("slow-upload", 10000);
    expect(slow.uploadBarriers).toBeGreaterThan(0);
    expect
      .soft(slow.candidateBytes, "slow uploads retain the complete candidate")
      .toBeLessThanOrEqual(slow.ledger.C);
  }, 86400000);
  it("rebase retains only one fold unit during atomic seed", async () => {
    const [r] = await measure("rebase", 10000);
    expect(r.position).toBe(0);
    expect(Math.max(r.foldInputBytes, r.liveDecodedBytes)).toBeLessThanOrEqual(
      r.ledger.C * 2,
    );
  }, 86400000);
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
  }, 86400000);
  it("progressive commits release consumed decoded batches", async () => {
    const [r] = await measure("progressive", 10000);
    expect(r.snapshot, "scenario must contain a snapshot").toBe(true);
    expect(r.liveDecodedBytes).toBeLessThanOrEqual(r.ledger.C * 2);
  }, 86400000);
  it("covered replacement preflight reads one bounded body unit", async () => {
    const rows = await measure("replace", 10000);
    expect(
      Math.max(...rows.map((r) => Math.max(r.operationBytes, r.queryBytes))),
    ).toBeLessThanOrEqual(rows[0].ledger.C);
  }, 86400000);
  it("real encryption roundtrips and calibrates single-unit allocations", async () => {
    const rows = await measure("crypto", 1);
    expect(rows[0].roundtrip).toBe(true);
    expect(rows[0].encryptedObjects).toBeGreaterThan(0);
    for (const key of ["Bcrypto", "bR", "bC", "bT"])
      expect(rows[0].ledger[key]).toBeGreaterThanOrEqual(0);
  }, 86400000);
  it("key metadata and finalize requests fit an encoded frame", async () => {
    const [jobs] = await measure("jobs", 1, 0);
    expect(jobs.settled).toBe(true);
    expect
      .soft(jobs.maxHeavyJobs, "heavy connection jobs lack global admission")
      .toBeLessThanOrEqual(1);
    expect(jobs.cancelled).toBe(16);
    expect(jobs.cancelledStarted).toBe(0);
    const [receipted] = await measure("receipts", 1, 0);
    expect(receipted.committed).toBe(true);
    expect
      .soft(
        receipted.metadataBytes,
        "resume materializes every durable unit receipt",
      )
      .toBeLessThanOrEqual(receipted.ledger.P);
    const [many] = await measure("many-streams", 5000, 0);
    expect(many.equivalent).toBe(true);
    expect(many.streams).toBe(512);
    const rows = await measure("metadata", 100000, 0);
    expect
      .soft(
        Math.max(...rows.map((r) => Math.max(r.metadataBytes, r.batchBytes))),
      )
      .toBeLessThanOrEqual(rows[0].ledger.T);
    const sorts = rows
      .flatMap((r) => r.explain ?? [])
      .filter((p) => p.plan.some((s: string) => s.includes("TEMP B-TREE")));
    expect
      .soft(
        Math.max(0, ...sorts.map((p) => p.bytes)),
        "changed-key selection performs a full sort",
      )
      .toBeLessThanOrEqual(rows[0].ledger.P);
    const indexed = rows.find((r) => r.phase === "indexed-page-control");
    expect(indexed.equivalent).toBe(true);
    expect(indexed.indexedCount).toBe(100000);
    expect(indexed.queryBytes).toBeLessThanOrEqual(indexed.ledger.P);
    expect(
      indexed.explain.every((p) =>
        p.plan.every((s: string) => !s.includes("TEMP B-TREE")),
      ),
    ).toBe(true);
  }, 86400000);
});
