/**
 * A stop that meets a failed repair, in real child processes. Each child runs
 * the ledger and then lets its event loop end on its own, as a host does on
 * shutdown; nothing in the test keeps a child alive. The parent then reopens
 * the store, as the next boot would, and reads the counts it finds.
 */
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { STOP_REPAIR_WINDOW_MS } from "./upload-attempts.js";

const LEDGER_URL = new URL("./upload-attempts.ts", import.meta.url).href;
const OWNER = "0x2222222222222222222222222222222222222222";

/**
 * The child: a store backed by one file. Write call N follows `plan[N - 1]`
 * ("ok", "fail", or "commit-uncertain": stored, then reported uncertain);
 * later writes follow `AFTER`. `MODE=shutdown` begins one attempt and stops;
 * `MODE=recover` only reopens and prints what the ledger counted.
 */
const CHILD = `
import { readFileSync, writeFileSync, existsSync } from "node:fs";
const {
  createUploadAttemptLedger,
  UploadAttemptWriteUncertainError,
} = await import(process.env.LEDGER_URL);
const FILE = process.env.STORE_FILE;
const OWNER = process.env.OWNER;
const plan = JSON.parse(process.env.PLAN ?? "[]");
const after = process.env.AFTER ?? "ok";
const entry = {
  id: 1, fileId: null, schemaId: null, path: "scope.1/p.json", scope: "scope.1",
  collectedAt: "2026-11-07T10:01:00Z", createdAt: "2026-11-07T10:01:00Z",
  sizeBytes: 1024, version: 1, dataPointId: null,
};
let writes = 0;
const store = {
  namespace: "file:" + FILE,
  async read() {
    return existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
  },
  async write(envelope) {
    writes += 1;
    const step = writes <= plan.length ? plan[writes - 1] : after;
    if (step === "fail") throw new Error("disk down");
    writeFileSync(FILE, JSON.stringify(envelope));
    if (step === "commit-uncertain")
      throw new UploadAttemptWriteUncertainError("stored");
  },
  async preserveCorrupt() {
    throw new Error("not expected");
  },
};
const ledger = createUploadAttemptLedger(store, OWNER);
const report = { begin: null, stop: null };
await ledger.recover();
if (process.env.MODE === "shutdown") {
  try {
    await ledger.begin(entry);
    report.begin = "ok";
  } catch (error) {
    report.begin = error.name;
  }
  try {
    await ledger.close();
    report.stop = "ok";
  } catch (error) {
    report.stop = error.name;
  }
}
const mine = (JSON.parse(existsSync(FILE) ? readFileSync(FILE, "utf8") : "{\\"records\\":[]}").records ?? [])
  .filter((r) => r.owner === OWNER.toLowerCase());
report.records = mine.map((r) => ({ interrupted: r.interrupted, inFlight: r.inFlight, quarantined: r.quarantined }));
report.quarantined = ledger.quarantined().length;
console.log("REPORT " + JSON.stringify(report));
`;

interface Report {
  begin: string | null;
  stop: string | null;
  records: Array<{
    interrupted: number;
    inFlight: boolean;
    quarantined: boolean;
  }>;
  quarantined: number;
}

/**
 * Scenario children. `refused`: entry 1 stays live, entry 2's admission is
 * refused with its rollback failing, storage heals, then a default stop
 * returns and the process ends. `crash`: one admission never settles and the
 * process ends. `late`: a default stop returns with entry 1 live; the body
 * then ends and its terminal write and immediate repair fail before storage
 * heals.
 */
const SCENARIO_CHILD = `
import { readFileSync, writeFileSync, existsSync } from "node:fs";
const {
  createUploadAttemptLedger,
  UploadAttemptWriteUncertainError,
} = await import(process.env.LEDGER_URL);
const FILE = process.env.STORE_FILE;
const OWNER = process.env.OWNER;
const plan = JSON.parse(process.env.PLAN ?? "[]");
const after = process.env.AFTER ?? "ok";
const entryOf = (id) => ({
  id, fileId: null, schemaId: null, path: "scope." + id + "/p.json",
  scope: "scope." + id, collectedAt: "2026-11-07T10:0" + id + ":00Z",
  createdAt: "2026-11-07T10:0" + id + ":00Z", sizeBytes: 1024, version: 1,
  dataPointId: null,
});
let writes = 0;
const store = {
  namespace: "file:" + FILE,
  async read() {
    return existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : null;
  },
  async write(envelope) {
    writes += 1;
    const step = writes <= plan.length ? plan[writes - 1] : after;
    if (step === "fail") throw new Error("disk down");
    writeFileSync(FILE, JSON.stringify(envelope));
    if (step === "commit-uncertain")
      throw new UploadAttemptWriteUncertainError("stored");
  },
  async preserveCorrupt() {
    throw new Error("not expected");
  },
};
const ledger = createUploadAttemptLedger(store, OWNER);
const report = {};
await ledger.recover();
const mode = process.env.MODE;
if (mode === "refused") {
  const token = await ledger.begin(entryOf(1));
  report.a = "begun";
  try {
    await ledger.begin(entryOf(2));
    report.b = "ok";
  } catch (error) {
    report.b = error.name;
  }
  await ledger.close();
  report.stop = "ok";
} else if (mode === "crash") {
  await ledger.begin(entryOf(1));
} else if (mode === "late") {
  const token = await ledger.begin(entryOf(1));
  await ledger.close();
  report.stop = "ok";
  await new Promise((wake) => setTimeout(wake, 100));
  try {
    await ledger.settle(token, "failure");
    report.settle = "ok";
  } catch (error) {
    report.settle = error.name;
  }
} else if (mode === "f3") {
  // A and C begin; the stop gives up on both at once (grace 0); then A
  // settles while C is still live.
  const a = await ledger.begin(entryOf(1));
  await ledger.begin(entryOf(2));
  await ledger.close(0);
  report.stop = "ok";
  try {
    await ledger.settle(a, "success");
    report.settle = "ok";
  } catch (error) {
    report.settle = error.name;
  }
} else if (mode === "f4") {
  // A begins; a default stop starts; another manager takes the store back
  // before A settles, and A's settlement write is refused.
  const a = await ledger.begin(entryOf(1));
  const closing = ledger.close();
  await ledger.recover();
  try {
    await ledger.settle(a, "success");
    report.settle = "ok";
  } catch (error) {
    report.settle = error.name;
  }
  await closing;
  report.stop = "ok";
} else if (mode === "f6") {
  // A begins and never settles; B's admission is refused with an uncertain
  // marker that cannot be rolled back; then the stop is void (not awaited).
  await ledger.begin(entryOf(1));
  try {
    await ledger.begin(entryOf(2));
    report.b = "ok";
  } catch (error) {
    report.b = error.name;
  }
  void ledger.close(Infinity);
  report.stop = "void";
}
const mine = (JSON.parse(existsSync(FILE) ? readFileSync(FILE, "utf8") : "{\\"records\\":[]}").records ?? [])
  .filter((r) => r.owner === OWNER.toLowerCase());
report.records = mine.map((r) => ({ rowId: r.rowId, interrupted: r.interrupted, inFlight: r.inFlight, quarantined: r.quarantined }));
console.log("REPORT " + JSON.stringify(report));
`;

interface ScenarioReport {
  stop?: string;
  records: Array<{
    rowId: number;
    interrupted: number;
    inFlight: boolean;
    quarantined: boolean;
  }>;
}

/** Run one scenario child to its natural end, with the same plan rules. */
function runScenario(
  file: string,
  mode: "refused" | "crash" | "late" | "f3" | "f4" | "f6" | "recover",
  plan: string[] = [],
) {
  return new Promise<{ report: ScenarioReport; code: number | null }>(
    (resolve, reject) => {
      const child = spawn(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "-e", SCENARIO_CHILD],
        {
          env: {
            ...process.env,
            LEDGER_URL,
            STORE_FILE: file,
            OWNER,
            PLAN: JSON.stringify(plan),
            AFTER: "ok",
            MODE: mode,
          },
          cwd: fileURLToPath(new URL(".", import.meta.url)),
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let out = "";
      let err = "";
      child.stdout.on("data", (chunk) => (out += chunk));
      child.stderr.on("data", (chunk) => (err += chunk));
      child.on("error", reject);
      child.on("close", (code) => {
        const line = out.split("\n").find((l) => l.startsWith("REPORT "));
        if (!line) {
          reject(new Error(`child printed no report (exit ${code}): ${err}`));
          return;
        }
        resolve({
          report: JSON.parse(line.slice("REPORT ".length)) as ScenarioReport,
          code,
        });
      });
    },
  );
}

/** Run one child to its natural end; resolve with its report and wall time. */
function runChild(
  file: string,
  env: { MODE: "shutdown" | "recover"; PLAN?: string[]; AFTER?: "ok" | "fail" },
) {
  const started = Date.now();
  return new Promise<{
    report: Report;
    elapsedMs: number;
    code: number | null;
  }>((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", CHILD],
      {
        env: {
          ...process.env,
          LEDGER_URL,
          STORE_FILE: file,
          OWNER,
          PLAN: JSON.stringify(env.PLAN ?? []),
          AFTER: env.AFTER ?? "ok",
          MODE: env.MODE,
        },
        cwd: fileURLToPath(new URL(".", import.meta.url)),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => (out += chunk));
    child.stderr.on("data", (chunk) => (err += chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      const line = out.split("\n").find((l) => l.startsWith("REPORT "));
      if (!line) {
        reject(new Error(`child printed no report (exit ${code}): ${err}`));
        return;
      }
      resolve({
        report: JSON.parse(line.slice("REPORT ".length)) as Report,
        elapsedMs: Date.now() - started,
        code,
      });
    });
  });
}

describe("a stop that meets a failed repair, across real process exits", () => {
  it("loses no marker when storage heals on the first stop retry, and reopening twice counts nothing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Write 1: the begin's marker, stored but reported uncertain. Write 2:
      // the begin's repair fails, so the begin rejects. Write 3: the first
      // stop's repair fails. From write 4 on, storage is healthy.
      const shutdown = await runChild(file, {
        MODE: "shutdown",
        PLAN: ["commit-uncertain", "fail", "fail"],
        AFTER: "ok",
      });
      expect(shutdown.code).toBe(0);
      expect(shutdown.report.begin).toBe("UploadAttemptStorageFailedError");

      const first = await runChild(file, { MODE: "recover" });
      const second = await runChild(file, { MODE: "recover" });
      for (const boot of [first, second]) {
        expect(boot.code).toBe(0);
        expect(boot.report.quarantined).toBe(0);
        expect(boot.report.records.every((r) => r.interrupted === 0)).toBe(
          true,
        );
        expect(boot.report.records.some((r) => r.inFlight)).toBe(false);
      }
      expect(shutdown.report.stop).toBe("ok");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);

  it("exits on its own once the window has passed, and counts the surviving marker once", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Storage never heals after the begin's uncertain write.
      const shutdown = await runChild(file, {
        MODE: "shutdown",
        PLAN: ["commit-uncertain"],
        AFTER: "fail",
      });
      expect(shutdown.code).toBe(0);
      expect(shutdown.report.begin).toBe("UploadAttemptStorageFailedError");
      expect(shutdown.report.stop).toBe("UploadAttemptStorageFailedError");
      // The stop retried (the first retry is after one second), gave up
      // before the window ended (the backoff's last retry that fits is
      // inside it), and the process then ended without anything holding it.
      expect(shutdown.elapsedMs).toBeGreaterThanOrEqual(1000);
      expect(shutdown.elapsedMs).toBeLessThan(STOP_REPAIR_WINDOW_MS + 5_000);

      // The next boot, with healthy storage, counts the marker exactly once.
      const next = await runChild(file, { MODE: "recover" });
      expect(next.report.records).toEqual([
        { interrupted: 1, inFlight: false, quarantined: false },
      ]);
      expect(next.report.quarantined).toBe(0);
      const later = await runChild(file, { MODE: "recover" });
      expect(later.report.records).toEqual([
        { interrupted: 1, inFlight: false, quarantined: false },
      ]);
      expect(readFileSync(file, "utf8")).toContain('"interrupted":1');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);

  it("keeps a refused admission out of the count when storage heals before a stop with a live body", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Writes per process: 1 entry 1's marker; 2 entry 2's marker, stored but
      // reported uncertain; 3 its rollback, which fails. From write 4 storage
      // is healthy, before the stop.
      const plan = ["ok", "commit-uncertain", "fail"];
      for (let run = 1; run <= 2; run++) {
        const stop = await runScenario(file, "refused", plan);
        expect(stop.code).toBe(0);
        expect(stop.report.stop).toBe("ok");
        const boot = await runScenario(file, "recover");
        expect(boot.code).toBe(0);
        const refused = boot.report.records.find((r) => r.rowId === 2);
        expect(refused?.interrupted ?? 0).toBe(0);
        expect(refused?.quarantined ?? false).toBe(false);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);

  it("does not quarantine an entry whose body ends after a clean stop when its terminal repair fails first", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // One earlier interruption, counted at the next boot.
      expect((await runScenario(file, "crash")).code).toBe(0);
      expect((await runScenario(file, "recover")).report.records).toEqual([
        expect.objectContaining({ rowId: 1, interrupted: 1, inFlight: false }),
      ]);
      // Writes: 1 the marker; 2 the body's terminal write, failing; 3 its
      // immediate repair, failing; from 4 storage is healthy.
      const late = await runScenario(file, "late", ["ok", "fail", "fail"]);
      expect(late.code).toBe(0);
      expect(late.report.stop).toBe("ok");
      for (const boot of [
        await runScenario(file, "recover"),
        await runScenario(file, "recover"),
      ]) {
        expect(boot.code).toBe(0);
        expect(boot.report.records).toEqual([
          expect.objectContaining({
            rowId: 1,
            interrupted: 1,
            inFlight: false,
            quarantined: false,
          }),
        ]);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);

  it("repairs a late failed settlement under a stop even while another attempt is still live", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Writes: 1 A's marker; 2 C's marker; 3 A's settlement, refused. From 4
      // storage is healthy. C never settles, so only A's marker may be gone.
      const run = await runScenario(file, "f3", ["ok", "ok", "fail"]);
      expect(run.code).toBe(0);
      expect(run.report.stop).toBe("ok");
      const boot = await runScenario(file, "recover");
      expect(boot.code).toBe(0);
      expect(boot.report.records.find((r) => r.rowId === 1)).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);

  it("repairs a settlement refused after a default stop has been handed back to another manager", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Writes: 1 A's marker; 2 A's settlement, refused. From 3 storage heals.
      const run = await runScenario(file, "f4", ["ok", "fail"]);
      expect(run.code).toBe(0);
      expect(run.report.stop).toBe("ok");
      const boot = await runScenario(file, "recover");
      expect(boot.code).toBe(0);
      expect(
        boot.report.records.find((r) => r.rowId === 1)?.interrupted ?? 0,
      ).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);

  it("repairs a refused, uncertain admission before a void stop waits on a body that never ends", async () => {
    const dir = mkdtempSync(join(tmpdir(), "upload-attempts-"));
    try {
      const file = join(dir, "upload-attempts.json");
      // Writes: 1 A's marker; 2 B's marker, stored but reported uncertain; 3
      // B's rollback, refused. From 4 storage is healthy, before the stop.
      const run = await runScenario(file, "f6", [
        "ok",
        "commit-uncertain",
        "fail",
      ]);
      expect(run.code).toBe(0);
      expect(run.report.b).toBe("UploadAttemptStorageFailedError");
      const boot = await runScenario(file, "recover");
      expect(boot.code).toBe(0);
      expect(boot.report.records.find((r) => r.rowId === 2)).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 90_000);
});
