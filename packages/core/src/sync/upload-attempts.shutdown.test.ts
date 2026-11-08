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
});
