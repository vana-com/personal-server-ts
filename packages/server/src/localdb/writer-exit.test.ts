import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type * as WorkerThreads from "node:worker_threads";
import { afterEach, describe, expect, it, vi } from "vitest";

// The test ends the writer worker the way a crash would, from outside the
// driver: it keeps a handle on every worker the driver starts.
const workers = vi.hoisted(
  () => [] as { role: string; worker: WorkerThreads.Worker }[],
);
vi.mock("node:worker_threads", async (importOriginal) => {
  const original = await importOriginal<typeof WorkerThreads>();
  class RecordingWorker extends original.Worker {
    constructor(
      file: URL | string,
      options?: { workerData?: { role: string } },
    ) {
      super(file, options as never);
      workers.push({ role: options?.workerData?.role ?? "", worker: this });
    }
  }
  return { ...original, Worker: RecordingWorker };
});

const { openBetterSqlite3 } = await import("./better-sqlite3-driver.js");

const SEAM = fileURLToPath(
  new URL("./open-seam.test-utils.cjs", import.meta.url),
);

describe("writer worker exit", () => {
  const dirs: string[] = [];
  afterEach(() => {
    workers.length = 0;
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const workerOf = (role: string): WorkerThreads.Worker =>
    workers.find((w) => w.role === role)!.worker;

  it("stops the read connection when the writer worker dies without close()", async () => {
    const dir = mkdtempSync(join(process.cwd(), ".writer-exit-test-"));
    dirs.push(dir);
    const db = openBetterSqlite3(join(dir, "db.sqlite"));
    await db.query("CREATE TABLE t (x)");
    await db.reads!.query("SELECT 1"); // the read connection is up
    const writer = workerOf("writer");
    const reader = workerOf("reader");
    const readerExit = once(reader, "exit");

    await writer.terminate(); // not close(): the writer is gone

    await readerExit; // the reader worker ended
    await expect(db.reads!.query("SELECT 1")).rejects.toThrow(
      /sqlite_writer_failed/,
    );
    await expect(db.query("SELECT 1")).rejects.toThrow(/sqlite_worker_exited/);
  });

  it("fails a read that was waiting on the reader when the writer dies", async () => {
    const dir = mkdtempSync(join(process.cwd(), ".writer-exit-test-"));
    dirs.push(dir);
    const db = openBetterSqlite3(join(dir, "db.sqlite"));
    await db.query("CREATE TABLE t (x)");
    const writerExit = once(workerOf("writer"), "exit");

    await workerOf("writer").terminate();
    await writerExit;

    // The read connection never started: it must not start for a dead writer.
    await expect(db.reads!.query("SELECT 1")).rejects.toThrow(
      /sqlite_writer_failed/,
    );
    expect(workers.some((w) => w.role === "reader")).toBe(false);
  });

  /** The reader worker parks at `step`; resolves once it is parked there. */
  const parkedReader = (step: "open" | "run") => {
    const gate = new Int32Array(new SharedArrayBuffer(8));
    return {
      testSeam: { module: SEAM, data: { park: step, gate: gate.buffer } },
      parked: Atomics.waitAsync(gate, 0, 0).value as Promise<unknown>,
      release: () => {
        Atomics.store(gate, 1, 1);
        Atomics.notify(gate, 1);
      },
    };
  };

  for (const [step, what] of [
    ["run", "a read that is running on the reader"],
    ["open", "a read waiting for the reader to start"],
  ] as const) {
    it(`rejects ${what} when the writer dies, and ends the reader`, async () => {
      const dir = mkdtempSync(join(process.cwd(), ".writer-exit-test-"));
      dirs.push(dir);
      const seam = parkedReader(step);
      const db = openBetterSqlite3(join(dir, "db.sqlite"), {
        testSeam: seam.testSeam,
      });
      await db.query("CREATE TABLE t (x)");
      const read = db.reads!.query("SELECT 1");
      const outcome = read.then(
        () => "resolved",
        (error: Error) => error.message,
      );
      await seam.parked; // the reader holds this read: it is in flight
      const readerExit = once(workerOf("reader"), "exit");

      await workerOf("writer").terminate();

      expect(await outcome).toMatch(/sqlite_writer_failed/);
      await readerExit;
      seam.release();
    });
  }
});
