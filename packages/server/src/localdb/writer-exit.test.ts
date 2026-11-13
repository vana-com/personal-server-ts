import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
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
});
