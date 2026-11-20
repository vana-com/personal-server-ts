import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import type * as WorkerThreads from "node:worker_threads";
import { afterEach, describe, expect, it, vi } from "vitest";
import { harness } from "./worker-harness.test-utils.js";

// The test ends the writer worker the way a crash would, from outside the
// driver: the harness keeps a handle on every worker the driver starts, and
// puts a reader at an exact step of its open sequence (see the harness).
vi.mock("node:worker_threads", async (importOriginal) => {
  const { hookedWorkerClass } = await import("./worker-harness.test-utils.js");
  const original = await importOriginal<typeof WorkerThreads>();
  return { ...original, Worker: hookedWorkerClass(original.Worker) };
});

const { openBetterSqlite3 } = await import("./better-sqlite3-driver.js");
const { workers } = harness;

describe("writer worker exit", () => {
  const dirs: string[] = [];
  const gates: (() => void)[] = [];
  // Teardown cannot depend on the test body reaching its last line: release
  // every parked worker, end every worker, then delete the directories.
  afterEach(async () => {
    for (const release of gates.splice(0)) release();
    harness.hooks = {};
    const started = workers.splice(0);
    await Promise.all(started.map(({ worker }) => worker.terminate()));
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
    const release = () => {
      Atomics.store(gate, 1, 1);
      Atomics.notify(gate, 1);
    };
    gates.push(release);
    harness.hooks = { park: { step, gate: gate.buffer as SharedArrayBuffer } };
    return Atomics.waitAsync(gate, 0, 0).value as Promise<unknown>;
  };

  for (const [step, what] of [
    ["run", "a read that is running on the reader"],
    ["open", "a read waiting for the reader to start"],
  ] as const) {
    it(`rejects ${what} when the writer dies, and ends the reader`, async () => {
      const dir = mkdtempSync(join(process.cwd(), ".writer-exit-test-"));
      dirs.push(dir);
      const parked = parkedReader(step);
      const db = openBetterSqlite3(join(dir, "db.sqlite"));
      await db.query("CREATE TABLE t (x)");
      const read = db.reads!.query("SELECT 1");
      const outcome = read.then(
        () => "resolved",
        (error: Error) => error.message,
      );
      await parked; // the reader holds this read: it is in flight
      const readerExit = once(workerOf("reader"), "exit");

      await workerOf("writer").terminate();

      expect(await outcome).toMatch(/sqlite_writer_failed/);
      await readerExit;
    });
  }
});
