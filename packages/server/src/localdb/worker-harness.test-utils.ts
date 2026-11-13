import { fileURLToPath } from "node:url";
import type * as WorkerThreads from "node:worker_threads";

/**
 * Test-side routing for the SQLite workers. A test file mocks
 * `node:worker_threads` with `hookedWorkerClass`; the driver starts its
 * workers as usual, and the Worker class here keeps a handle on each and,
 * when `harness.hooks` is set, starts `worker-bootstrap.test-utils.cjs` in
 * front of the real worker file. The shipped driver and worker hold no hook.
 */
const BOOTSTRAP = fileURLToPath(
  new URL("./worker-bootstrap.test-utils.cjs", import.meta.url),
);

export interface WorkerHooks {
  /** Writer: another file replaces the database between create and open. */
  readonly replaceAfterCreate?: true;
  /** Reader: stop at `step` until the test releases `gate`. */
  readonly park?: { step: "open" | "run"; gate: SharedArrayBuffer };
}

export const harness = {
  /** Applies to workers the driver starts after it is set. */
  hooks: {} as WorkerHooks,
  /** Every worker the driver started, so a test can end one like a crash. */
  workers: [] as { role: string; worker: WorkerThreads.Worker }[],
};

export function hookedWorkerClass(
  Base: typeof WorkerThreads.Worker,
): typeof WorkerThreads.Worker {
  return class HookedWorker extends Base {
    constructor(
      file: URL | string,
      options?: { workerData?: { role?: string } },
    ) {
      const hooked = Object.keys(harness.hooks).length > 0;
      super(
        hooked ? BOOTSTRAP : file,
        (hooked
          ? {
              ...options,
              workerData: {
                ...options?.workerData,
                harness: {
                  worker: typeof file === "string" ? file : fileURLToPath(file),
                  ...harness.hooks,
                },
              },
            }
          : options) as never,
      );
      harness.workers.push({
        role: options?.workerData?.role ?? "",
        worker: this,
      });
    }
  };
}
