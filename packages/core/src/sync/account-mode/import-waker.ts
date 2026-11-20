/**
 * Wakes the legacy import when an account is switched to stream sync.
 *
 * This is all the account-mode side does about the import. What is owed, what
 * is done and what may be written are the import writer's own record (the
 * writer gate); the importer is an injected port, so this file knows nothing
 * of how it works.
 *
 * - `wake()` runs the importer when the owner is switched, and joins a run that
 *   is already going. The check and the start have no await between them, so
 *   two callers in one tick start one run.
 * - A host wakes it at each Account answer that leaves the owner On (the
 *   authority's `onOn`) and once at boot. A failed run is logged and tried
 *   again at the next answer. There is no timer.
 * - `stop()` refuses new wakes, aborts the run and waits for it to return. A
 *   host closes the importer's storage after that.
 */

import type { ModeAuthority } from "./authority.js";

/** The importer, as the account-mode side sees it. */
export interface ImportRunner {
  run(signal: AbortSignal): Promise<void>;
}

export interface ImportWaker {
  /** Never rejects. Resolves when the run it started or joined has ended. */
  wake(): Promise<void>;
  /** Abort the run in flight and wait for it. Later wakes do nothing. */
  stop(): Promise<void>;
}

export interface ImportWakerOptions {
  authority: Pick<ModeAuthority, "ready" | "read">;
  owner: string;
  importer: ImportRunner;
  onWarning?: (message: string, detail?: unknown) => void;
}

export function createImportWaker(options: ImportWakerOptions): ImportWaker {
  const { authority, owner, importer } = options;
  const warn = options.onWarning ?? (() => {});
  const controller = new AbortController();
  let stopped = false;
  let running: Promise<void> | undefined;

  const start = (): Promise<void> => {
    const run = Promise.resolve()
      .then(() => (stopped ? undefined : importer.run(controller.signal)))
      .catch((error: unknown) => {
        warn(
          "the legacy import failed; it runs again at the next answer",
          error,
        );
      })
      .finally(() => {
        if (running === run) running = undefined;
      });
    running = run;
    return run;
  };

  return {
    async wake() {
      // Records load before the first read; boot may ask before they have.
      await authority.ready;
      // `stop()` may have landed during the await above.
      if (stopped) return;
      if (authority.read(owner).kind !== "streams") return;
      await (running ?? start());
    },
    async stop() {
      stopped = true;
      controller.abort();
      await running;
    },
  };
}
