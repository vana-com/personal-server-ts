import { NeedsFencedPublicationError } from "@opendatalabs/personal-server-ts-core/publication";
import {
  AdditionsBudget,
  AdditionsBudgetExceeded,
  additionsLedgerScope,
  ADDITIONS_SUMMARY_SCOPE,
  summarizeAdditions,
  type DurableAdditionsService,
} from "@opendatalabs/personal-server-ts-core/additions";
import { additionsTransfers } from "./additions-protocol.js";
import type {
  AdditionsOperation,
  AdditionsWorkerInit,
  HostMessage,
  WorkerMessage,
} from "./additions-protocol.js";
import type { DiagnosticsRecorder } from "./diagnostics.js";
import type { PsLiteAdditionsTransport } from "./additions-transport.js";

export interface AdditionsWorkerPort {
  postMessage(message: WorkerMessage, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<HostMessage>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
}
export interface PsLiteAdditionsSessionOptions {
  init: AdditionsWorkerInit;
  diagnostics?: DiagnosticsRecorder;
  transport: PsLiteAdditionsTransport;
  deleteSystemScope(scope: string): Promise<void>;
  /** Bundlers may supply their own URL/factory; no synchronous fallback exists. */
  workerFactory?: () => AdditionsWorkerPort;
}

export function createPsLiteAdditionsSession(
  options: PsLiteAdditionsSessionOptions,
): DurableAdditionsService {
  async function run(operation: AdditionsOperation): Promise<unknown> {
    const started = performance.now();
    // The longer window is for background summary reconstruction only.
    // Optional upload hints must not delay a registered source for minutes.
    const timeBudgetMs =
      operation.method === "summarize"
        ? options.init.timeBudgetMs
        : Math.min(10_000, options.init.timeBudgetMs);
    if (typeof navigator === "undefined" || !navigator.locks)
      throw new Error(
        "Bounded additions requires browser locks for persisted publication",
      );
    const signal = AbortSignal.timeout(timeBudgetMs);
    // Web Locks span tabs and survive worker restarts without a stale lease.
    return navigator.locks.request(
      JSON.stringify([
        "ps-lite.additions.v1",
        options.init.ownerAddress.toLowerCase(),
        options.init.network,
      ]),
      { mode: "exclusive", signal },
      async () => {
        signal.throwIfAborted();
        const remainingMs = Math.max(
          1,
          Math.floor(timeBudgetMs - (performance.now() - started)),
        );
        return runLocked(operation, remainingMs);
      },
    );
  }
  async function runLocked(
    operation: AdditionsOperation,
    remainingMs: number,
  ): Promise<unknown> {
    const controller = new AbortController();
    const transport = options.transport.openSession();
    const worker: AdditionsWorkerPort =
      options.workerFactory?.() ??
      new Worker(new URL("./additions-worker.bundle.js", import.meta.url), {
        type: "module",
      });
    const active = new Set<Promise<void>>();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await new Promise<unknown>((resolve, reject) => {
        let finished = false;
        const finish = (error?: Error, value?: unknown) => {
          if (finished) return;
          finished = true;
          controller.abort(error ?? new Error("Additions session complete"));
          worker.terminate();
          void Promise.allSettled([...active]).then(() =>
            error ? reject(error) : resolve(value),
          );
        };
        timer = setTimeout(
          () => finish(new Error("Additions worker deadline exceeded")),
          remainingMs,
        );
        worker.onerror = (event) =>
          finish(new Error(event.message || "Additions worker failed"));
        worker.onmessage = (event) => {
          if (finished) return;
          const message = event.data;
          if (message.kind === "diagnostic") {
            options.diagnostics?.observe({
              phase: "unknown",
              scope: message.event.scope,
              fileId: message.event.version,
              detail: `additions:${message.event.code}`,
              error: true,
            });
            return;
          }
          if (message.kind === "result") {
            finish(undefined, message.result);
            return;
          }
          if (message.kind === "error") {
            finish(new Error(message.error));
            return;
          }
          const task = (async () => {
            const budget = new AdditionsBudget(
              message.remaining,
              message.remainingMilliseconds === undefined ||
                !Number.isFinite(message.remainingMilliseconds)
                ? undefined
                : Math.max(0, Math.floor(message.remainingMilliseconds)),
              controller.signal,
            );
            try {
              const hostBudget = {
                signal: budget.signal,
                get remaining() {
                  return budget.remaining;
                },
                recordSpent(bytes: number) {
                  budget.recordSpent(bytes);
                },
                charge(bytes = 0) {
                  budget.signal?.throwIfAborted();
                  budget.charge(bytes);
                },
              };
              // This channel is private to the worker created above. Network
              // responses are validated in that worker, never trusted as JSON.
              const args = message.args;
              let result: unknown;
              switch (message.method) {
                case "fetch":
                  result = await transport.fetch(
                    args[0] as Parameters<typeof transport.fetch>[0],
                    hostBudget,
                  );
                  break;
                case "download":
                  result = await transport.download(
                    args[0] as string,
                    hostBudget,
                  );
                  break;
                case "signRequest":
                  result = await transport.signRequest(
                    args[0] as Parameters<typeof transport.signRequest>[0],
                    budget.signal,
                  );
                  break;
                case "publish":
                  result = await transport.publish(
                    args[0] as Parameters<typeof transport.publish>[0],
                    hostBudget,
                  );
                  break;
                case "readPending":
                  result = await transport.readPending(
                    args[0] as string,
                    hostBudget,
                  );
                  break;
                case "clearPending":
                  result = await transport.clearPending(
                    args[0] as string,
                    hostBudget,
                  );
                  break;
              }
              if (!finished)
                worker.postMessage(
                  {
                    kind: "response",
                    id: message.id,
                    result,
                    spent: message.remaining - budget.remaining,
                  },
                  additionsTransfers(result),
                );
            } catch (error) {
              if (!finished)
                worker.postMessage({
                  kind: "response",
                  id: message.id,
                  error: error instanceof Error ? error.message : String(error),
                  publicationBlocked:
                    error instanceof NeedsFencedPublicationError
                      ? { scope: error.scope, reason: error.reason }
                      : undefined,
                  budgetExceeded:
                    error instanceof AdditionsBudgetExceeded ||
                    budget.signal?.aborted,
                  spent: message.remaining - budget.remaining,
                });
            }
          })();
          active.add(task);
          void task.finally(() => active.delete(task));
        };
        worker.postMessage({
          kind: "run",
          init: {
            ...options.init,
            timeBudgetMs: remainingMs,
            byteBudget:
              operation.method === "summarize"
                ? options.init.byteBudget
                : Math.min(8 * 1024 * 1024, options.init.byteBudget),
          },
          operation,
        });
      });
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      controller.abort();
      worker.terminate();
      await Promise.allSettled([...active]);
    }
  }
  return {
    async summarize(input) {
      try {
        return (await run({ method: "summarize", args: [input] })) as Awaited<
          ReturnType<DurableAdditionsService["summarize"]>
        >;
      } catch {
        return summarizeAdditions({
          ...input,
          ledgers: [],
          coverage: "behind",
        });
      }
    },
    async recordUpload(version) {
      if (version.scope.startsWith("vana.system.")) return;
      // Upload bodies already belong to sync. Recovery reads bounded committed
      // blobs instead of cloning an arbitrarily large upload into the worker.
      try {
        await run({ method: "recordUpload", scope: version.scope });
      } catch {
        /* The next read retries authoritative recovery. */
      }
    },
    async deleteScope(scope, deletion) {
      if (scope.startsWith("vana.system.")) return;
      if (typeof navigator === "undefined" || !navigator.locks)
        throw new Error("Durable additions deletion requires browser locks");
      // Explicit durable deletion belongs to the ordinary sync pipeline and
      // has no bounded-recovery deadline or noncancelable worker RPC.
      const budget = deletion?.durableOnly
        ? new AdditionsBudget(
            Math.min(8 * 1024 * 1024, options.init.byteBudget),
            options.init.timeBudgetMs,
            deletion.signal,
          )
        : undefined;
      await navigator.locks.request(
        JSON.stringify([
          "ps-lite.additions.v1",
          options.init.ownerAddress.toLowerCase(),
          options.init.network,
        ]),
        { mode: "exclusive", signal: budget?.signal },
        async () => {
          if (budget) {
            await options.transport.deleteScope(scope, budget);
            return;
          }
          for (const target of [
            additionsLedgerScope(scope),
            ADDITIONS_SUMMARY_SCOPE,
          ]) {
            await options.deleteSystemScope(target);
            await options.transport.clearPending(target, new AdditionsBudget());
          }
        },
      );
    },
  };
}
