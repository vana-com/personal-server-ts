import type { Database, Statement } from "better-sqlite3";

/** One global evaluator bounds memory; each instance has one coalesced follow-up. */
export function createLegacyScopeRevalidator(input: {
  evaluate(instance: string, scopes: readonly string[]): Promise<void>;
  candidates(): readonly {
    instance: string;
    scopes: readonly string[];
    stale: boolean;
  }[];
  fingerprint(): string;
  intervalMs?: number;
  onChange?(): void;
  onSweep?(): void;
  onFailure?(instance: string, scopes: readonly string[]): void;
  logger: { warn(fields: Record<string, unknown>, message: string): void };
}) {
  const interval = input.intervalMs ?? 900_000;
  if (!Number.isFinite(interval) || interval < 100 || interval > 900_000)
    throw Error("Coverage sweep interval must be 100..900000 ms");
  const pending = new Map<string, Set<string>>();
  let running: Promise<void> | undefined;
  let closed = false;
  let fingerprint = input.fingerprint();
  let pollTimer: ReturnType<typeof setInterval> | undefined;
  let sweepTimer: ReturnType<typeof setInterval> | undefined;
  function enqueue(instance: string, scopes: readonly string[]) {
    if (closed) return;
    const next = pending.get(instance) ?? new Set<string>();
    for (const scope of scopes) next.add(scope);
    pending.set(instance, next);
    if (!running) {
      schedule();
    }
  }
  function schedule() {
    running = Promise.resolve()
      .then(drain)
      .finally(() => {
        running = undefined;
        if (!closed && pending.size) schedule();
      });
  }
  async function drain() {
    while (!closed && pending.size) {
      const [instance, scopes] = pending.entries().next().value!;
      pending.delete(instance);
      try {
        await input.evaluate(instance, [...scopes]);
      } catch {
        try {
          input.onFailure?.(instance, [...scopes]);
        } catch {
          input.logger.warn(
            { reason: "diagnostic_write_failed" },
            "Could not persist re-evaluation failure",
          );
        }
        input.logger.warn(
          { instance, scopes: [...scopes], reason: "evaluation_failed" },
          "Legacy coverage re-evaluation failed; retaining prior verdict",
        );
      }
    }
  }
  function scan(force: boolean) {
    if (closed) return;
    try {
      for (const candidate of input.candidates())
        if (force || candidate.stale)
          enqueue(candidate.instance, candidate.scopes);
    } catch {
      input.logger.warn(
        { reason: "scan_failed" },
        "Legacy coverage recovery scan failed",
      );
    }
  }
  function sweep() {
    try {
      input.onSweep?.();
      scan(true);
    } catch {
      input.logger.warn(
        { reason: "sweep_failed" },
        "Legacy coverage recovery sweep failed",
      );
    }
  }
  return {
    enqueue,
    start() {
      sweep();
      pollTimer = setInterval(
        () => {
          try {
            const next = input.fingerprint();
            if (next !== fingerprint) {
              fingerprint = next;
              input.onChange?.();
              scan(true);
            }
          } catch {
            input.logger.warn(
              { reason: "poll_failed" },
              "Legacy coverage dependency poll failed",
            );
          }
        },
        Math.min(1000, interval),
      );
      // Force real evaluation even for equal cursors: baseline cursors omit blob/replica inputs.
      sweepTimer = setInterval(sweep, interval);
      pollTimer.unref();
      sweepTimer.unref();
    },
    async idle() {
      while (running) await running;
    },
    async stop() {
      closed = true;
      pending.clear();
      clearInterval(pollTimer);
      clearInterval(sweepTimer);
      if (running) await running;
    },
  };
}

const candidateQueries = new WeakMap<Database, Statement<[]>>();

/** Durable candidate identities only; the worker reuses the full live decision. */
export function legacyCoverageCandidates(db: Database) {
  let query = candidateQueries.get(db);
  if (!query) {
    query = db.prepare(
      `SELECT DISTINCT b.instance,t.scope FROM legacy_scope_takeovers t
    JOIN pdpp_instance_binding b ON (t.instance=b.instance AND t.generation=b.generation) OR t.instance=''
    WHERE b.deleted_at IS NULL AND EXISTS(SELECT 1 FROM data_files f WHERE f.scope=t.scope)
    ORDER BY b.instance,t.scope`,
    );
    candidateQueries.set(db, query);
  }
  const rows = query.all() as { instance: string; scope: string }[];
  const candidates = new Map<
    string,
    { instance: string; scopes: string[]; stale: boolean }
  >();
  for (const { instance, scope } of rows) {
    const candidate = candidates.get(instance) ?? {
      instance,
      scopes: [],
      stale: true,
    };
    candidate.scopes.push(scope);
    candidates.set(instance, candidate);
  }
  return [...candidates.values()];
}
