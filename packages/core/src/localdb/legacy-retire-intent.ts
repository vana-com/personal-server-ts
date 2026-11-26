// Scheduling and status for connector legacy retirement. The pipeline owns
// capture, effects and completion; this owner only admits and retries passes.
import {
  createLegacyRetirePipeline,
  type LegacyRetirePipelinePorts,
} from "./legacy-retire-pipeline.js";
import {
  blocked,
  PART_DONE,
  PART_PENDING,
  type DeletePart,
} from "./delete-status.js";
import type { LocalSyncDeps } from "./deps.js";

/** What a request answers: the intent, and what is left of it. */
export interface LegacyRetireStatus {
  readonly retireId: string;
  /** `done` only after every bound scope's erasure was confirmed. */
  readonly legacy: DeletePart;
}

/** The account has not switched (or its mode cannot be read yet): nothing is retired. */
export class LegacyRetireNotAdmitted extends Error {
  constructor(readonly mode: "unswitched" | "unknown") {
    super(`legacy retirement refused: the account mode is ${mode}`);
    this.name = "LegacyRetireNotAdmitted";
  }
}

/** This host cannot reach the legacy side now (no ports, or the gateway head is unreadable). */
export class LegacyRetireUnavailable extends Error {
  constructor(message = "legacy retirement is unavailable here") {
    super(message);
    this.name = "LegacyRetireUnavailable";
  }
}

export interface LegacyRetirer {
  /**
   * Persist the intent (or find the one that exists) and start retiring.
   * Rejects `LegacyRetireNotAdmitted` before the switch or while the mode is
   * unknown, and `LegacyRetireUnavailable` when the heads cannot be read.
   */
  request(connector: string): Promise<{ readonly retireId: string }>;
  /** What is left of the connector's intent; `null` when it has none. */
  status(connector: string): Promise<LegacyRetireStatus | null>;
  /** Start the passes of every open intent (a restart's sweep). */
  resume(): Promise<void>;
  /** Connectors that still hold an in-memory pass or verdict. */
  retained(): number;
  /**
   * Stop scheduling and abort the passes. Resolves once every pass that was
   * running has returned, so the caller may close the database after it.
   */
  close(): Promise<void>;
}

export type LegacyRetirerDeps = Pick<
  LocalSyncDeps,
  "db" | "ownerAddress" | "logger" | "newOp" | "now"
>;

interface Intent {
  readonly retireId: string;
  readonly state: "open" | "done";
}

interface Loop {
  timer: ReturnType<typeof setTimeout> | undefined;
  running: boolean;
  again: boolean;
  delay: number;
}

/** A pass met a closed write gate between two host calls. */
class WriteNotReady extends Error {
  constructor() {
    super("legacy retirement paused: the host has no write authority now");
    this.name = "WriteNotReady";
  }
}

export function createLegacyRetirer(
  deps: LegacyRetirerDeps,
  options: {
    /** Read when a pass runs; `undefined`: this host cannot retire a legacy copy. */
    readonly ports: () => LegacyRetirePipelinePorts | undefined;
    readonly retryMs: { readonly first: number; readonly max: number };
    /**
     * Host write authority, checked before every issued mutation: while a
     * registration is held, a pass sends no tombstone, advances no journal step
     * and erases no blob. A definite not-sent attempt may undo its provisional
     * marker. Absent or undefined: not ready.
     */
    readonly writeReady?: () => boolean;
  },
): LegacyRetirer {
  const owner = deps.ownerAddress.toLowerCase();
  const stop = new AbortController();
  const verdicts = new Map<string, DeletePart>();
  const loops = new Map<string, Loop>();
  /** Passes in flight: `close` waits for them before the database goes. */
  const active = new Set<Promise<void>>();

  async function intentOf(connector: string): Promise<Intent | null> {
    const [row] = await deps.db.query<{
      retire_id: string;
      state: "open" | "done";
    }>(
      "SELECT retire_id, state FROM legacy_retirements WHERE owner = ? AND connector = ?",
      [owner, connector],
    );
    return row
      ? {
          retireId: row.retire_id,
          state: row.state,
        }
      : null;
  }

  async function pass(
    connector: string,
  ): Promise<{ part: DeletePart; retry: boolean }> {
    const intent = await intentOf(connector);
    if (!intent || intent.state === "done")
      return { part: PART_DONE, retry: false };
    const ports = options.ports();
    if (!ports) return { part: blocked("needs_another_device"), retry: true };
    const check = () => {
      stop.signal.throwIfAborted();
      if (ports.mode() !== "switched" || options.writeReady?.() !== true)
        throw new WriteNotReady();
    };
    try {
      check();
      const part = await createLegacyRetirePipeline(deps, ports).advance(
        intent.retireId,
        check,
        stop.signal,
      );
      return { part, retry: part.state === "pending" };
    } catch (error) {
      if (error instanceof WriteNotReady)
        return { part: PART_PENDING, retry: true };
      throw error;
    }
  }

  function schedule(connector: string, delay: number): void {
    if (stop.signal.aborted) return;
    let loop = loops.get(connector);
    if (!loop) {
      loop = {
        timer: undefined,
        running: false,
        again: false,
        delay: options.retryMs.first,
      };
      loops.set(connector, loop);
    }
    if (loop.running) {
      loop.again = true;
      return;
    }
    clearTimeout(loop.timer);
    const timer = setTimeout(() => {
      const running = run(connector);
      active.add(running);
      void running.finally(() => active.delete(running));
    }, delay);
    // A pending retry must not keep a process alive.
    (timer as { unref?: () => void }).unref?.();
    loop.timer = timer;
  }

  async function run(connector: string): Promise<void> {
    const loop = loops.get(connector)!;
    loop.timer = undefined;
    loop.running = true;
    loop.again = false;
    let retry = false;
    try {
      const outcome = await pass(connector);
      if (outcome.part.state === "done") {
        // `done` is durable: status reads the row. Release the verdict and loop.
        verdicts.delete(connector);
        loops.delete(connector);
        return;
      }
      verdicts.set(connector, outcome.part);
      retry = outcome.retry;
    } catch (error) {
      if (stop.signal.aborted) return;
      deps.logger.warn(
        {
          connector,
          error: error instanceof Error ? error.message : String(error),
        },
        "stream sync: the legacy retirement pass failed",
      );
      retry = true;
    } finally {
      loop.running = false;
    }
    if (stop.signal.aborted) return;
    if (retry) {
      schedule(connector, loop.again ? 0 : loop.delay);
      loop.delay = Math.min(options.retryMs.max, loop.delay * 2);
    } else {
      loop.delay = options.retryMs.first;
      if (loop.again) schedule(connector, 0);
    }
  }

  return {
    async request(connector) {
      const ports = options.ports();
      if (!ports) throw new LegacyRetireUnavailable();
      // Without it the intent cannot name the streams its scopes feed, and the
      // permanent import fence would hold nothing.
      if (!ports.streamsOf)
        throw new LegacyRetireUnavailable(
          "this host cannot name the streams of a legacy scope",
        );
      const mode = ports.mode();
      if (mode !== "switched")
        throw new LegacyRetireNotAdmitted(
          mode === "unknown" ? "unknown" : "unswitched",
        );
      const check = () => {
        stop.signal.throwIfAborted();
        if (ports.mode() !== "switched" || options.writeReady?.() !== true)
          throw new WriteNotReady();
      };
      try {
        await createLegacyRetirePipeline(deps, ports).capture(connector, check);
      } catch (error) {
        throw new LegacyRetireUnavailable(
          error instanceof Error ? error.message : String(error),
        );
      }
      const intent = (await intentOf(connector))!;
      if (intent.state === "open") schedule(connector, 0);
      return { retireId: intent.retireId };
    },
    async status(connector) {
      const intent = await intentOf(connector);
      if (!intent) return null;
      const manifest = await deps.db.query(
        "SELECT retire_id FROM legacy_retire_manifests WHERE retire_id = ?",
        [intent.retireId],
      );
      if (!manifest.length)
        return {
          retireId: intent.retireId,
          legacy: blocked("legacy_manifest_missing"),
        };
      if (intent.state === "done")
        return { retireId: intent.retireId, legacy: PART_DONE };
      // A poll reports the verdict. It starts a worker only where none was
      // started (a process that has not cycled since a restart): it is not a
      // retry, so it neither skips a pending intent's backoff nor restarts a
      // blocked one.
      if (!loops.has(connector)) schedule(connector, 0);
      return {
        retireId: intent.retireId,
        legacy: verdicts.get(connector) ?? PART_PENDING,
      };
    },
    async resume() {
      const open = await deps.db.query<{ connector: string }>(
        "SELECT connector FROM legacy_retirements WHERE owner = ? AND state = 'open'",
        [owner],
      );
      for (const { connector } of open)
        if (!loops.has(connector)) schedule(connector, 0);
    },
    retained: () => new Set([...verdicts.keys(), ...loops.keys()]).size,
    async close() {
      stop.abort();
      for (const loop of loops.values()) clearTimeout(loop.timer);
      loops.clear();
      await Promise.allSettled([...active]);
    },
  };
}
