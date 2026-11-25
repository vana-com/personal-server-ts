// A standalone retirement of a connector's legacy (pre-switch) copy, apart
// from the connector's delete.
//
// A connector's delete retires the legacy copy as its second stage, behind the
// connection's control tombstone, and it ends the connection. After a delete
// that was never sent and a reconnect, the legacy scopes are still listed and
// the connection is live: a connector delete would end it too. This is the
// legacy stage alone.
//
// It persists its own intent (`legacy_retirements`), not `delete_intents`:
//   - the intent names the connector's bound legacy scopes and the gateway
//     head of each, as the request read them. A pass retires those heads and
//     no others; a head that is not the pinned one blocks the scope
//     (`legacy_head_changed`) and the intent is never widened;
//   - while it is open, the connector's legacy import is refused
//     (`importFence`, and the merge batch's own guard), so an import cannot
//     bring the copy back into the stream while it is retired. Once `done`,
//     an import of a stream a bound scope feeds stays refused for good
//     (`legacy_retired`): a batch read before the retirement finished would
//     otherwise merge the records it deleted. Other streams are not held. Nothing else
//     reads it: the connection's control row, stream heads, records, sync and
//     publish paths do not see it, and no pass sends a connector-wide fence,
//     purges local state or erases a log;
//   - a repeat or a restart resumes the same intent id and the same scopes.
//
// Each scope goes through the connector delete's own worker
// (`retireLegacyScope`): the tombstone is fenced to the pinned head, an
// already-deleted answer is read again, and a scope is `done` only after
// storage's idempotent delete answered for every slot of the gateway's kept
// history. The intent is `done` only when every scope is.
import {
  retireLegacyScope,
  worst,
  type LegacyDeletePorts,
  type LegacyHead,
  type LegacyMemory,
} from "./legacy-delete.js";
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
  /** Connectors that still hold in-memory state (a pass, a verdict, a history). */
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
  readonly scopes: readonly {
    scope: string;
    head: LegacyHead;
    /** The streams the scope feeds: what a later import is held back by. */
    streams?: readonly string[];
  }[];
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

/**
 * The ports a pass hands the stage: each host call first reads the gate, so a
 * hold that starts mid-pass stops the next call, whatever the caller was doing.
 */
function gatedPorts(
  ports: LegacyDeletePorts,
  ready: () => boolean,
): LegacyDeletePorts {
  const gate =
    <A extends unknown[], R>(call: (...args: A) => R) =>
    (...args: A): R => {
      if (!ready()) throw new WriteNotReady();
      return call(...args);
    };
  return {
    ...ports,
    head: gate(ports.head.bind(ports)),
    // The delete worker reads the live gate again before each destructive step
    // of its own: the tombstone post, the queue write and the local erase.
    retire: (scope, fence, options) => {
      if (!ready()) throw new WriteNotReady();
      return ports.retire(scope, fence, {
        pinned: options?.pinned ?? false,
        writeReady: ready,
      });
    },
    pendingBlobs: gate(ports.pendingBlobs),
    finality: {
      tombstoneState: gate(ports.finality.tombstoneState.bind(ports.finality)),
    },
    versions: {
      ...ports.versions,
      list: gate(ports.versions.list.bind(ports.versions)),
    },
    objects: {
      deleteBlobVersions: gate(
        ports.objects.deleteBlobVersions.bind(ports.objects),
      ),
    },
  };
}

export function createLegacyRetirer(
  deps: LegacyRetirerDeps,
  options: {
    /** Read when a pass runs; `undefined`: this host cannot retire a legacy copy. */
    readonly ports: () => LegacyDeletePorts | undefined;
    readonly retryMs: { readonly first: number; readonly max: number };
    /**
     * Host write authority, read before every host call of a pass: while it
     * answers false (a registration that is held) a pass sends no tombstone,
     * queues no row and erases no blob. Absent: always ready.
     */
    readonly writeReady?: () => boolean;
  },
): LegacyRetirer {
  const owner = deps.ownerAddress.toLowerCase();
  const stop = new AbortController();
  const memories = new Map<string, LegacyMemory>();
  const verdicts = new Map<string, DeletePart>();
  const loops = new Map<string, Loop>();
  /** Passes in flight: `close` waits for them before the database goes. */
  const active = new Set<Promise<void>>();

  async function intentOf(connector: string): Promise<Intent | null> {
    const [row] = await deps.db.query<{
      retire_id: string;
      state: "open" | "done";
      scopes: string;
    }>(
      "SELECT retire_id, state, scopes FROM legacy_retirements WHERE owner = ? AND connector = ?",
      [owner, connector],
    );
    return row
      ? {
          retireId: row.retire_id,
          state: row.state,
          scopes: JSON.parse(row.scopes) as Intent["scopes"],
        }
      : null;
  }

  function memoryOf(connector: string): LegacyMemory {
    let memory = memories.get(connector);
    if (!memory) {
      memory = {
        refused: new Map(),
        erased: new Map(),
        localCleaned: new Set(),
      };
      memories.set(connector, memory);
    }
    return memory;
  }

  /** One pass over the pinned scopes. `retry`: a later pass can change the verdict. */
  async function pass(
    connector: string,
  ): Promise<{ part: DeletePart; retry: boolean }> {
    const intent = await intentOf(connector);
    if (!intent || intent.state === "done")
      return { part: PART_DONE, retry: false };
    const ports = options.ports();
    if (!ports) return { part: blocked("needs_another_device"), retry: true };
    // Nothing is sent before the switch, or while the mode is unknown.
    if (ports.mode() !== "switched") return { part: PART_PENDING, retry: true };
    const ready = () =>
      ports.mode() === "switched" && (options.writeReady?.() ?? true);
    if (!ready()) return { part: PART_PENDING, retry: true };
    const guarded = gatedPorts(ports, ready);
    const memory = memoryOf(connector);
    let part: DeletePart = PART_DONE;
    let retry = false;
    for (const { scope, head } of intent.scopes) {
      stop.signal.throwIfAborted();
      // One scope's failed read says nothing of the others.
      const outcome = await retireLegacyScope(
        { memory },
        guarded,
        scope,
        head,
        stop.signal,
      ).catch((error: unknown) => {
        if (stop.signal.aborted) throw error;
        if (error instanceof WriteNotReady)
          return { part: PART_PENDING, retry: true };
        deps.logger.warn(
          {
            connector,
            scope,
            error: error instanceof Error ? error.message : String(error),
          },
          "stream sync: a pinned legacy scope could not be retired yet",
        );
        return { part: PART_PENDING, retry: true };
      });
      part = worst(part, outcome.part);
      retry ||= outcome.retry;
    }
    // A pass that outlived `close` writes no verdict: nothing it learned
    // before the abort says the account or the heads are still what it read.
    if (part.state === "done") {
      stop.signal.throwIfAborted();
      // The mode was read at the pass's start; a host call has run since.
      if (!ready()) return { part: PART_PENDING, retry: true };
      await deps.db.batch([
        {
          sql: "UPDATE legacy_retirements SET state = 'done' WHERE owner = ? AND connector = ? AND retire_id = ?",
          params: [owner, connector, intent.retireId],
        },
      ]);
    }
    return { part, retry: retry || part.state === "pending" };
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
        // `done` is durable: status reads the row, and nothing else needs the
        // erasure history, the verdict or the loop.
        memories.delete(connector);
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
      let intent = await intentOf(connector);
      if (!intent) {
        // Pin the heads now: the intent retires these and no others.
        const scopes: Intent["scopes"][number][] = [];
        try {
          for (const scope of ports.scopesOf(connector))
            scopes.push({
              scope,
              head: await ports.head(scope),
              streams: [...ports.streamsOf(connector, scope)],
            });
        } catch (error) {
          throw new LegacyRetireUnavailable(
            `a legacy head could not be read: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
        // Another request may have won the insert: the first intent stands.
        await deps.db.batch([
          {
            sql: "INSERT OR IGNORE INTO legacy_retirements (owner, connector, retire_id, state, scopes, created_at) VALUES (?, ?, ?, 'open', ?, ?)",
            params: [
              owner,
              connector,
              deps.newOp(),
              JSON.stringify(scopes),
              deps.now(),
            ],
          },
        ]);
        intent = (await intentOf(connector))!;
      }
      if (intent.state === "open") schedule(connector, 0);
      return { retireId: intent.retireId };
    },
    async status(connector) {
      const intent = await intentOf(connector);
      if (!intent) return null;
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
    retained: () =>
      new Set([...memories.keys(), ...verdicts.keys(), ...loops.keys()]).size,
    async close() {
      stop.abort();
      for (const loop of loops.values()) clearTimeout(loop.timer);
      loops.clear();
      await Promise.allSettled([...active]);
    },
  };
}
