import type { SqlDriver } from "./driver.js";

/**
 * What a consumer needs to re-read after the local view moved: the
 * connections whose records, identity, control state or streams changed.
 * Never record data, so a listener cannot learn more from the event than from
 * asking.
 */
export interface ViewChange {
  readonly connectionIds: readonly string[];
}

export type ViewChangeListener = (change: ViewChange) => void;

/** The part a host hands to a consumer. */
export interface ViewChanges {
  /** Listener runs once per change of the local view; returns its unsubscribe. */
  subscribe(listener: ViewChangeListener): () => void;
}

/** A recorder with no subscriber and no database: every call is a no-op. */
export const NO_VIEW_CHANGES: ViewChanges = { subscribe: () => () => {} };

export interface ViewLogger {
  warn(obj: Record<string, unknown>, msg?: string): void;
}

export interface ViewChangeRecorder extends ViewChanges {
  /**
   * Wrap the database the host opened. The host uses the returned driver
   * everywhere it used the raw one. A baseline is read first, and a write
   * waits for it, so the first change after an early `subscribe` is a change
   * against that baseline. Attaching again (the database closed and reopened)
   * starts over with a new baseline.
   */
  attach(db: SqlDriver, logger: ViewLogger): SqlDriver;
  /** Resolves when no check is running or owed. For tests and orderly hosts. */
  settled(): Promise<void>;
}

interface Attachment {
  readonly raw: SqlDriver;
  readonly logger: ViewLogger;
  /** The counters last seen; null when unknown (nobody listened, or a read failed). */
  versions: ReadonlyMap<string, number> | null;
  ready: Promise<void>;
  /** A write committed since the last check. */
  dirty: boolean;
  running: Promise<void> | null;
  closed: boolean;
}

/**
 * One recorder per host. What a screen shows of a connection is kept as one
 * monotonic counter per connection in `view_versions`. Triggers bump it in the
 * same transaction as every record write and every change of the connection or
 * stream rows a screen shows (see the migration in schema.ts). The counter is
 * never pruned, so unlike `record_changes` a compaction cannot erase it, and
 * the order of writes cannot hide a change.
 *
 * `SqlDriver.batch` is the one door every write goes through. The attached
 * driver reads the counters after each committed batch that changed a row,
 * compares them with the last it saw, and tells each listener the connections
 * whose counter moved. Every path is covered by construction, however it
 * commits and whether it fails later, because the check hangs on the commit
 * and not on the operation.
 *
 * - No listener: no reads. A write only marks what was seen as unknown, and the
 *   next subscriber starts from a fresh baseline.
 * - Checks run one at a time and collapse: writes that commit while a check
 *   runs owe one more check, not one each.
 * - Listeners run after the commit, outside any transaction. One that throws
 *   is logged and skipped. One that reads or syncs causes a check only if it
 *   changed something, so it cannot loop on an idle database.
 */
export function createViewChanges(): ViewChangeRecorder {
  const listeners = new Set<ViewChangeListener>();
  let current: Attachment | null = null;

  async function readCounters(
    db: SqlDriver,
  ): Promise<ReadonlyMap<string, number>> {
    const rows = await db.query<{ id: string; v: number }>(
      "SELECT connection_id AS id, version AS v FROM view_versions",
    );
    return new Map(rows.map((row) => [row.id, Number(row.v)]));
  }

  function dispatch(att: Attachment, connectionIds: readonly string[]) {
    const change: ViewChange = Object.freeze({
      connectionIds: Object.freeze([...connectionIds]),
    });
    for (const listener of [...listeners]) {
      try {
        listener(change);
      } catch (error) {
        att.logger.warn(
          { error: String(error) },
          "stream sync: a view change listener threw",
        );
      }
    }
  }

  async function check(att: Attachment): Promise<void> {
    let seen: ReadonlyMap<string, number>;
    try {
      seen = await readCounters(att.raw);
    } catch (error) {
      att.versions = null;
      if (!att.closed)
        att.logger.warn(
          { error: String(error) },
          "stream sync: the view change check failed; the next one starts over",
        );
      return;
    }
    if (att.closed) return;
    const before = att.versions;
    att.versions = seen;
    if (!before) return; // nothing to compare with: this is the baseline
    const changed: string[] = [];
    for (const [id, version] of seen)
      if (before.get(id) !== version) changed.push(id);
    if (changed.length > 0) dispatch(att, changed.sort());
  }

  /** Take a silent baseline; writes wait for it (they await `ready`). */
  function baseline(att: Attachment): void {
    att.ready = att.ready
      .then(() => readCounters(att.raw))
      .then(
        (seen) => {
          if (!att.closed && att.versions === null) att.versions = seen;
        },
        (error: unknown) => {
          if (!att.closed)
            att.logger.warn(
              { error: String(error) },
              "stream sync: the view change baseline failed",
            );
        },
      );
  }

  function pump(att: Attachment): void {
    if (att.running || att.closed) return;
    att.running = (async () => {
      try {
        await att.ready;
        while (att.dirty && !att.closed) {
          att.dirty = false;
          await check(att);
        }
      } finally {
        att.running = null;
      }
    })();
  }

  function committed(att: Attachment): void {
    if (att.closed) return;
    if (listeners.size === 0) {
      att.versions = null; // unknown from here: no one is reading
      return;
    }
    att.dirty = true;
    pump(att);
  }

  return {
    subscribe(listener) {
      listeners.add(listener);
      const att = current;
      if (att && !att.closed && att.versions === null) baseline(att);
      return () => {
        listeners.delete(listener);
      };
    },

    attach(raw, logger) {
      if (current) current.closed = true;
      const att: Attachment = {
        raw,
        logger,
        versions: null,
        ready: Promise.resolve(),
        dirty: false,
        running: null,
        closed: false,
      };
      current = att;
      baseline(att);
      const batch: SqlDriver["batch"] = async (statements) => {
        await att.ready;
        const result = await raw.batch(statements);
        if (result.changes.some((n) => n > 0)) committed(att);
        return result;
      };
      const close = async () => {
        att.closed = true;
        att.versions = null;
        if (current === att) current = null;
        await att.running?.catch(() => {});
        return raw.close();
      };
      return new Proxy(raw, {
        get(target, prop) {
          if (prop === "batch") return batch;
          if (prop === "close") return close;
          const value = Reflect.get(target, prop, target) as unknown;
          return typeof value === "function"
            ? (value as (...a: unknown[]) => unknown).bind(target)
            : value;
        },
      });
    },

    async settled() {
      for (;;) {
        const att = current;
        if (!att) return;
        await att.ready;
        const running = att.running;
        if (!running) return;
        await running;
      }
    },
  };
}
