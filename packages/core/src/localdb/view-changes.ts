import type { LocalSyncDeps } from "./deps.js";

/**
 * What a consumer needs to re-read after the local view moved: the
 * connections whose rows, stream set or control state changed. Never record
 * data, so a listener cannot learn more from the event than from asking.
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

/** What the modules of one database call (`LocalSyncDeps.viewChanges`). */
export interface ViewChangeRecorder extends ViewChanges {
  /**
   * Run one operation. When it settles, success or throw, compare the view
   * with what the last settle saw and emit once if it differs. A throw from
   * `work` is rethrown unchanged after its committed part is announced.
   */
  observe<T>(deps: ViewDeps, work: () => Promise<T>): Promise<T>;
  /** Compare now. For commits that run outside an observed operation. */
  settle(deps: ViewDeps): Promise<void>;
  /**
   * Tell the recorder which database it watches. A subscriber that arrives
   * later then gets its baseline at once, so a commit made before any
   * operation of this recorder is still announced.
   */
  bind(deps: ViewDeps): void;
}

type ViewDeps = Pick<LocalSyncDeps, "db" | "logger">;

/** A recorder with no subscriber and no database: every call is a no-op. */
export const NO_VIEW_CHANGES: ViewChanges = { subscribe: () => () => {} };

interface Mark {
  readonly seq: number;
  /** One string per connection; a change of it is a change of that connection. */
  readonly state: ReadonlyMap<string, string>;
}

/**
 * One recorder per open database. The view a reader sees is the records, and
 * for each connection that has streams, its identity and control state and
 * each stream's presence, completeness and delete version. `record_changes`
 * already logs every record insert, update and removal of every origin
 * (local, import, remote, refresh, purge) with an ever-rising `seq`, so a rise
 * of `seq` since the last settle is exactly "a record changed", whichever
 * module committed it. The other parts are small tables read whole. Publish
 * bookkeeping (head versions, watermarks, checkpoints) is not part of the
 * view and is left out: a cycle that only publishes emits nothing.
 *
 * Settles run one at a time against one shared mark, so two operations that
 * overlap announce each change once, in whichever settles first.
 */
export function createViewChanges(): ViewChangeRecorder {
  const listeners = new Set<ViewChangeListener>();
  let mark: Mark | null = null;
  let markedDb: unknown;
  let bound: ViewDeps | null = null;
  let chain: Promise<unknown> = Promise.resolve();

  const serial = <T>(step: () => Promise<T>): Promise<T> => {
    const next = chain.then(step, step);
    chain = next.catch(() => {});
    return next;
  };

  async function read(deps: ViewDeps): Promise<Mark> {
    const [seq] = await deps.db.query<{ seq: number }>(
      "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='record_changes'),0) AS seq",
    );
    const connections = await deps.db.query<{ id: string; s: string }>(
      "SELECT connection_id AS id, generation||'|'||control_state||'|'||control_version||'|'||COALESCE(deleted_at,'') AS s FROM connections",
    );
    const streams = await deps.db.query<{ id: string; s: string }>(
      "SELECT connection_id AS id, stream||':'||complete||':'||last_delete_version AS s FROM stream_state ORDER BY connection_id, stream",
    );
    // A connection with no stream is not in anyone's view yet (the cycle's
    // bootstrap lists such rows), so only connections with streams count.
    const identity = new Map(connections.map((row) => [row.id, row.s]));
    const state = new Map<string, string>();
    for (const row of streams)
      state.set(
        row.id,
        `${state.get(row.id) ?? identity.get(row.id) ?? ""}#${row.s}`,
      );
    return { seq: Number(seq?.seq ?? 0), state };
  }

  async function changedSince(deps: ViewDeps, before: Mark, after: Mark) {
    const ids = new Set<string>();
    if (after.seq !== before.seq) {
      const rows = await deps.db.query<{ id: string }>(
        "SELECT DISTINCT connection_id AS id FROM record_changes WHERE seq>? AND seq<=?",
        [before.seq, after.seq],
      );
      for (const row of rows) ids.add(row.id);
    }
    for (const [id, s] of after.state)
      if (before.state.get(id) !== s) ids.add(id);
    for (const id of before.state.keys()) if (!after.state.has(id)) ids.add(id);
    return [...ids].sort();
  }

  function emit(connectionIds: readonly string[], deps: ViewDeps) {
    const change: ViewChange = Object.freeze({
      connectionIds: Object.freeze([...connectionIds]),
    });
    for (const listener of [...listeners]) {
      try {
        listener(change);
      } catch (error) {
        deps.logger.warn(
          { error: String(error) },
          "stream sync: a view change listener threw",
        );
      }
    }
  }

  async function settleNow(deps: ViewDeps): Promise<void> {
    if (listeners.size === 0) {
      mark = null; // nobody is watching: the next observed operation starts a mark
      return;
    }
    try {
      const after = await read(deps);
      const before = markedDb === deps.db ? mark : null;
      mark = after;
      markedDb = deps.db;
      if (!before) return; // first look: nothing to compare with
      const changed = await changedSince(deps, before, after);
      if (changed.length > 0) emit(changed, deps);
    } catch (error) {
      mark = null;
      deps.logger.warn(
        { error: String(error) },
        "stream sync: the view change check failed; the next one starts over",
      );
    }
  }

  async function begin(deps: ViewDeps): Promise<void> {
    if (listeners.size === 0) return;
    if (mark && markedDb === deps.db) return;
    try {
      mark = await read(deps);
      markedDb = deps.db;
    } catch (error) {
      mark = null;
      deps.logger.warn(
        { error: String(error) },
        "stream sync: the view change baseline failed",
      );
    }
  }

  return {
    bind(deps) {
      bound = deps;
    },
    subscribe(listener) {
      listeners.add(listener);
      const watched = bound;
      if (watched) void serial(() => begin(watched));
      return () => {
        listeners.delete(listener);
      };
    },
    async observe(deps, work) {
      await serial(() => begin(deps));
      try {
        return await work();
      } finally {
        await serial(() => settleNow(deps));
      }
    },
    settle: (deps) => serial(() => settleNow(deps)),
  };
}
