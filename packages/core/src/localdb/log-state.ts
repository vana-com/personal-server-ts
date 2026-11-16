// The log position a device holds for a connection (`log_state`): where the
// reader of the stream-sync log (log-apply.ts) stands, and what it applied.

import type {
  SegmentRef,
  SnapshotPointer,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import type { SqlStatement } from "./driver.js";

export interface LogState {
  readonly position: number;
  readonly base: number;
  /** Refs of positions base+1..position: the list the next segment carries. */
  readonly refs: readonly SegmentRef[];
  /** The snapshot the log rests on; `null` before its first compaction. */
  readonly snapshot: SnapshotPointer | null;
}

/**
 * The registry's log is not a continuation of the one this device applied: it
 * is behind this device, or names another segment at a position this device
 * holds. A real rebaseline (rows, tombstones and checkpoints rebuilt from the
 * log, the local overlay kept apart) is not built; until it is, the device
 * refuses to read on top of state the log no longer vouches for.
 */
export class LogDivergedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LogDivergedError";
  }
}

const NO_LOG: LogState = { position: 0, base: 0, refs: [], snapshot: null };

export async function readLogState(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<LogState> {
  const [row] = await deps.db.query<{
    position: number;
    base: number;
    refs: string;
    snapshot: string | null;
  }>(
    "SELECT position, base, refs, snapshot FROM log_state WHERE connection_id = ?",
    [connectionId],
  );
  return row
    ? {
        position: row.position,
        base: row.base,
        refs: JSON.parse(row.refs) as SegmentRef[],
        snapshot: row.snapshot
          ? (JSON.parse(row.snapshot) as SnapshotPointer)
          : null,
      }
    : NO_LOG;
}

export function writeLogState(
  connectionId: string,
  state: LogState,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO log_state (connection_id, position, base, refs, snapshot)
          VALUES (?, ?, ?, ?, ?)`,
    params: [
      connectionId,
      state.position,
      state.base,
      JSON.stringify(state.refs),
      state.snapshot ? JSON.stringify(state.snapshot) : null,
    ],
  };
}

/**
 * The position a key-ordered first load (log-keyed.ts) means to publish, kept
 * (`log_keyed_pending`) from the commit that first writes its rows until the
 * commit that publishes. Those rows are in `records` and `log_tombstones`
 * before the cursor moves, so a later load must name a prefix that holds
 * every one of them: `null` when no key-ordered load is unfinished.
 */
export async function readKeyedPending(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
): Promise<LogState | null> {
  const [row] = await deps.db.query<{
    position: number;
    base: number;
    refs: string;
  }>(
    "SELECT position, base, refs FROM log_keyed_pending WHERE connection_id = ?",
    [connectionId],
  );
  return row
    ? {
        position: row.position,
        base: row.base,
        refs: JSON.parse(row.refs) as SegmentRef[],
        snapshot: null,
      }
    : null;
}

export function writeKeyedPending(
  connectionId: string,
  target: LogState,
): SqlStatement {
  return {
    sql: `INSERT OR REPLACE INTO log_keyed_pending (connection_id, position, base, refs)
          VALUES (?, ?, ?, ?)`,
    params: [
      connectionId,
      target.position,
      target.base,
      JSON.stringify(target.refs),
    ],
  };
}

export function clearKeyedPending(connectionId: string): SqlStatement {
  return {
    sql: "DELETE FROM log_keyed_pending WHERE connection_id = ?",
    params: [connectionId],
  };
}
