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
