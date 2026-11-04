import type { Database } from "better-sqlite3";
import {
  exclusiveScopeStreams,
  scopeMethods,
  scopeHasSharedStreams,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

/** Expected refusal: ownership is unknown, so records must remain held. */
export class UnboundScopeStreamsError extends Error {
  constructor(
    readonly scope: string,
    readonly instance: string,
    readonly stream: string,
  ) {
    super("Cannot establish the owner of a stream");
    this.name = "UnboundScopeStreamsError";
  }
}

/** An unbound row cannot safely be assigned to a scope by stream name alone. */
export function assertScopeStreamsBound(db: Database, scope: string): void {
  const streams = [
    ...new Set([...exclusiveScopeStreams(scope).values()].flat()),
  ];
  if (!streams.length) return;
  for (const table of [
    "pdpp_records",
    "pdpp_record_changes",
    "pdpp_stream_completion",
    "pdpp_record_arrival",
  ]) {
    const row = db
      .prepare(
        `SELECT r.instance, r.stream FROM ${table} r LEFT JOIN pdpp_instance_binding b ON b.instance = r.instance WHERE (b.instance IS NULL OR b.method IS NULL) AND NOT EXISTS (SELECT 1 FROM pdpp_claude_transition c WHERE c.archive_instance = r.instance) AND NOT EXISTS (SELECT 1 FROM pdpp_strava_transition t WHERE t.archive_instance = r.instance) AND r.stream IN (${streams.map(() => "?").join(",")}) LIMIT 1`,
      )
      .get(...streams) as { instance: string; stream: string } | undefined;
    if (row)
      throw new UnboundScopeStreamsError(scope, row.instance, row.stream);
  }
}

/** Called only inside the full reset/delete transaction, after every row is erased. */
export function markEmptySharedScopes(
  db: Database,
  replication: boolean,
): void {
  if (
    replication ||
    !db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE name = 'vana_scope_deletion_history'",
      )
      .get()
  )
    return;
  const columns = db.pragma("table_info(vana_scope_deletion_history)") as {
    name: string;
  }[];
  if (!columns.some(({ name }) => name === "shared_fresh")) return;
  const entries = db
    .prepare(
      "SELECT owner_address, scope FROM vana_scope_deletion_history WHERE erase_applied = 1 AND erase_applied_version IS tombstone_version AND shared_fresh = 0",
    )
    .all() as { owner_address: string; scope: string }[];
  for (const { owner_address, scope } of entries) {
    if (!scopeHasSharedStreams(scope)) continue;
    let held = false;
    for (const [method, streams] of scopeMethods(scope)) {
      if (!streams.length) continue;
      for (const table of [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_stream_completion",
        "pdpp_record_arrival",
      ]) {
        if (
          db
            .prepare(
              `SELECT 1 FROM ${table} r LEFT JOIN pdpp_instance_binding b ON b.instance = r.instance WHERE r.stream IN (${streams.map(() => "?").join(",")}) AND (b.method = ? OR b.method IS NULL OR EXISTS (SELECT 1 FROM pdpp_claude_transition c WHERE c.archive_instance = r.instance) OR EXISTS (SELECT 1 FROM pdpp_strava_transition t WHERE t.archive_instance = r.instance)) LIMIT 1`,
            )
            .get(...streams, method)
        ) {
          held = true;
          break;
        }
      }
      if (held) break;
    }
    if (!held)
      db.prepare(
        "UPDATE vana_scope_deletion_history SET shared_fresh = 1 WHERE owner_address = ? AND scope = ? AND erase_applied = 1 AND erase_applied_version IS tombstone_version",
      ).run(owner_address, scope);
  }
}
