import type { Database } from "better-sqlite3";
import { exclusiveScopeStreams } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

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
      throw Object.assign(new Error("Cannot establish the owner of a stream"), {
        scope,
        ...row,
      });
  }
}
