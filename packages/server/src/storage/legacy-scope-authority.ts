import type { Database } from "better-sqlite3";
import type { LegacyScopeAuthority } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

/**
 * Registry facts for the legacy scope view, read with plain SELECTs on the
 * record store's tables. It does not open the record store: opening it
 * migrates and sweeps, and this must also answer when PDPP is disabled. A
 * table that was never created holds no connection and no evidence.
 *
 * It shares the record store's database connection, so its reads inside
 * the store's `readSnapshot` see that same snapshot.
 */
export function createLegacyScopeAuthority(db: Database): LegacyScopeAuthority {
  const hasTable = (name: string) =>
    db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(name) !== undefined;

  return {
    listMethodConnections(methods) {
      if (methods.length === 0 || !hasTable("pdpp_instance_binding")) {
        return [];
      }
      // `listConnections` hides deleted connections; a deleted one is still
      // evidence that the scope's data lived in the registry.
      const rows = db
        .prepare(
          `SELECT * FROM pdpp_instance_binding
            WHERE method IN (${methods.map(() => "?").join(", ")})
            ORDER BY instance`,
        )
        .all(...methods) as {
        instance: string;
        source_id?: string | null;
        method: string | null;
        deleted_at?: string | null;
        generation: number;
        reset_clock: number;
      }[];
      return rows.map((row) => ({
        instance: row.instance,
        sourceId: row.source_id ?? null,
        method: row.method,
        deletedAt: row.deleted_at ?? null,
        generation: row.generation,
        resetClock: row.reset_clock,
      }));
    },

    hasHeldData(instance, streams) {
      if (streams?.length === 0) return false;
      const streamFilter = streams
        ? ` AND stream IN (${streams.map(() => "?").join(", ")})`
        : "";
      const tables = [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_stream_completion",
      ].filter(hasTable);
      return tables.some(
        (table) =>
          db
            .prepare(
              `SELECT 1 FROM ${table} WHERE instance = ?${streamFilter} LIMIT 1`,
            )
            .get(instance, ...(streams ?? [])) !== undefined,
      );
    },

    readSnapshot: <T>(read: () => T): T => db.transaction(read).deferred(),
  };
}
