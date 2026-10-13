import type { Database } from "better-sqlite3";
import type { LegacyScopeViewStore } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

/**
 * The SQLite record store plus the two registry reads the legacy scope view
 * needs. The view calls read methods only; the added ones are SELECTs on the
 * store's own binding table.
 */
export function createLegacyScopeViewStore(
  db: Database,
  store: ReturnType<typeof createSqliteRecordStore>,
): LegacyScopeViewStore {
  // `listConnections` hides deleted connections; a deleted one is still
  // evidence that the source's data lives in the registry.
  const instancesOfSource = db.prepare(
    "SELECT instance FROM pdpp_instance_binding WHERE source_id = ? ORDER BY instance",
  );
  // The store is a plain object of closures; spreading it keeps every read
  // method the canonical reader needs without listing them here.
  return {
    ...store,
    listSourceBindings: (sourceId) =>
      (instancesOfSource.all(sourceId) as { instance: string }[]).map((row) =>
        store.getInstanceBinding(row.instance),
      ),
    hasRecordHistory: (instance) =>
      store.getInstanceBinding(instance).empty === false,
  };
}
