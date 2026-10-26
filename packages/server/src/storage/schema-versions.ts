import type Database from "better-sqlite3";

// v17 is a compatibility fence for the converged runtime. Slots 15 and 16
// were also used by the conformance line for other additive columns.
// Older Desktop builds must refuse this database even when PDPP is disabled:
// they lack retained-history blob protection and the current MCP ingress policy.
// The table change remains v15's additive replacement_cursor migration.
export const INDEX_SCHEMA_VERSION = 17;

/** Read both counters before either opener changes the shared database. */
export function assertSupportedSchemaVersions(
  db: Database.Database,
  supportedRecordSchemaVersion: number,
): number {
  const currentVersion = db.pragma("user_version", { simple: true }) as number;
  if (currentVersion > INDEX_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported index.db schema version ${currentVersion}; runtime supports ${INDEX_SCHEMA_VERSION}`,
    );
  }
  const hasRecordsVersion =
    db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_schema_version'",
      )
      .get() !== undefined;
  if (hasRecordsVersion) {
    const records = db
      .prepare("SELECT version FROM pdpp_schema_version WHERE id = 1")
      .get() as { version: number } | undefined;
    if (records && records.version > supportedRecordSchemaVersion) {
      throw new Error(
        `Unsupported index.db PDPP schema version ${records.version}; runtime supports ${supportedRecordSchemaVersion}`,
      );
    }
  }
  return currentVersion;
}
