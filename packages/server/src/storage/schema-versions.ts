import type Database from "better-sqlite3";

// `user_version` stamps are monotonic compatibility fences shared across lines.
// Slots 15 and 16 were used by the conformance and convergence lines for
// different additive columns; their migrations are presence-based.
/** v17: the converged runtime (#475). Older Desktop/conformance builds refuse it. */
export const CONVERGED_INDEX_SCHEMA_VERSION = 17;
/** v18: a root with durable legacy write shutdown enrollment history. */
export const LEGACY_GATE_INDEX_SCHEMA_VERSION = 18;
/** Highest index.db stamp this runtime opens. */
export const INDEX_SCHEMA_VERSION = LEGACY_GATE_INDEX_SCHEMA_VERSION;

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
