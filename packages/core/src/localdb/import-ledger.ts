import type { SqlDriver, SqlStatement } from "./driver.js";
import type { ImportReceipt } from "./legacy-import-types.js";

/** F.2: receipt key is (source revision, connection, stream); source encodes revision. */
export interface ImportLedger {
  get(
    source: string,
    connectionId: string,
    stream: string,
  ): Promise<ImportReceipt | null>;
  /** Must share the import merge transaction; returns statements, never commits separately. */
  statements(receipt: ImportReceipt): readonly SqlStatement[];
}

/** Migration 2 nullable receipt columns; reason is free text. NULL/malformed metadata holds. */
export function createImportLedger(_db: SqlDriver): ImportLedger {
  throw new Error("PS-3: not built");
}
