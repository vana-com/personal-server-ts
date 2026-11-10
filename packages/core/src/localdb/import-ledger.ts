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

/** F.2: use existing import_ledger only; reason = JSON {v:1, revision, generation, highestSeq, detail}. Unknown/malformed metadata never authorizes retire. */
export function createImportLedger(_db: SqlDriver): ImportLedger {
  throw new Error("PS-3: not built");
}
