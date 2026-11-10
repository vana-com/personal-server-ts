import type { SqlDriver, SqlStatement, SqlValue } from "./driver.js";
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

const nonempty = (value: unknown): value is string =>
  typeof value === "string" && value.trim().length > 0;
const nonnegativeInteger = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

function readReceipt(
  row: Record<string, SqlValue> | undefined,
): ImportReceipt | null {
  if (
    !row ||
    !nonempty(row.source) ||
    !nonempty(row.connection_id) ||
    !nonempty(row.stream) ||
    !nonempty(row.revision) ||
    row.generation !== 1 ||
    !nonnegativeInteger(row.highest_seq) ||
    !nonnegativeInteger(row.rows) ||
    (row.rows > 0 && row.highest_seq === 0) ||
    !nonempty(row.fingerprint) ||
    !nonnegativeInteger(row.at) ||
    (row.reason !== null && typeof row.reason !== "string") ||
    (row.state !== "imported" &&
      row.state !== "verified" &&
      row.state !== "retired" &&
      row.state !== "excluded")
  ) {
    // Missing or malformed metadata is unknown, never retirement evidence.
    return null;
  }
  return {
    source: row.source,
    revision: row.revision,
    connectionId: row.connection_id,
    stream: row.stream,
    generation: 1,
    highestSeq: row.highest_seq,
    rows: row.rows,
    fingerprint: row.fingerprint,
    state: row.state,
    reason: row.reason,
    at: row.at,
  };
}

/**
 * F.2: use import_ledger's dedicated receipt columns; reason is free text.
 * Unknown/malformed receipts return null and hold retirement. Statements must
 * run in the caller's final merge transaction, never in a separate commit.
 */
export function createImportLedger(db: SqlDriver): ImportLedger {
  return {
    async get(source, connectionId, stream) {
      const rows = await db.query(
        `SELECT source, connection_id, stream, state, rows, fingerprint, reason,
                at, revision, generation, highest_seq
           FROM import_ledger
          WHERE source = ? AND connection_id = ? AND stream = ?`,
        [source, connectionId, stream],
      );
      return readReceipt(rows[0]);
    },
    statements(receipt) {
      const row = {
        source: receipt.source,
        connection_id: receipt.connectionId,
        stream: receipt.stream,
        state: receipt.state,
        rows: receipt.rows,
        fingerprint: receipt.fingerprint,
        reason: receipt.reason,
        at: receipt.at,
        revision: receipt.revision,
        generation: receipt.generation,
        highest_seq: receipt.highestSeq,
      };
      if (!readReceipt(row)) throw new Error("Invalid import receipt");

      const key = [receipt.source, receipt.connectionId, receipt.stream];
      return [
        {
          // Retain the committed high-water mark when replay adds no changes.
          // A different revision must supply its own sequence, not inherit it.
          sql: `UPDATE import_ledger
                   SET state = ?, rows = ?, fingerprint = ?, reason = ?, at = ?,
                       highest_seq = CASE
                         WHEN revision = ? AND generation = ?
                          AND typeof(highest_seq) = 'integer'
                          AND highest_seq BETWEEN 0 AND 9007199254740991
                         THEN max(highest_seq, ?) ELSE ? END,
                       revision = ?, generation = ?
                 WHERE source = ? AND connection_id = ? AND stream = ?`,
          params: [
            receipt.state,
            receipt.rows,
            receipt.fingerprint,
            receipt.reason,
            receipt.at,
            receipt.revision,
            receipt.generation,
            receipt.highestSeq,
            receipt.highestSeq,
            receipt.revision,
            receipt.generation,
            ...key,
          ],
        },
        {
          // UPDATE + INSERT works on SQLite 3.22 without REPLACE's deletion.
          sql: `INSERT INTO import_ledger
                   (source, connection_id, stream, state, rows, fingerprint,
                    reason, at, revision, generation, highest_seq)
                SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                 WHERE NOT EXISTS (
                   SELECT 1 FROM import_ledger
                    WHERE source = ? AND connection_id = ? AND stream = ?
                 )`,
          params: [
            ...key,
            receipt.state,
            receipt.rows,
            receipt.fingerprint,
            receipt.reason,
            receipt.at,
            receipt.revision,
            receipt.generation,
            receipt.highestSeq,
            ...key,
          ],
        },
      ];
    },
  };
}
