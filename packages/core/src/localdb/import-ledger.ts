import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import type { LegacyCopy } from "./legacy-import-types.js";
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

/** Localdb-owned journal, separate from source receipts and their free-text
 * reason. An intent binds every copy field, including its raw content hash.
 * The host writes it under its storage lock immediately before unlink. */
export interface LegacyEraseLedger {
  belongsTo(owner: string, network: string): Promise<boolean>;
  record(copy: LegacyCopy): Promise<void>;
  has(copy: LegacyCopy): Promise<boolean>;
  pending(): AsyncIterable<LegacyCopy>;
  finish(copy: LegacyCopy): Promise<void>;
}
export function createLegacyEraseLedger(
  db: SqlDriver,
  now: () => number,
): LegacyEraseLedger {
  const descriptor = (copy: LegacyCopy) =>
    canonicalJson({
      ...copy,
      sources: [...copy.sources].sort((a, b) =>
        canonicalJson(a) < canonicalJson(b)
          ? -1
          : canonicalJson(a) > canonicalJson(b)
            ? 1
            : 0,
      ),
    });
  const valid = (copy: LegacyCopy) =>
    !!copy &&
    nonempty(copy.id) &&
    nonempty(copy.path) &&
    nonempty(copy.contentHash) &&
    /^[0-9a-f]{64}$/.test(copy.contentHash) &&
    nonempty(copy.revision) &&
    typeof copy.dataSet === "string" &&
    Array.isArray(copy.sources) &&
    copy.sources.every(
      (s) =>
        !!s &&
        nonempty(s.source) &&
        nonempty(s.connectionId) &&
        nonempty(s.stream),
    );
  return {
    async belongsTo(owner, network) {
      const [meta] = await db.query<{ owner: string; network: string }>(
        "SELECT owner, network FROM db_meta WHERE id = 1",
      );
      return meta?.owner === owner.toLowerCase() && meta.network === network;
    },
    async record(copy) {
      if (!valid(copy)) throw new Error("invalid_erase_intent");
      const text = descriptor(copy);
      await db.batch([
        {
          sql: "INSERT OR IGNORE INTO legacy_erase_intents VALUES (?, ?, ?)",
          params: [text, text, now()],
        },
      ]);
    },
    async has(copy) {
      if (!valid(copy)) return false;
      const text = descriptor(copy);
      const [row] = await db.query<{ descriptor: string }>(
        "SELECT descriptor FROM legacy_erase_intents WHERE copy_key = ?",
        [text],
      );
      return row?.descriptor === text;
    },
    async *pending() {
      let after = "";
      for (;;) {
        const [row] = await db.query<{ copy_key: string; descriptor: string }>(
          "SELECT copy_key, descriptor FROM legacy_erase_intents WHERE copy_key > ? ORDER BY copy_key LIMIT 1",
          [after],
        );
        if (!row) return;
        let copy: LegacyCopy;
        try {
          copy = JSON.parse(row.descriptor);
          if (!valid(copy) || descriptor(copy) !== row.copy_key)
            throw new Error();
        } catch {
          throw new Error("invalid_erase_intent");
        }
        yield copy;
        after = row.copy_key;
      }
    },
    async finish(copy) {
      await db.batch([
        {
          sql: "DELETE FROM legacy_erase_intents WHERE copy_key = ? AND descriptor = ?",
          params: [descriptor(copy), descriptor(copy)],
        },
      ]);
    },
  };
}
