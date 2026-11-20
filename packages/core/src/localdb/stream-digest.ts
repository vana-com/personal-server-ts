import type { SqlReader } from "./driver.js";
import { importFingerprint } from "./import-fingerprint.js";
import type { ImportFingerprint } from "./legacy-import-types.js";

/** Rows read per query. A page is small enough to hold in memory on a phone. */
export const STREAM_DIGEST_PAGE_ROWS = 2048;

/**
 * Count and content digest of one stream's live records, for comparing two
 * devices that should hold the same records.
 *
 * The set is every row of `records` for the connection and stream: a deleted
 * record has no row (a delete removes it; a local tombstone lives in
 * `record_tombstones` and `log_tombstones`, which are not read), so a delete
 * and a record never held leave the same digest.
 *
 * Each row contributes `(pk_hash, body_sha256)`. The stamp, the first-seen time
 * and the order of arrival are device facts and do not enter it, so two
 * databases that hold the same live records with the same bodies report the
 * same digest, whatever order or batches the records arrived in. A different
 * body, a missing record or an extra record changes it.
 *
 * It is the import fingerprint (`importFingerprint`): SHA-256 over the rows in
 * binary `pk_hash` order, so the digest is of the set and not of a history. A
 * set hash that sums per-row hashes would not need the order, but it costs a
 * hash call for every row; the sorted fold costs one streaming update per row
 * and the same read.
 *
 * Read cost: one keyset-paged scan of the stream's rows in `pk_hash` order,
 * linear in the live rows, with a row read per record (`body_sha256` sits
 * after `body`, so a record with an overflowing body reads its overflow pages
 * too). It reads the read connection and writes nothing.
 *
 * Throws `invalid_import_fingerprint_rows` when a stored hash is not 64
 * lowercase hex characters.
 */
export async function streamDigest(
  reads: SqlReader,
  connectionId: string,
  stream: string,
  pageRows: number = STREAM_DIGEST_PAGE_ROWS,
): Promise<ImportFingerprint> {
  async function* rows() {
    let after: string | null = null;
    for (;;) {
      const page: { pk_hash: string; body_sha256: string }[] =
        await reads.query(
          `SELECT pk_hash, body_sha256 FROM records
            WHERE connection_id = ? AND stream = ?${after === null ? "" : " AND pk_hash > ?"}
            ORDER BY pk_hash LIMIT ?`,
          after === null
            ? [connectionId, stream, pageRows]
            : [connectionId, stream, after, pageRows],
        );
      yield* page;
      if (page.length < pageRows) return;
      after = page[page.length - 1]!.pk_hash;
    }
  }
  return importFingerprint(rows());
}
