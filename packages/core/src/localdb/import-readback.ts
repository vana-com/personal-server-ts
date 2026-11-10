import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { importFingerprint } from "./import-fingerprint.js";
import { createImportLedger } from "./import-ledger.js";
import {
  stageImportSnapshot,
  snapshotRows,
  clearImportSnapshot,
  canonicalImportRow,
} from "./import-snapshot.js";
import type { LocalSyncDeps } from "./deps.js";
import type {
  ImportSource,
  ImportReadback,
  ImportFingerprint,
} from "./legacy-import-types.js";

/** Check the imported seed, not equality with an obsolete legacy projection.
 * Valid current database values are authoritative even when their bodies differ.
 * Failures are diagnostic bug reports; retirement never depends on this result.
 * Caller owns the connection queue. No durable status or data writes here. */
export async function readBackLegacyImport(
  deps: LocalSyncDeps,
  source: ImportSource,
): Promise<ImportReadback> {
  const receipt = await createImportLedger(deps.db).get(
    source.source,
    source.target.connectionId,
    source.target.stream,
  );
  let actual: ImportFingerprint = await importFingerprint(
    (async function* () {})(),
  );
  const result = (reason: string | null): ImportReadback => ({
    receipt,
    actual,
    pass: reason === null,
    reason,
  });
  if (!receipt) return result("missing_receipt");
  const [meta] = await deps.db.query<{ owner: string; network: string }>(
    "SELECT owner, network FROM db_meta WHERE id = 1",
  );
  if (
    meta?.owner !== source.owner.toLowerCase() ||
    meta.owner !== deps.ownerAddress.toLowerCase() ||
    meta.network !== source.network
  )
    return result("owner_mismatch");
  if (receipt.revision !== source.revision) return result("source_changed");
  const op = deps.newOp();
  try {
    const expected = await stageImportSnapshot(deps.db, source, op);
    if (
      expected.rows !== receipt.rows ||
      expected.fingerprint !== receipt.fingerprint
    )
      return result("source_changed");
    let mismatch = false;
    actual = await importFingerprint(
      (async function* () {
        for await (const expectedRow of snapshotRows(deps.db, op)) {
          const [row] = await deps.db.query<{
            pk_hash: string;
            record_key: string;
            body: string;
            body_sha256: string;
          }>(
            "SELECT pk_hash, record_key, body, body_sha256 FROM records WHERE connection_id = ? AND stream = ? AND pk_hash = ?",
            [
              source.target.connectionId,
              source.target.stream,
              expectedRow.pk_hash,
            ],
          );
          if (!row) {
            mismatch = true;
            continue;
          }
          const computed = await canonicalImportRow(
            JSON.parse(row.body),
            source.target.primaryKey,
          );
          if (
            canonicalJson(computed) !==
            canonicalJson({
              pk_hash: row.pk_hash,
              record_key: row.record_key,
              body: row.body,
              body_sha256: row.body_sha256,
            })
          )
            throw new Error("stored_row_invalid");
          yield row;
        }
      })(),
    );
    return result(mismatch ? "record_mismatch" : null);
  } catch (error) {
    return result(
      error instanceof Error &&
        ["source_changed", "invalid_record", "stored_row_invalid"].includes(
          error.message,
        )
        ? error.message
        : "readback_unavailable",
    );
  } finally {
    await clearImportSnapshot(deps.db, op);
  }
}
