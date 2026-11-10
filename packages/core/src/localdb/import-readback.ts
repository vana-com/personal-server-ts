import type { LocalSyncDeps } from "./deps.js";
import type {
  ImportSource,
  ImportReadback,
  LegacyCopy,
  ProjectionProof,
  CopyRecords,
} from "./legacy-import-types.js";

/** F.2: adapter uses frozen bindings.ts only; missing/ambiguous/lossy coverage fails closed. */
export interface ImportProjectionReader {
  /** Compare source and database projections for EVERY applicable data-set name, and the exact copy if supplied. Stable canonical JSON and fixed now; never emit bodies. */
  compare(
    source: ImportSource,
    copy: LegacyCopy | null,
  ): Promise<readonly ProjectionProof[]>;
}

/**
 * F.2: page source into SQL TEMP for external sorting, compare counts AND
 * fingerprints of sorted (pk_hash, body_sha256) with committed records in a
 * coherent DB view (caller owns all affected connection queues; never
 * reacquire them), plus every projection. Newer differing DB rows
 * conservatively hold the source. Never read published frames or an overlay.
 * A mismatch, missing ledger, exclusion or uncovered copy cannot pass.
 * Use createImportLedger for decoding; absent/NULL receipt returns receipt:null,
 * pass:false, reason:missing_receipt. Use the same canonical row rules as
 * ImportSource.records and importFingerprint; no second hash/key convention.
 */
export function readBackLegacyImport(
  _deps: LocalSyncDeps,
  _source: ImportSource,
  _projections: ImportProjectionReader,
  _copy: LegacyCopy | null,
): Promise<ImportReadback> {
  throw new Error("PS-3: not built");
}

/**
 * F.2: unchanged bindings/projection API; no connector literals. sourcesFor
 * supplies every peer stream from the same immutable snapshot for joined
 * data-set projections. Missing peers fail closed, never substitute DB rows
 * on the expected side. Callers hold all peer connection queues too.
 */
export function createImportProjectionReader(
  _deps: LocalSyncDeps,
  _projectionTime: string,
  _sourcesFor: (source: ImportSource) => AsyncIterable<ImportSource>,
  /** Required to prove a supplied copy; absent fails copy_unreadable. Compare
   * canonical stored payload with frozen bindings' payload at projectionTime.
   * Reuse storage/canonical-legacy-projection; never treat raw file hash as a
   * projected digest. All peer sources must share the sealed snapshot. */
  _copyRecords?: CopyRecords,
): ImportProjectionReader {
  throw new Error("PS-3: not built");
}
