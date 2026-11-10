import type { LocalSyncDeps } from "./deps.js";
import type { ImportLedger } from "./import-ledger.js";
import type { ImportReceipt, ImportSource } from "./legacy-import-types.js";

/** F.2/C.0/F.5: refused/excluded never means the source is safe to erase. */
export type LegacyImportResult =
  | {
      readonly kind: "imported" | "already-imported";
      readonly receipt: ImportReceipt;
    }
  | {
      readonly kind: "refused";
      readonly reason:
        | "connection_deleted"
        | "generation_not_one"
        | "unknown_control"
        | "owner_mismatch"
        | "source_changed"
        | "invalid_record";
    };

/**
 * F.2, C.0, F.5; r5.2 §1.2. Bootstrap before staging, then hold the connection
 * queue (kind end). Recheck local deleted control and delete_intents BEFORE
 * registry refresh, and again inside every merge batch: refresh cannot undo
 * a local delete. Never reconnect. Require known generation 1. Merge with
 * origin import, stamp (0,'seed'), first_o NULL, <=4 MiB per batch. Check
 * per-stream delete floor too. Replays/crash retries add no rows or changes.
 * Receipt and last merge commit atomically; highestSeq includes earlier crash
 * batches (conservatively use the stream change high-water mark). Empty,
 * invalid, changed or excluded sources never prove delivery. No frame codec.
 */
export function importLegacySource(
  _deps: LocalSyncDeps,
  _ledger: ImportLedger,
  _source: ImportSource,
): Promise<LegacyImportResult> {
  throw new Error("PS-3: not built");
}
