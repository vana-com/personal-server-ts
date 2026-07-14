import type Database from "better-sqlite3";
import type {
  StateMigration,
  StateMigrationContext,
  StateMigrationResult,
} from "./state-migrations.js";

/**
 * BUI-715 follow-up — NON-DESTRUCTIVE detection of the stuck version-ledger
 * fingerprint on the desktop Personal Server.
 *
 * Background. The local `version` in `data_files` is a per-snapshot counter
 * (`findLatestVersionByScope() + 1`, bumped on every connector run). The
 * gateway's `currentVersion` is a per-content-change counter. When the gateway
 * falls behind the local counter (a moksha / DataRegistry reset, or a pre-#755
 * network switch that shared one state folder across mainnet/testnet), repeated
 * re-snapshots pile up several unsynced rows for the same scope that thrash on
 * `409 Gap in version sequence`.
 *
 * Why detect, not repair. The runtime already recovers this non-destructively:
 * the upload worker's 409 handling (BUI-540 adopt / BUI-715 rebase, #158/#202)
 * rebases distinct content onto the gateway's next-valid version and ADOPTS
 * identical content (`record.dataHash === dataHash`) rather than minting a new
 * version — so duplicate pending rows dedupe on the next sync without deleting
 * anything. A boot-time `DELETE` cannot be made safe offline: `data_files`
 * carries no content hash, so "duplicate re-snapshot" (safe to drop) is
 * indistinguishable from "distinct history" (must keep). Worse, the schema
 * migration adds `data_point_id` as a NULL column, so on the first boot after a
 * schema upgrade a legacy user's fully-synced rows momentarily look pending.
 * This migration therefore only OBSERVES and records prevalence; recovery is
 * left to the runtime.
 *
 * Caveat on the count. Because `data_point_id IS NULL` also matches rows freshly
 * backfilled by the schema migration, the reported pending-row count is an upper
 * bound on the first boot after a schema upgrade. It is telemetry, not a gate.
 */
export const DETECT_STUCK_VERSION_LEDGER_ID =
  "2026-07-14-detect-stuck-version-ledger";

export interface StuckScopeReport {
  scope: string;
  pendingRows: number;
}

interface StuckScopeRow {
  scope: string;
  pending_rows: number;
}

/**
 * Scopes with more than one row still pending upload (`data_point_id IS NULL`) —
 * the accumulation fingerprint. One pending row is ordinary in-flight work.
 */
export function findStuckScopes(db: Database.Database): StuckScopeReport[] {
  const rows = db
    .prepare(
      `SELECT scope, COUNT(*) AS pending_rows
         FROM data_files
        WHERE data_point_id IS NULL
        GROUP BY scope
       HAVING COUNT(*) > 1
        ORDER BY scope ASC`,
    )
    .all() as StuckScopeRow[];
  return rows.map((r) => ({ scope: r.scope, pendingRows: r.pending_rows }));
}

export const detectStuckVersionLedger: StateMigration = {
  id: DETECT_STUCK_VERSION_LEDGER_ID,
  description:
    "Detect (non-destructively) scopes whose upload queue has accumulated multiple pending rows — the version-ledger thrash fingerprint (BUI-715). Records prevalence to state.json; the sync worker's 409 rebase/adopt (#158/#202) performs the actual recovery.",
  // Cheap, mutation-free observation — safe to re-run every boot.
  everyBoot: true,
  check(ctx: StateMigrationContext): boolean {
    return findStuckScopes(ctx.db).length > 0;
  },
  run(ctx: StateMigrationContext): StateMigrationResult {
    const reports = findStuckScopes(ctx.db);
    if (reports.length === 0) return { changed: false };
    const pendingRows = reports.reduce((sum, r) => sum + r.pendingRows, 0);
    ctx.logger?.warn(
      {
        migration: DETECT_STUCK_VERSION_LEDGER_ID,
        scopeCount: reports.length,
        scopes: reports.map((r) => r.scope),
        pendingRows,
      },
      "Detected stuck version-ledger scopes (BUI-715); runtime 409 recovery will drain them on the next sync",
    );
    return {
      // Non-destructive: nothing was mutated, so `changed` stays false; the log
      // entry itself is the record of the detection.
      changed: false,
      detail: `detected ${reports.length} scope(s) with ${pendingRows} accumulated pending row(s)`,
    };
  },
};
