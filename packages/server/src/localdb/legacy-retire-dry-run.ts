import type { Database } from "better-sqlite3";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  LocalSyncDeps,
  LegacyRetireAccess,
  LegacyRetireOptions,
  LegacyRetireFileReport,
  LegacyRetireReport,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { LegacyAccess, LegacyAccessOptions } from "./legacy-access.js";

/** F.2/F.4: caller supplies trusted offline ports; no config parsing. */
export interface LegacyRetireDryRunOptions {
  readonly copyRoot: string;
  readonly scratchRoot: string;
  readonly owner: string;
  readonly network: string;
  readonly declarations: readonly DeclarationSnapshot[];
  readonly isSwitched: LegacyAccessOptions["isSwitched"];
  readonly verifyBinding: LegacyAccessOptions["verifyBinding"];
  readonly legacyWriteSeal: LegacyAccessOptions["legacyWriteSeal"];
  readonly isQuiescent: LegacyAccessOptions["isQuiescent"];
  /** Relative to copyRoot; two distinct files. Never guess that legacy index.db
   * has localdb db_meta/receipts. Reject traversal, symlinks, WAL/SHM inputs. */
  readonly localDatabasePath: string;
  readonly legacyDatabasePath: string;
  /** Open only the scratch copies. Native legacy handle is separate from the
   * SqlDriver in deps; close owns both, including partial-open rollback. */
  readonly openScratch: (paths: {
    localDatabasePath: string;
    legacyDatabasePath: string;
  }) => Promise<{
    deps: LocalSyncDeps;
    legacyDb: Database;
    close(): Promise<void>;
  }>;
  readonly openAccess: (options: LegacyAccessOptions) => Promise<LegacyAccess>;
  /** Caller composes fresh read-back with immutable peer sources and copyRecords.
   * This capability cannot erase. All SQL reads use scratch deps. */
  readonly readBack: (
    deps: LocalSyncDeps,
    access: LegacyAccess,
  ) => LegacyRetireAccess["readBack"];
  readonly retire: (
    deps: LocalSyncDeps,
    access: LegacyRetireAccess,
    options: LegacyRetireOptions,
  ) => Promise<LegacyRetireReport>;
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/**
 * Byte-copy only, never live user data. Hash input tree before/after; all
 * mutation, including retireReplication, is on scratch. Invoke retire with
 * dryRun:true and an erase port that refuses. Never import, publish, refresh
 * registry or persist proof status. Close all acquired handles on every exit.
 */
export function runLegacyRetireDryRun(
  _options: LegacyRetireDryRunOptions,
): Promise<LegacyRetireReport> {
  throw new Error("PS-3: not built");
}
