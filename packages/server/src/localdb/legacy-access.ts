import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { Database } from "better-sqlite3";
import type {
  ImportInventoryEntry,
  CopyRecords,
  LegacyCopy,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.4: scoped to the verified switched owner and the same local database/network. */
export interface LegacyAccessOptions {
  /** Borrowed native handle for root/index.db, NOT LocalSyncDeps.db. */
  readonly db: Database;
  /** Legacy index.db has no owner/network db_meta. Caller must bind the open
   * handle and canonical root to authenticated owner/network before any read
   * or retireReplication effect. Missing/false evidence refuses access.
   * Do not create identity metadata or trust copied config as authority. */
  readonly verifyBinding: (binding: {
    db: Database;
    owner: string;
    network: string;
    root: string;
  }) => Promise<boolean>;
  readonly owner: string;
  readonly network: string;
  /** Re-read trusted mode; unknown/off refuse before opening any store. */
  readonly isSwitched: (owner: string) => Promise<boolean>;
  readonly root: string;
  readonly declarations: readonly DeclarationSnapshot[];
  /** Existing storage removal authority; no new parallel lock/seal. */
  readonly legacyWriteSeal: import("@opendatalabs/personal-server-ts-core/storage/legacy-write-seal").LegacyWriteSeal;
  /** All legacy writers must be quiescent for the lifetime of this access.
   * Caller owns stopping them; false refuses before reads or door retirement. */
  readonly isQuiescent: () => Promise<boolean>;
}

/** F.4: all access to a switched owner's legacy index.db, including erase, passes here. */
export interface LegacyAccess {
  readonly owner: string;
  readonly network: string;
  /** Includes descriptors with exclusions for unmapped data; never silently omit a store. */
  sources(): AsyncIterable<ImportInventoryEntry>;
  readonly copyRecords: CopyRecords;
  copies(): AsyncIterable<LegacyCopy>;
  erase(copy: LegacyCopy): Promise<boolean>;
  close(): Promise<void>;
}

/**
 * F.4: verify db owner/root first; retireReplication(db) BEFORE reads or erases,
 * then openRecordStore(db,false). No replica wrappers, even when env enables
 * replication. Door stays closed. Must not close caller-owned db in close().
 * All raw SQL and file access for switched legacy stores is private here.
 * Inventory root/data using hierarchy's finalized-envelope layout and index
 * entries (including orphan/unmapped files); pending stages/blocks/sidecars
 * are held, never claimed covered. Reject symlinks and paths outside root.
 * Read/hash exact bytes with SHA-256. Erase uses withScopeLock(scope, work)
 * and legacyWriteSeal.remove, matching node-data-storage; these are not
 * reentrant: do not call a storage delete method while holding the same lock.
 * Writer quiescence must precede the snapshot and include sync/download sinks.
 * Missing trustworthy binding or quiescence refuses; root path is not identity.
 */
export function openLegacyAccess(
  _options: LegacyAccessOptions,
): Promise<LegacyAccess> {
  throw new Error("PS-3: not built");
}
