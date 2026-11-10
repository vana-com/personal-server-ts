import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { Database } from "better-sqlite3";
import type {
  ImportSource,
  LegacyCopy,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.4: scoped to the verified switched owner and the same local database/network. */
export interface LegacyAccessOptions {
  readonly db: Database;
  readonly owner: string;
  readonly network: string;
  /** Re-read trusted mode; unknown/off refuse before opening any store. */
  readonly isSwitched: (owner: string) => Promise<boolean>;
  readonly root: string;
  readonly declarations: readonly DeclarationSnapshot[];
}

/** F.4: all access to a switched owner's legacy index.db, including erase, passes here. */
export interface LegacyAccess {
  readonly owner: string;
  readonly network: string;
  /** Includes descriptors with exclusions for unmapped data; never silently omit a store. */
  sources(): AsyncIterable<ImportSource>;
  copies(): AsyncIterable<LegacyCopy>;
  erase(copy: LegacyCopy): Promise<boolean>;
  close(): Promise<void>;
}

/**
 * F.4: verify db owner/root first; retireReplication(db) BEFORE reads or erases,
 * then openRecordStore(db,false). No replica wrappers, even when env enables
 * replication. Door stays closed. Must not close caller-owned db in close().
 * All raw SQL and file access for switched legacy stores is private here.
 */
export function openLegacyAccess(
  _options: LegacyAccessOptions,
): Promise<LegacyAccess> {
  throw new Error("PS-3: not built");
}
