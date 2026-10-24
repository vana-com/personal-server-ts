import type { Database } from "better-sqlite3";
import { laterScopeDeletion } from "@opendatalabs/personal-server-ts-core/sync";
import type {
  ScopeDeletionHistory,
  ScopeTombstone,
} from "@opendatalabs/personal-server-ts-core/sync";

/**
 * Gateway deletion observations survive file registration and restart.
 * This table owns no record data and cannot authorize a canonical re-add.
 */
export function createScopeDeletionHistory(
  db: Database,
  ownerAddress: string,
): ScopeDeletionHistory {
  db.exec(`
    CREATE TABLE IF NOT EXISTS vana_scope_deletion_history (
      owner_address TEXT NOT NULL,
      scope TEXT NOT NULL,
      deleted_at TEXT NOT NULL,
      tombstone_version TEXT,
      PRIMARY KEY (owner_address, scope)
    );
  `);
  const owner = ownerAddress.toLowerCase();
  const remember = db.prepare(`
    INSERT INTO vana_scope_deletion_history
      (owner_address, scope, deleted_at, tombstone_version)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (owner_address, scope) DO UPDATE SET
      deleted_at = excluded.deleted_at,
      tombstone_version = excluded.tombstone_version
  `);
  const get = db.prepare(`
    SELECT deleted_at, tombstone_version FROM vana_scope_deletion_history
    WHERE owner_address = ? AND scope = ?
  `);
  const history: ScopeDeletionHistory = {
    remember: db.transaction((scope: string, tombstone: ScopeTombstone) => {
      const retained = laterScopeDeletion(history.get(scope), tombstone);
      remember.run(owner, scope, retained.deletedAt, retained.version);
    }),
    get(scope): ScopeTombstone | null {
      const row = get.get(owner, scope) as
        { deleted_at: string; tombstone_version: string | null } | undefined;
      return row
        ? { deletedAt: row.deleted_at, version: row.tombstone_version }
        : null;
    },
  };
  return history;
}
