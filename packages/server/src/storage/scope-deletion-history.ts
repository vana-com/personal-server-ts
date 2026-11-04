import type { Database } from "better-sqlite3";
import type {
  ScopeDeletionHistory,
  ScopeTombstone,
} from "@opendatalabs/personal-server-ts-core/sync";

/**
 * Gateway deletion observations survive file registration and restart.
 * A marker authorizes canonical reads only after the matching erase commits.
 */
export function createScopeDeletionHistory(
  db: Database,
  ownerAddress: string,
  records?:
    | {
        recordScopeDeletion(
          scope: string,
          writeHistory: () => boolean,
          markApplied: () => void,
        ): void;
      }
    | (() =>
        | {
            recordScopeDeletion(
              scope: string,
              writeHistory: () => boolean,
              markApplied: () => void,
            ): void;
          }
        | undefined),
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
  const columns = db.pragma("table_info(vana_scope_deletion_history)") as {
    name: string;
  }[];
  if (!columns.some((column) => column.name === "erase_applied")) {
    db.exec(
      "ALTER TABLE vana_scope_deletion_history ADD COLUMN erase_applied INTEGER NOT NULL DEFAULT 0",
    );
  }
  const owner = ownerAddress.toLowerCase();
  const remember = db.prepare(`
    INSERT INTO vana_scope_deletion_history
      (owner_address, scope, deleted_at, tombstone_version)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (owner_address, scope) DO UPDATE SET
      deleted_at = excluded.deleted_at,
      tombstone_version = excluded.tombstone_version,
      erase_applied = 0
  `);
  const get = db.prepare(`
    SELECT deleted_at, tombstone_version, erase_applied FROM vana_scope_deletion_history
    WHERE owner_address = ? AND scope = ?
  `);
  return {
    remember(scope, tombstone) {
      const write = () => {
        const previous = get.get(owner, scope) as
          { deleted_at: string; tombstone_version: string | null } | undefined;
        if (previous) {
          const priorVersion =
            previous.tombstone_version === "0"
              ? null
              : previous.tombstone_version;
          if (priorVersion === null || tombstone.version === null) {
            if (
              priorVersion === tombstone.version &&
              previous.deleted_at === tombstone.deletedAt
            )
              return false;
            throw new Error("Cannot order tombstones without versions");
          }
          if (BigInt(tombstone.version) <= BigInt(priorVersion)) return false;
        }
        remember.run(owner, scope, tombstone.deletedAt, tombstone.version);
        return true;
      };
      const store = typeof records === "function" ? records() : records;
      const markApplied = () => {
        db.prepare(
          "UPDATE vana_scope_deletion_history SET erase_applied = 1 WHERE owner_address = ? AND scope = ?",
        ).run(owner, scope);
      };
      if (store) store.recordScopeDeletion(scope, write, markApplied);
      else if (records) {
        db.transaction(() => {
          const registry = db
            .prepare(
              "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name IN ('pdpp_instance_binding', 'pdpp_records', 'pdpp_record_changes', 'pdpp_stream_completion', 'pdpp_record_arrival') LIMIT 1",
            )
            .get();
          if (registry)
            throw new Error(
              "Canonical record store unavailable for deletion observation",
            );
          if (write()) markApplied();
        }).immediate();
      } else write();
    },
    get(scope): ScopeTombstone | null {
      const row = get.get(owner, scope) as
        | {
            deleted_at: string;
            tombstone_version: string | null;
            erase_applied: number;
          }
        | undefined;
      return row
        ? {
            deletedAt: row.deleted_at,
            version: row.tombstone_version,
            ...(row.erase_applied === 1 ? { eraseApplied: true } : {}),
          }
        : null;
    },
  };
}
