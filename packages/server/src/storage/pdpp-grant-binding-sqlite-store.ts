import type { Database } from "better-sqlite3";

import { InvalidSignatureError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  bindingsAgree,
  permissionKey,
  type ChainPermissionRef,
  type PdppGrantBinding,
  type PdppGrantBindingStore,
} from "@opendatalabs/personal-server-ts-core/grants";

const MIGRATIONS: string[] = [
  `
CREATE TABLE IF NOT EXISTS pdpp_grant_bindings (
  pdpp_grant_id TEXT PRIMARY KEY,
  permission_key TEXT NOT NULL UNIQUE,
  chain_id INTEGER NOT NULL,
  contract_address TEXT NOT NULL,
  permission_id TEXT NOT NULL,
  owner_address TEXT NOT NULL,
  grantee_address TEXT NOT NULL,
  pdpp_client_id TEXT NOT NULL,
  grantee_id TEXT NOT NULL,
  bound_at TEXT NOT NULL
);
`,
];

function migrate(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS pdpp_grant_bindings_schema_version (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      version INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO pdpp_grant_bindings_schema_version (id, version) VALUES (1, 0);
  `);
  const current = db
    .prepare(
      "SELECT version FROM pdpp_grant_bindings_schema_version WHERE id = 1",
    )
    .get() as { version: number };

  const applyFrom = db.transaction((fromVersion: number) => {
    for (let v = fromVersion; v < MIGRATIONS.length; v++) {
      db.exec(MIGRATIONS[v]);
    }
    db.prepare(
      "UPDATE pdpp_grant_bindings_schema_version SET version = ? WHERE id = 1",
    ).run(MIGRATIONS.length);
  });

  if (current.version < MIGRATIONS.length) {
    applyFrom(current.version);
  } else if (current.version > MIGRATIONS.length) {
    throw new Error(
      `pdpp_grant_bindings database schema version ${current.version} is newer than this build supports (${MIGRATIONS.length}). Refusing to open — upgrade this build before opening this database.`,
    );
  }
}

interface BindingRowDb {
  pdpp_grant_id: string;
  permission_key: string;
  chain_id: number;
  contract_address: string;
  permission_id: string;
  owner_address: string;
  grantee_address: string;
  pdpp_client_id: string;
  grantee_id: string;
  bound_at: string;
}

function toBinding(row: BindingRowDb): PdppGrantBinding {
  return Object.freeze({
    pdppGrantId: row.pdpp_grant_id,
    permission: {
      chainId: row.chain_id,
      contractAddress: row.contract_address as `0x${string}`,
      permissionId: row.permission_id,
    },
    ownerAddress: row.owner_address as `0x${string}`,
    granteeAddress: row.grantee_address as `0x${string}`,
    pdppClientId: row.pdpp_client_id,
    granteeId: row.grantee_id,
    boundAt: row.bound_at,
  });
}

/**
 * SQLite-backed PdppGrantBindingStore for desktop persistence. Backs the same
 * port as `createInMemoryPdppGrantBindingStore` (packages/core/src/grants/
 * pdpp-binding-store.ts) — append-only identity binding, idempotent identical
 * re-put, conflicting-rewrite rejection, no mirrored revocation status.
 *
 * The two unique constraints (PRIMARY KEY on pdpp_grant_id, UNIQUE on
 * permission_key) are the enforcement mechanism: a conflicting insert fails
 * at the SQL layer inside the same transaction as the pre-check, so no
 * partial row is ever visible to a concurrent reader.
 */
export function createSqlitePdppGrantBindingStore(
  db: Database,
): PdppGrantBindingStore {
  db.pragma("journal_mode = WAL");
  migrate(db);

  const getByGrantIdStmt = db.prepare(
    "SELECT * FROM pdpp_grant_bindings WHERE pdpp_grant_id = ?",
  );
  const getByPermissionKeyStmt = db.prepare(
    "SELECT * FROM pdpp_grant_bindings WHERE permission_key = ?",
  );
  const insertStmt = db.prepare(`
    INSERT INTO pdpp_grant_bindings
      (pdpp_grant_id, permission_key, chain_id, contract_address, permission_id,
       owner_address, grantee_address, pdpp_client_id, grantee_id, bound_at)
    VALUES
      (@pdpp_grant_id, @permission_key, @chain_id, @contract_address, @permission_id,
       @owner_address, @grantee_address, @pdpp_client_id, @grantee_id, @bound_at)
  `);

  function putBinding(binding: PdppGrantBinding): void {
    const runPut = db.transaction(() => {
      const existingByGrant = getByGrantIdStmt.get(binding.pdppGrantId) as
        BindingRowDb | undefined;
      if (existingByGrant) {
        if (!bindingsAgree(toBinding(existingByGrant), binding)) {
          throw new InvalidSignatureError({
            reason: "A different binding already exists for this PDPP grant id",
            pdppGrantId: binding.pdppGrantId,
          });
        }
        return;
      }

      const key = permissionKey(binding.permission);
      const existingByPermission = getByPermissionKeyStmt.get(key) as
        BindingRowDb | undefined;
      if (existingByPermission) {
        if (!bindingsAgree(toBinding(existingByPermission), binding)) {
          throw new InvalidSignatureError({
            reason: "A different binding already exists for this permission",
            permission: key,
          });
        }
        return;
      }

      insertStmt.run({
        pdpp_grant_id: binding.pdppGrantId,
        permission_key: key,
        chain_id: binding.permission.chainId,
        contract_address: binding.permission.contractAddress,
        permission_id: binding.permission.permissionId,
        owner_address: binding.ownerAddress,
        grantee_address: binding.granteeAddress,
        pdpp_client_id: binding.pdppClientId,
        grantee_id: binding.granteeId,
        bound_at: binding.boundAt,
      });
    });

    runPut();
  }

  return {
    putBinding,
    getByPdppGrantId(pdppGrantId: string): PdppGrantBinding | null {
      const row = getByGrantIdStmt.get(pdppGrantId) as BindingRowDb | undefined;
      return row ? toBinding(row) : null;
    },
    getByPermission(permission: ChainPermissionRef): PdppGrantBinding | null {
      const row = getByPermissionKeyStmt.get(permissionKey(permission)) as
        BindingRowDb | undefined;
      return row ? toBinding(row) : null;
    },
  };
}
