import type Database from "better-sqlite3";
import type { RetirementRows } from "@opendatalabs/personal-server-ts-core/localdb";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import { retireDataFileSync } from "./hierarchy.js";

export function createLegacyRetireRows(
  db: Database.Database,
  index: IndexManager,
  options: HierarchyManagerOptions,
  seal: LegacyWriteSeal,
): RetirementRows {
  const immediate = <T>(run: () => T): T => db.transaction(run).immediate();
  return {
    async capture(save, authority, scopes) {
      if (scopes.length === 0) return save([]);
      // Snapshot is taken in the same IMMEDIATE owner as index publication.
      const rows = immediate(() => {
        authority();
        return scopes.flatMap((scope) => {
          const rows = [];
          for (let offset = 0; ; offset += 200) {
            const page = index.findByScope({ scope, limit: 200, offset });
            rows.push(...page.map((row) => ({ ...row })));
            if (page.length < 200) return rows;
          }
        });
      });
      authority();
      return save(rows);
    },
    async absent(rows, authority) {
      return immediate(() => {
        authority();
        return rows.every(
          (row) =>
            !db.prepare("SELECT 1 FROM data_files WHERE id = ?").get(row.id),
        );
      });
    },
    erase: (row, authority) =>
      seal.remove(async () => {
        immediate(() => {
          authority();
          const current = index.findByPath(row.path);
          if (
            !current ||
            current.id !== row.id ||
            current.scope !== row.scope ||
            current.collectedAt !== row.collectedAt
          )
            return;
          retireDataFileSync(options, row.scope, row.collectedAt, authority);
          authority();
          index.deleteByPath(row.path);
        });
      }),
  };
}
