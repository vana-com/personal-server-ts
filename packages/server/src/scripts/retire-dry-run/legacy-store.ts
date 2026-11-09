/**
 * The real Node storage stack (SQLite index + legacy files), opened so the
 * data folder cannot change.
 *
 * SQLite cannot be opened read-only on a WAL database without making a `-shm`
 * file beside it, so the tool never opens the copy's database in place. It
 * copies `index.db` and `index.db-wal` (never `-shm`) into a scratch folder of
 * its own (new and empty, made by the caller) and opens that. A scratch folder
 * that already holds anything is refused: a stale `-wal` there would be
 * replayed over the copy. The legacy files are
 * read in place with plain reads. `deleteVersion` is the one write the stack
 * has; here it throws.
 */

import { copyFile, mkdir, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { RetireDeps } from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "../../storage/index-schema.js";
import { createIndexManager } from "../../storage/index-manager.js";
import { createNodeDataStorage } from "../../storage/node-data-storage.js";
import { isInside } from "./copy-only.js";

export type LegacyStorage = RetireDeps["storage"];

export interface LegacyStore {
  readonly storage: LegacyStorage;
  /** Every local legacy version the index lists, for the report's totals. */
  countVersions(): { scopes: number; versions: number };
  close(): void;
}

export class LegacyStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LegacyStoreError";
  }
}

/** The data folder's database files that exist; `-shm` is never copied. */
const SCOPE_PAGE = 200;

const DB_FILES = ["index.db", "index.db-wal"] as const;

export async function openLegacyStore(input: {
  /** The copy of the Personal Server root: `index.db`, `data/`. */
  readonly rootDir: string;
  /** A folder the tool owns; the database copy lives here. */
  readonly scratchDir: string;
}): Promise<LegacyStore> {
  const dataDir = join(input.rootDir, "data");
  await mkdir(input.scratchDir, { recursive: true });
  if ((await readdir(input.scratchDir)).length > 0) {
    throw new LegacyStoreError("The scratch folder is not empty.");
  }
  for (const name of DB_FILES) {
    try {
      await copyFile(join(input.rootDir, name), join(input.scratchDir, name));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      if (name === "index.db") {
        throw new LegacyStoreError(
          "The data folder has no index.db: copy the database file with the data folder.",
        );
      }
    }
  }
  const db = initializeDatabase(join(input.scratchDir, "index.db"));
  const indexManager = createIndexManager(db);
  const node = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });

  const realDataDir = resolve(dataDir);
  const storage: LegacyStorage = {
    listScopes: (options) => node.listScopes(options),
    listVersions: (scope, options) => node.listVersions(scope, options),
    readEnvelope(scope, collectedAt) {
      // The index names scope and time; never let a bad row reach outside.
      const path = resolve(buildDataFilePath(realDataDir, scope, collectedAt));
      if (!isInside(realDataDir, path)) {
        return Promise.reject(new LegacyStoreError("path leaves data folder"));
      }
      return node.readEnvelope(scope, collectedAt);
    },
    deleteVersion() {
      return Promise.reject(
        new LegacyStoreError("the dry run never deletes a file"),
      );
    },
  };

  return {
    storage,
    countVersions() {
      let scopes = 0;
      let versions = 0;
      for (let offset = 0; ; offset += SCOPE_PAGE) {
        const page = node.listScopes({ limit: SCOPE_PAGE, offset }).scopes;
        scopes += page.length;
        versions += page.reduce((n, s) => n + s.versionCount, 0);
        if (page.length < SCOPE_PAGE) return { scopes, versions };
      }
    },
    close: () => db.close(),
  };
}
