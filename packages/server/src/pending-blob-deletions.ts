import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  createPendingBlobDeletionStore,
  type PendingBlobDeletionKv,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { PendingBlobDeletionStore } from "@opendatalabs/personal-server-ts-core/ports";

interface PendingBlobDeletionsFile {
  version: 1;
  scopes: string[];
}

/**
 * File-backed retry marker for blob deletions whose gateway tombstone landed
 * but whose storage DELETE did not. Lives next to `sync-cursor.json` under
 * the server root; written atomically (tmp + rename) like the cursor.
 */
export function createFilePendingBlobDeletionStore(
  filePath: string,
): PendingBlobDeletionStore {
  const kv: PendingBlobDeletionKv = {
    async read() {
      try {
        const raw = await readFile(filePath, "utf8");
        const parsed = JSON.parse(raw) as Partial<PendingBlobDeletionsFile>;
        return Array.isArray(parsed.scopes) ? parsed.scopes : [];
      } catch (err) {
        if (
          err instanceof Error &&
          "code" in err &&
          (err as NodeJS.ErrnoException).code === "ENOENT"
        ) {
          return null;
        }
        throw err;
      }
    },
    async write(scopes) {
      await mkdir(dirname(filePath), { recursive: true });
      const tmpPath = `${filePath}.tmp`;
      const state: PendingBlobDeletionsFile = { version: 1, scopes };
      await writeFile(tmpPath, `${JSON.stringify(state, null, 2)}\n`);
      await rename(tmpPath, filePath);
    },
  };
  return createPendingBlobDeletionStore(kv);
}
