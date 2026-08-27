import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  createPendingBlobDeletionStore,
  normalizePendingBlobDeletions,
  type PendingBlobDeletionKv,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "@opendatalabs/personal-server-ts-core/ports";

interface PendingBlobDeletionsFile {
  version: 2;
  keys: PendingBlobDeletion[];
}

/**
 * File-backed retry markers for blob deletions whose gateway tombstone landed
 * but whose storage DELETE did not finish: one exact (scope, version) key
 * each. Lives next to `sync-cursor.json` under the server root; written
 * atomically (tmp + rename) like the cursor. A version-1 file (whole scopes)
 * is read as version-less markers the retry expands into exact keys.
 */
export function createFilePendingBlobDeletionStore(
  filePath: string,
): PendingBlobDeletionStore {
  const kv: PendingBlobDeletionKv = {
    async read() {
      try {
        const raw = await readFile(filePath, "utf8");
        const parsed = JSON.parse(raw) as {
          version?: number;
          keys?: unknown;
          scopes?: unknown;
        };
        return normalizePendingBlobDeletions(parsed.keys ?? parsed.scopes);
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
    async write(keys) {
      await mkdir(dirname(filePath), { recursive: true });
      const tmpPath = `${filePath}.tmp`;
      const state: PendingBlobDeletionsFile = { version: 2, keys };
      await writeFile(tmpPath, `${JSON.stringify(state, null, 2)}\n`);
      await rename(tmpPath, filePath);
    },
  };
  return createPendingBlobDeletionStore(kv);
}
