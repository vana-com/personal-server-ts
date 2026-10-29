import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  createPendingBlobDeletionStore,
  normalizePendingBlobDeletionPlanned,
  normalizePendingBlobDeletions,
  type PendingBlobDeletionKv,
  type PendingBlobDeletionPlanned,
} from "@opendatalabs/personal-server-ts-core/sync";
import type {
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "@opendatalabs/personal-server-ts-core/ports";

interface PendingBlobDeletionsFile {
  version: 2;
  keys: PendingBlobDeletion[];
  /**
   * Per scope, the highest tombstone version already planned (queued or
   * done), so a repeated delete resumes instead of restarting at version 1.
   * Older builds ignore it; losing it only costs a redundant re-sweep.
   */
  planned?: PendingBlobDeletionPlanned;
}

/**
 * File-backed retry markers for blob deletions whose gateway tombstone landed
 * but whose storage DELETE did not finish: one exact (scope, version) key
 * each. Lives next to `sync-cursor.json` under the server root; written
 * atomically (tmp + rename) like the cursor. A version-1 file (whole scopes)
 * is read as version-less markers the retry expands into exact keys.
 * `planned` keeps each scope's planned-through watermark in the same write.
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
          planned?: unknown;
        };
        return {
          keys: normalizePendingBlobDeletions(parsed.keys ?? parsed.scopes),
          planned: normalizePendingBlobDeletionPlanned(parsed.planned),
        };
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
    async write(keys, planned) {
      await mkdir(dirname(filePath), { recursive: true });
      const tmpPath = `${filePath}.tmp`;
      const state: PendingBlobDeletionsFile = { version: 2, keys, planned };
      await writeFile(tmpPath, `${JSON.stringify(state, null, 2)}\n`);
      await rename(tmpPath, filePath);
    },
  };
  return createPendingBlobDeletionStore(kv);
}
