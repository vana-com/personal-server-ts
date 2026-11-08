import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type {
  UploadAttemptRecord,
  UploadAttemptStore,
} from "@opendatalabs/personal-server-ts-core/sync";

/**
 * File-backed upload-attempt markers (see core `upload-attempts.ts`), next to
 * `pending-blob-deletions.json` under the server root. Written atomically (tmp
 * + rename) before an upload body is built, so a process killed mid-upload
 * leaves the marker behind.
 */
export function createFileUploadAttemptStore(
  filePath: string,
): UploadAttemptStore {
  return {
    async read() {
      try {
        const parsed = JSON.parse(await readFile(filePath, "utf8")) as {
          records?: unknown;
        };
        return Array.isArray(parsed.records)
          ? (parsed.records as UploadAttemptRecord[])
          : null;
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
    },
    async write(records) {
      await mkdir(dirname(filePath), { recursive: true });
      const tmpPath = `${filePath}.tmp`;
      await writeFile(
        tmpPath,
        `${JSON.stringify({ version: 1, records }, null, 2)}\n`,
      );
      await rename(tmpPath, filePath);
    },
  };
}
