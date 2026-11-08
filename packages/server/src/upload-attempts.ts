import { mkdir, open, readFile, rename } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  acquireProcessLock,
  type UploadAttemptStore,
} from "@opendatalabs/personal-server-ts-core/sync";

let tempCounter = 0;

/**
 * File-backed upload-attempt markers (see core `upload-attempts.ts`), next to
 * `pending-blob-deletions.json` under the server root. Each write goes to a
 * unique temp file, is flushed, renamed over the ledger, and the directory is
 * flushed, so the marker is on disk before an upload body is built. One
 * manager per file per process holds the owner lock.
 */
export function createFileUploadAttemptStore(
  filePath: string,
): UploadAttemptStore {
  const lockName = `upload-attempts:${resolve(filePath)}`;
  return {
    async read() {
      let text: string;
      try {
        text = await readFile(filePath, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      // Unparseable text throws: the file is kept for recovery, not replaced.
      return JSON.parse(text) as unknown;
    },
    async write(envelope) {
      const directory = dirname(filePath);
      await mkdir(directory, { recursive: true });
      const tmpPath = `${filePath}.${process.pid}.${++tempCounter}.tmp`;
      const file = await open(tmpPath, "w");
      try {
        await file.writeFile(`${JSON.stringify(envelope, null, 2)}\n`);
        await file.sync();
      } finally {
        await file.close();
      }
      await rename(tmpPath, filePath);
      const dir = await open(directory, "r");
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
    },
    async acquire() {
      return acquireProcessLock(lockName);
    },
  };
}
