import { mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import {
  UploadAttemptWriteUncertainError,
  type UploadAttemptStore,
} from "@opendatalabs/personal-server-ts-core/sync";

let tempCounter = 0;
const MAX_CORRUPT_COPIES = 3;

/** Write `text` so it is on disk when this resolves: temp file, flush, rename, flush the directory. */
async function writeDurably(path: string, text: string): Promise<void> {
  const directory = dirname(path);
  await mkdir(directory, { recursive: true });
  const tmpPath = `${path}.${process.pid}.${++tempCounter}.tmp`;
  const file = await open(tmpPath, "w");
  try {
    await file.writeFile(text);
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(tmpPath, path);
  // Past the rename the new value may already be what a reader sees.
  try {
    const dir = await open(directory, "r");
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  } catch (error) {
    throw new UploadAttemptWriteUncertainError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

/**
 * File-backed upload-attempt markers (see core `upload-attempts.ts`), next to
 * `pending-blob-deletions.json` under the server root. Every write is on disk
 * before an upload body is built. The resolved file path names the store, so
 * one manager per file per process holds the owner lock; another process on
 * the same file is not excluded.
 */
export function createFileUploadAttemptStore(
  filePath: string,
): UploadAttemptStore {
  const path = resolve(filePath);
  return {
    namespace: path,
    async read() {
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      try {
        return JSON.parse(text) as unknown;
      } catch {
        // Readable but not JSON: hand the text on as a value that is not a
        // ledger, so it is preserved rather than lost.
        return text;
      }
    },
    write: (envelope) =>
      writeDurably(path, `${JSON.stringify(envelope, null, 2)}\n`),
    async preserveCorrupt(value, stamp) {
      const name = `${basename(path)}.corrupt-${stamp.replace(/[^0-9A-Za-z]/g, "-")}`;
      await writeDurably(
        resolve(dirname(path), name),
        typeof value === "string" ? value : JSON.stringify(value, null, 2),
      );
      const copies = (await readdir(dirname(path)))
        .filter((file) => file.startsWith(`${basename(path)}.corrupt-`))
        .sort();
      for (const old of copies.slice(0, -MAX_CORRUPT_COPIES))
        await rm(resolve(dirname(path), old), { force: true });
    },
  };
}
