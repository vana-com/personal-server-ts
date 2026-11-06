/**
 * `StreamSyncFiles` on the local filesystem (§2.8, Desktop full server).
 *
 * `write` replaces a file atomically (temporary file, fsync, rename, fsync of
 * the directory). `append` fsyncs before it resolves. Paths are relative to
 * `root` and may not leave it.
 */

import { createReadStream } from "node:fs";
import {
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  stat,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";

const CHUNK_BYTES = 1024 * 1024;

async function fsyncDir(dir: string): Promise<void> {
  const handle = await open(dir, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export function createFsStreamSyncFiles(root: string): StreamSyncFiles {
  const base = resolve(root);
  let tmpCounter = 0;
  const abs = (path: string): string => {
    const full = resolve(base, path);
    if (full !== base && !full.startsWith(`${base}${sep}`)) {
      throw new Error(`path ${path} leaves the stream-sync root`);
    }
    return full;
  };
  const missing = (error: unknown) =>
    (error as NodeJS.ErrnoException).code === "ENOENT";

  return {
    async write(path, bytes) {
      const full = abs(path);
      await mkdir(dirname(full), { recursive: true });
      tmpCounter += 1;
      const tmp = `${full}.tmp-${process.pid}-${tmpCounter}`;
      const handle = await open(tmp, "w");
      try {
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tmp, full);
      await fsyncDir(dirname(full));
    },
    async read(path) {
      try {
        return new Uint8Array(await readFile(abs(path)));
      } catch (error) {
        if (missing(error)) return null;
        throw error;
      }
    },
    async append(path, bytes) {
      const full = abs(path);
      await mkdir(dirname(full), { recursive: true });
      const handle = await open(full, "a");
      try {
        await handle.write(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
    },
    async *readChunks(path) {
      const full = abs(path);
      try {
        await stat(full);
      } catch (error) {
        if (missing(error)) return;
        throw error;
      }
      const stream = createReadStream(full, { highWaterMark: CHUNK_BYTES });
      for await (const chunk of stream) {
        yield new Uint8Array(chunk as Buffer);
      }
    },
    async size(path) {
      try {
        return (await stat(abs(path))).size;
      } catch (error) {
        if (missing(error)) return 0;
        throw error;
      }
    },
    async list(prefix) {
      const dir = abs(prefix);
      try {
        const entries = await readdir(dir, {
          recursive: true,
          withFileTypes: true,
        });
        return entries
          .filter((e) => e.isFile() && !e.name.includes(".tmp-"))
          .map((e) =>
            relative(base, join(e.parentPath, e.name)).split(sep).join("/"),
          )
          .sort();
      } catch (error) {
        if (missing(error)) return [];
        throw error;
      }
    },
    async remove(prefix) {
      await rm(abs(prefix), { recursive: true, force: true });
    },
  };
}
