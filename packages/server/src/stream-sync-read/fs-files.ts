/**
 * Filesystem {@link StreamSyncReadFiles} for the full server, under one root
 * directory. A write lands in a temporary file that is synced and renamed
 * over the target, so a reader or a crash never sees half a file.
 */

import { createReadStream } from "node:fs";
import { mkdir, open, readdir, readFile, rename, rm } from "node:fs/promises";
import { dirname, join, relative, sep } from "node:path";
import type { StreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";

function inside(root: string, path: string): string {
  const full = join(root, path);
  const rel = relative(root, full);
  if (rel === "" || rel.startsWith("..") || rel.split(sep).includes("..")) {
    throw new Error("path leaves the stream-sync directory");
  }
  return full;
}

export function createFsStreamSyncReadFiles(root: string): StreamSyncReadFiles {
  let counter = 0;
  return {
    async write(path, bytes) {
      const target = inside(root, path);
      await mkdir(dirname(target), { recursive: true });
      const temp = `${target}.tmp-${process.pid}-${counter++}`;
      const handle = await open(temp, "w");
      try {
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temp, target);
    },
    async read(path) {
      try {
        return new Uint8Array(await readFile(inside(root, path)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    },
    async *readChunks(path) {
      try {
        for await (const chunk of createReadStream(inside(root, path), {
          highWaterMark: 64 * 1024,
        })) {
          yield new Uint8Array(chunk as Buffer);
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
        throw error;
      }
    },
    async list(prefix) {
      const base = inside(root, prefix);
      const out: string[] = [];
      try {
        for (const entry of await readdir(base, {
          recursive: true,
          withFileTypes: true,
        })) {
          if (!entry.isFile() || entry.name.includes(".tmp-")) continue;
          out.push(
            relative(root, join(entry.parentPath, entry.name))
              .split(sep)
              .join("/"),
          );
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
        throw error;
      }
      return out.sort();
    },
    async remove(prefix) {
      await rm(inside(root, prefix), { recursive: true, force: true });
    },
  };
}
