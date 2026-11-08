/**
 * {@link StreamSyncReadFiles} on a directory, for tests that must read the
 * same files from a fresh process (see `memory-oracle.ts`). Same contract as
 * the memory adapter: paths are relative to `root`, `list` and `remove` match
 * `prefix/`, and a missing file reads as `null` or as nothing.
 */

import { createReadStream } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import type { StreamSyncReadFiles } from "../stream-sync-read/ports.js";

const CHUNK = 64 * 1024;

const missing = (error: unknown): boolean =>
  (error as NodeJS.ErrnoException).code === "ENOENT";

export function createDiskStreamSyncReadFiles(
  root: string,
): StreamSyncReadFiles {
  const base = resolve(root);
  const abs = (path: string): string => {
    const full = resolve(base, path);
    if (!full.startsWith(`${base}${sep}`)) {
      throw new Error(`path ${path} leaves the root`);
    }
    return full;
  };
  return {
    async write(path, bytes) {
      const full = abs(path);
      await mkdir(dirname(full), { recursive: true });
      const tmp = `${full}.tmp`;
      await writeFile(tmp, bytes);
      await rename(tmp, full);
    },
    async read(path) {
      try {
        return new Uint8Array(await readFile(abs(path)));
      } catch (error) {
        if (missing(error)) return null;
        throw error;
      }
    },
    async *readChunks(path) {
      const stream = createReadStream(abs(path), { highWaterMark: CHUNK });
      try {
        for await (const chunk of stream) {
          yield new Uint8Array(chunk as Buffer);
        }
      } catch (error) {
        if (!missing(error)) throw error;
      }
    },
    async list(prefix) {
      const out: string[] = [];
      const walk = async (dir: string): Promise<void> => {
        let entries;
        try {
          entries = await readdir(dir, { withFileTypes: true });
        } catch (error) {
          if (missing(error)) return;
          // A file prefix lists itself, as the memory adapter does.
          if ((error as NodeJS.ErrnoException).code === "ENOTDIR") {
            out.push(relative(base, dir).split(sep).join("/"));
            return;
          }
          throw error;
        }
        for (const entry of entries) {
          const full = join(dir, entry.name);
          if (entry.isDirectory()) await walk(full);
          else if (!entry.name.endsWith(".tmp")) {
            out.push(relative(base, full).split(sep).join("/"));
          }
        }
      };
      await walk(abs(prefix));
      return out.sort();
    },
    async remove(prefix) {
      await rm(abs(prefix), { recursive: true, force: true });
    },
  };
}
