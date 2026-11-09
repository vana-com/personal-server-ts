/** Disk-backed `StreamSyncReadFiles` for the memory workloads: no file stays in the heap. */

import {
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createReadStream } from "node:fs";
import { dirname, join } from "node:path";
import type { StreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";

export function fsReadFiles(root: string): StreamSyncReadFiles {
  const abs = (path: string) => join(root, path);
  const walk = async (dir: string, base: string): Promise<string[]> => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return [];
    }
    const out: string[] = [];
    for (const entry of entries) {
      const rel = `${base}/${entry.name}`;
      if (entry.isDirectory())
        out.push(...(await walk(join(dir, entry.name), rel)));
      else out.push(rel);
    }
    return out.sort();
  };
  return {
    async write(path, bytes) {
      await mkdir(dirname(abs(path)), { recursive: true });
      const tmp = `${abs(path)}.tmp`;
      await writeFile(tmp, bytes);
      await rename(tmp, abs(path));
    },
    async read(path) {
      try {
        return new Uint8Array(await readFile(abs(path)));
      } catch {
        return null;
      }
    },
    async *readChunks(path) {
      try {
        for await (const chunk of createReadStream(abs(path), {
          highWaterMark: 1024 * 1024,
        })) {
          yield chunk as Uint8Array;
        }
      } catch {
        return;
      }
    },
    list: (prefix) => walk(abs(prefix), prefix),
    remove: (prefix) => rm(abs(prefix), { recursive: true, force: true }),
  };
}
