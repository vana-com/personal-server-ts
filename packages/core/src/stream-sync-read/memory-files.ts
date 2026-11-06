/** In-memory {@link StreamSyncReadFiles}, for PS-Lite without disk and for tests. */

import type { StreamSyncReadFiles } from "./ports.js";

const CHUNK = 64 * 1024;

export function createMemoryStreamSyncReadFiles(): StreamSyncReadFiles & {
  readonly files: Map<string, Uint8Array>;
} {
  const files = new Map<string, Uint8Array>();
  const under = (prefix: string) => (path: string) =>
    path === prefix || path.startsWith(`${prefix}/`);
  return {
    files,
    async write(path, bytes) {
      files.set(path, bytes.slice());
    },
    async read(path) {
      const bytes = files.get(path);
      return bytes ? bytes.slice() : null;
    },
    async *readChunks(path) {
      const bytes = files.get(path);
      if (!bytes) return;
      for (let at = 0; at < bytes.length; at += CHUNK) {
        yield bytes.slice(at, at + CHUNK);
      }
    },
    async list(prefix) {
      return [...files.keys()].filter(under(prefix)).sort();
    },
    async remove(prefix) {
      for (const path of [...files.keys()]) {
        if (under(prefix)(path)) files.delete(path);
      }
    },
  };
}
