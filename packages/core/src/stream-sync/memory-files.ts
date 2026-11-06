/** In-memory `StreamSyncFiles`, for tests and short-lived hosts. */

import type { StreamSyncFiles } from "./ports.js";

export function createMemoryStreamSyncFiles(
  chunkBytes = 64 * 1024,
): StreamSyncFiles & { readonly paths: () => string[] } {
  const store = new Map<string, Uint8Array[]>();
  const under = (prefix: string) => (path: string) =>
    path === prefix || path.startsWith(`${prefix}/`);
  return {
    paths: () => [...store.keys()].sort(),
    async write(path, bytes) {
      store.set(path, [bytes.slice()]);
    },
    async read(path) {
      const chunks = store.get(path);
      if (!chunks) return null;
      const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
      let offset = 0;
      for (const chunk of chunks) {
        out.set(chunk, offset);
        offset += chunk.length;
      }
      return out;
    },
    async append(path, bytes) {
      const chunks = store.get(path) ?? [];
      chunks.push(bytes.slice());
      store.set(path, chunks);
    },
    async *readChunks(path) {
      for (const chunk of store.get(path) ?? []) {
        for (let i = 0; i < chunk.length; i += chunkBytes) {
          yield chunk.subarray(i, i + chunkBytes);
        }
      }
    },
    async size(path) {
      return (store.get(path) ?? []).reduce((n, c) => n + c.length, 0);
    },
    async list(prefix) {
      return [...store.keys()].filter((p) => p.startsWith(`${prefix}/`)).sort();
    },
    async remove(prefix) {
      for (const path of [...store.keys()].filter(under(prefix))) {
        store.delete(path);
      }
    },
  };
}
