import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import {
  createSeedStaging,
  type SeedStaging,
  type StreamSyncFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { PsLiteStateKey, PsLiteStateStore } from "./state.js";

type File =
  | { kind: "text"; text: string; bytes: number }
  | { kind: "chunks"; parts: number; bytes: number };
type FileIndex = Record<string, File>;

/** Seed staging over Lite's injected durable state, including native phone
 * stores. Values are JSON-compatible UTF-8 text, never Node files or a growing
 * record array. The index holds pointers and chunk counts, not row contents.
 * The shared stager appends complete NDJSON records in bounded write batches. */
export function createPsLiteSeedStaging(
  store: PsLiteStateStore,
  owner: string,
  network: string,
): SeedStaging {
  const namespace = encodeURIComponent(
    JSON.stringify([owner.toLowerCase(), network]),
  );
  const indexKey: PsLiteStateKey = `seed-v1:${namespace}:index`;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const chunkKey = (path: string, part: number): PsLiteStateKey =>
    `seed-v1:${namespace}:chunk:${encodeURIComponent(path)}:${part}`;
  const index = async () => (await store.get<FileIndex>(indexKey)) ?? {};
  const under = (path: string, prefix: string) =>
    path === prefix || path.startsWith(prefix + "/");
  const mutate = <T>(work: (files: FileIndex) => Promise<T>) =>
    withScopeLock(
      `seed-files:${store.namespace ?? "custom"}:${namespace}`,
      async () => work(await index()),
    );
  const files: StreamSyncFiles = {
    async write(path, bytes) {
      await mutate(async (entries) => {
        // Only the shared stager can use this private port. Its row files are
        // append-only until removed; atomic replacements are small pointers.
        if (entries[path]?.kind === "chunks")
          throw new Error("seed_rows_are_immutable");
        entries[path] = {
          kind: "text",
          text: decoder.decode(bytes),
          bytes: bytes.byteLength,
        };
        await store.set(indexKey, entries);
      });
    },
    async read(path) {
      const file = (await index())[path];
      if (!file) return null;
      if (file.kind === "text") return encoder.encode(file.text);
      const bytes = new Uint8Array(file.bytes);
      let offset = 0;
      for await (const chunk of files.readChunks(path)) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      return bytes;
    },
    async appendMany(appends) {
      await mutate(async (entries) => {
        for (const { path, bytes } of appends) {
          const prior = entries[path];
          if (prior?.kind === "text")
            throw new Error("seed_pointer_is_not_appendable");
          const file = prior ?? { kind: "chunks" as const, parts: 0, bytes: 0 };
          const part = file.parts;
          entries[path] = {
            kind: "chunks",
            parts: part + 1,
            bytes: file.bytes + bytes.byteLength,
          };
          // Register planned chunks before writing. A crash leaves no published
          // pointer, and collection can remove even a missing planned chunk.
          await store.set(indexKey, entries);
          await store.set(chunkKey(path, part), decoder.decode(bytes));
        }
      });
    },
    async sync() {
      // Each state write is durable when its promise resolves. The shared
      // stager publishes its pointer only after every chunk write resolves.
    },
    async *readChunks(path) {
      const file = (await index())[path];
      if (!file) return;
      if (file.kind === "text") {
        yield encoder.encode(file.text);
        return;
      }
      for (let part = 0; part < file.parts; part++) {
        const text = await store.get<string>(chunkKey(path, part));
        if (text === null) throw new Error("seed_chunk_missing");
        yield encoder.encode(text);
      }
    },
    async size(path) {
      return (await index())[path]?.bytes ?? 0;
    },
    async list(prefix) {
      return Object.keys(await index()).filter((path) => under(path, prefix));
    },
    async remove(prefix) {
      await mutate(async (entries) => {
        for (const [path, file] of Object.entries(entries)) {
          if (!under(path, prefix)) continue;
          if (file.kind === "chunks")
            for (let part = 0; part < file.parts; part++)
              await store.delete(chunkKey(path, part));
          delete entries[path];
        }
        await store.set(indexKey, entries);
      });
    },
  };
  return createSeedStaging(files);
}
