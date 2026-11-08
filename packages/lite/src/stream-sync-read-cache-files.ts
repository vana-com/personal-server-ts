import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type { StreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";

/** A key-specific reader namespace inside the bound writer home. */
export function createStreamSyncReadCacheFiles(
  files: StreamSyncFiles,
  keyCheck: string,
): StreamSyncReadFiles {
  const root = `read-cache/${keyCheck}`;
  const path = (name: string) => {
    if (
      !name ||
      name.split("/").some((part) => !part || part === "." || part === "..")
    ) {
      throw new Error("Invalid read cache path");
    }
    return `${root}/${name}`;
  };
  return {
    write: (name, bytes) => files.write(path(name), bytes),
    read: (name) => files.read(path(name)),
    readChunks: (name) => files.readChunks(path(name)),
    list: async (prefix) =>
      (await files.list(path(prefix))).map((name) =>
        name.slice(root.length + 1),
      ),
    remove: (prefix) => files.remove(path(prefix)),
  };
}
