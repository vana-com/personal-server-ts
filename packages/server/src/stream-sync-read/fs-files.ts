/**
 * Filesystem {@link StreamSyncReadFiles} for the full server, under one root
 * directory. A write lands in a temporary file that is synced and renamed
 * over the target, so a reader or a crash never sees half a file.
 *
 * Durability by ownership: the adapter owns the root and everything below it.
 * The root's parent and the directories above belong to whoever provisions
 * the storage root. Opening makes the root exist and syncs the root and its
 * parent; each write syncs every directory on the written file's ancestor
 * chain, from its parent up to and including the root. A directory that only
 * a failed write created is synced when a later write passes through it. The
 * adapter never opens a directory above the root's parent.
 *
 * A relative root is resolved once, at open, so a later change of the working
 * directory moves neither the files nor the sync boundary.
 */

import { createReadStream } from "node:fs";
import { mkdir, open, readdir, readFile, rename, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { StreamSyncReadFiles } from "@opendatalabs/personal-server-ts-core/stream-sync-read";

function inside(root: string, path: string): string {
  const full = join(root, path);
  const rel = relative(root, full);
  if (rel === "" || rel.startsWith("..") || rel.split(sep).includes("..")) {
    throw new Error("path leaves the stream-sync directory");
  }
  return full;
}

async function syncDirectory(path: string): Promise<void> {
  // On Windows, Node opens a directory for reading but fsync calls
  // FlushFileBuffers, which needs write access, so it fails. A resolved write
  // there guarantees the file contents are flushed, but not that the rename
  // is durable, because Node's rename does not use MOVEFILE_WRITE_THROUGH.
  // See #553.
  if (process.platform === "win32") return;
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function createFsStreamSyncReadFiles(
  root: string,
): Promise<StreamSyncReadFiles> {
  const base = resolve(root);
  // Runs on every open, so a root created by an earlier process that crashed
  // before syncing it becomes durable here.
  await mkdir(base, { recursive: true });
  await syncDirectory(base);
  await syncDirectory(dirname(base));
  let counter = 0;
  return {
    async write(path, bytes) {
      const target = inside(base, path);
      const parent = dirname(target);
      await mkdir(parent, { recursive: true });
      const temp = `${target}.tmp-${process.pid}-${counter++}`;
      const handle = await open(temp, "w");
      try {
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(temp, target);
      // Publish the file entry, then every directory entry above it up to
      // and including the root. Existence of a directory is no proof that its
      // entry was synced, so nothing is remembered between attempts. The
      // root's parent was synced when the adapter opened.
      for (let directory = parent; ; directory = dirname(directory)) {
        const rel = relative(base, directory);
        if (rel.startsWith("..") || isAbsolute(rel)) {
          throw new Error("sync walk left the stream-sync directory");
        }
        await syncDirectory(directory);
        if (directory === base) break;
      }
    },
    async read(path) {
      try {
        return new Uint8Array(await readFile(inside(base, path)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    },
    async *readChunks(path) {
      try {
        for await (const chunk of createReadStream(inside(base, path), {
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
      const dir = inside(base, prefix);
      const out: string[] = [];
      try {
        for (const entry of await readdir(dir, {
          recursive: true,
          withFileTypes: true,
        })) {
          if (!entry.isFile() || entry.name.includes(".tmp-")) continue;
          out.push(
            relative(base, join(entry.parentPath, entry.name))
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
      const target = inside(base, prefix);
      await rm(target, { recursive: true, force: true });
      try {
        await syncDirectory(dirname(target));
      } catch (error) {
        // Preserve idempotent removal when even the parent is absent.
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    },
  };
}
