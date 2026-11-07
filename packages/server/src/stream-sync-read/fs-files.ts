/**
 * Filesystem {@link StreamSyncReadFiles} for the full server, under one root
 * directory. A write lands in a temporary file that is synced and renamed
 * over the target, so a reader or a crash never sees half a file.
 *
 * Durability by ownership: the adapter owns the root and everything below it.
 * The root's parent and the directories above belong to whoever provisions
 * the storage root. Opening makes the root exist and syncs the root and its
 * parent; each write syncs every directory from the file's parent up to and
 * including the root. The adapter never opens a directory above the root's
 * parent.
 */

import { createReadStream } from "node:fs";
import { mkdir, open, readdir, readFile, rename, rm } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
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
      const target = inside(root, path);
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
      for (let directory = resolve(parent); ; directory = dirname(directory)) {
        await syncDirectory(directory);
        if (directory === base) break;
      }
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
      const target = inside(root, prefix);
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
