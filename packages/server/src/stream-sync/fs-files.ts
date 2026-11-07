/**
 * `StreamSyncFiles` on the local filesystem (§2.8, Desktop full server).
 *
 * `write` replaces a file atomically (temporary file, fsync, rename, fsync of
 * the directory). `appendMany` does not fsync: it keeps at most `MAX_OPEN`
 * append handles open (least recently used closed first) and remembers which
 * files are dirty. `sync(prefix)` fsyncs the dirty files under the prefix and
 * their directories, then closes their handles. Paths are relative to `root`
 * and may not leave it.
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
import type { FileHandle } from "node:fs/promises";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";

const CHUNK_BYTES = 1024 * 1024;
/** Append handles kept open at once; the spool has up to 256 shards. */
const MAX_OPEN = 64;
/** Files fsynced at once by `sync`; the disk can merge their journal commits. */
const SYNC_PARALLEL = 128;

async function fsyncDir(dir: string): Promise<void> {
  // On Windows, Node opens a directory for reading but fsync calls
  // FlushFileBuffers, which needs write access, so it fails. A resolved write
  // there guarantees the file contents are flushed, but not that the rename
  // is durable, because Node's rename does not use MOVEFILE_WRITE_THROUGH.
  if (process.platform === "win32") return;
  const handle = await open(dir, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

const IDLE_CLOSE_MS = 200;

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

  // Open append handles in least-recently-used order (Map keeps insertion
  // order) and the files appended since their last sync.
  const handles = new Map<string, FileHandle>();
  const dirty = new Set<string>();
  const under = (prefix: string) => (full: string) =>
    full === prefix || full.startsWith(`${prefix}${sep}`);

  async function appendHandle(full: string): Promise<FileHandle> {
    const cached = handles.get(full);
    if (cached) {
      handles.delete(full);
      handles.set(full, cached);
      return cached;
    }
    while (handles.size >= MAX_OPEN) {
      const [oldest, handle] = handles.entries().next().value!;
      handles.delete(oldest);
      await handle.close();
    }
    // The directory exists after the first append of a run; create it only
    // when `open` says it does not.
    let handle: FileHandle;
    try {
      handle = await open(full, "a");
    } catch (error) {
      if (!missing(error)) throw error;
      await mkdir(dirname(full), { recursive: true });
      handle = await open(full, "a");
    }
    handles.set(full, handle);
    return handle;
  }

  // Idle handles are closed so a finished or abandoned writer holds no
  // descriptors; the dirty set still lets `sync` reach their files.
  let appending = 0;
  let idleTimer: NodeJS.Timeout | undefined;
  const armIdleClose = () => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      idleTimer = undefined;
      if (appending > 0) return armIdleClose();
      const open = [...handles.values()];
      handles.clear();
      for (const handle of open) void handle.close().catch(() => {});
    }, IDLE_CLOSE_MS);
    idleTimer.unref();
  };

  /** Close the handles of `full` and of every file under it, and forget them. */
  async function release(full: string): Promise<void> {
    const match = under(full);
    for (const [path, handle] of [...handles]) {
      if (!match(path)) continue;
      handles.delete(path);
      await handle.close();
    }
    for (const path of [...dirty]) if (match(path)) dirty.delete(path);
  }

  async function syncUnder(prefix: string): Promise<void> {
    const match = under(abs(prefix));
    const files = [...dirty].filter(match);
    const folders = new Set<string>();
    let next = 0;
    const worker = async () => {
      while (next < files.length) {
        const full = files[next++]!;
        const cached = handles.get(full);
        if (cached) await cached.sync();
        else {
          const handle = await open(full, "r");
          try {
            await handle.sync();
          } finally {
            await handle.close();
          }
        }
        // New files add entries to their directory and, for new
        // directories, to every ancestor up to the root.
        for (let dir = dirname(full); under(base)(dir); dir = dirname(dir)) {
          if (folders.has(dir)) break;
          folders.add(dir);
        }
      }
    };
    await Promise.all(
      Array.from({ length: Math.min(SYNC_PARALLEL, files.length) }, worker),
    );
    for (const dir of folders) await fsyncDir(dir);
    for (const full of files) dirty.delete(full);
    for (const [path, handle] of [...handles]) {
      if (!match(path)) continue;
      handles.delete(path);
      await handle.close();
    }
  }

  return {
    async write(path, bytes) {
      const full = abs(path);
      // The rename replaces the inode; an append handle would write to the old one.
      await release(full);
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
    async appendMany(entries) {
      appending += 1;
      try {
        for (const { path, bytes } of entries) {
          const full = abs(path);
          const handle = await appendHandle(full);
          await handle.writeFile(bytes);
          dirty.add(full);
        }
      } finally {
        appending -= 1;
        armIdleClose();
      }
    },
    async sync(prefix) {
      appending += 1;
      try {
        await syncUnder(prefix);
      } finally {
        appending -= 1;
        armIdleClose();
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
      await release(abs(prefix));
      await rm(abs(prefix), { recursive: true, force: true });
    },
  };
}
