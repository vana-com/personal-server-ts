/**
 * The stream-sync home of one (owner, network) in a data directory
 * (`stream-sync-homes/<id>/`), held by one process through a lock file.
 *
 * The lock file `stream-sync-homes/<id>.lock` is created exclusively and holds
 * the owner process id and a random token. A second process that finds a live
 * holder gets `null` and runs no stream sync (legacy sync is unaffected).
 *
 * A holder is live only if its process exists AND the lock file was touched
 * within `staleMs`: the holder touches it every `heartbeatMs`. The process
 * check alone is not enough, because after a crash or reboot an unrelated
 * process can own the recorded pid. A file clock needs no per-OS process
 * start-time lookup and no native lock, so it behaves the same on macOS,
 * Linux and Windows. A crashed holder's lock is taken over after `staleMs`.
 *
 * A holder that stalls past `staleMs` (a laptop asleep) can be replaced while
 * it is still running. Each heartbeat therefore confirms the lock file still
 * holds this process's token before it touches the file. On a mismatch the
 * holder is fenced: it never touches the new holder's lock, `onLost` runs
 * once, and every later file operation of its home and seed area rejects with
 * `StreamSyncLockLostError`. The writer persists all of its state through
 * those files, so a fenced writer cannot collect, finish or publish.
 *
 * The staged Desktop seed rows live beside the home (`<id>.seed/`), under the
 * same lock, so a different owner never sees them. The old unbound
 * directories (`stream-sync/`, `stream-sync-seed/`) are not read or migrated.
 */

import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  bindStreamSyncHome,
  type StreamSyncFiles,
  type StreamSyncHome,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";

/** The home's lock was taken over; this process must write nothing more. */
export class StreamSyncLockLostError extends Error {
  constructor() {
    super("stream-sync home lock was taken over by another process");
    this.name = "StreamSyncLockLostError";
  }
}

function fenced(
  files: StreamSyncFiles,
  isLost: () => boolean,
): StreamSyncFiles {
  const check = () => {
    if (isLost()) throw new StreamSyncLockLostError();
  };
  return {
    write: async (path, bytes) => {
      check();
      return files.write(path, bytes);
    },
    read: async (path) => {
      check();
      return files.read(path);
    },
    appendMany: async (entries) => {
      check();
      return files.appendMany(entries);
    },
    sync: async (prefix) => {
      check();
      return files.sync(prefix);
    },
    readChunks: async function* (path) {
      check();
      yield* files.readChunks(path);
    },
    size: async (path) => {
      check();
      return files.size(path);
    },
    list: async (prefix) => {
      check();
      return files.list(prefix);
    },
    remove: async (prefix) => {
      check();
      return files.remove(prefix);
    },
  };
}

export interface FsStreamSyncHome {
  readonly home: StreamSyncHome;
  /** Staging area for this home's Desktop seed rows. */
  readonly seedFiles: StreamSyncFiles;
  /** Release the lock. */
  close(): Promise<void>;
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to someone else.
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** A holder that has not touched its lock for this long is gone. */
export const LOCK_STALE_MS = 60_000;
export const LOCK_HEARTBEAT_MS = 10_000;

export async function openFsStreamSyncHome(input: {
  /** The data directory root; homes live in `<root>/stream-sync-homes/`. */
  readonly root: string;
  readonly ownerAddress: `0x${string}`;
  readonly network: string;
  readonly staleMs?: number;
  readonly heartbeatMs?: number;
  /** Runs once if another process takes this home's lock over. */
  readonly onLost?: () => void;
}): Promise<FsStreamSyncHome | null> {
  const staleMs = input.staleMs ?? LOCK_STALE_MS;
  const heartbeatMs = input.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const homes = join(input.root, "stream-sync-homes");
  await mkdir(homes, { recursive: true });
  let lost = false;
  const isLost = () => lost;
  const home = bindStreamSyncHome({
    ownerAddress: input.ownerAddress,
    network: input.network,
    open: (id) => fenced(createFsStreamSyncFiles(join(homes, id)), isLost),
  });
  const lockPath = join(homes, `${home.id}.lock`);
  const token = randomBytes(8).toString("hex");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await writeFile(lockPath, `${process.pid}\n${token}`, { flag: "wx" });
      const beat = setInterval(() => {
        void (async () => {
          const text = await readFile(lockPath, "utf8").catch(() => "");
          if (text.split("\n")[1] !== token) {
            if (lost) return;
            lost = true;
            clearInterval(beat);
            input.onLost?.();
            return;
          }
          const now = new Date();
          await utimes(lockPath, now, now).catch(() => {});
        })();
      }, heartbeatMs);
      beat.unref();
      return {
        home,
        seedFiles: fenced(
          createFsStreamSyncFiles(join(homes, `${home.id}.seed`)),
          isLost,
        ),
        close: async () => {
          clearInterval(beat);
          // Remove only our own lock: a takeover after a long stall owns it now.
          const text = await readFile(lockPath, "utf8").catch(() => "");
          if (text.split("\n")[1] === token)
            await rm(lockPath, { force: true });
        },
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const holder = Number.parseInt(
      await readFile(lockPath, "utf8").catch(() => ""),
      10,
    );
    const touched = await stat(lockPath)
      .then((s) => s.mtimeMs)
      .catch(() => 0);
    if (
      Number.isInteger(holder) &&
      holder > 0 &&
      alive(holder) &&
      Date.now() - touched < staleMs
    ) {
      return null;
    }
    await rm(lockPath, { force: true });
  }
  return null;
}
