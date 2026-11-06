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
}): Promise<FsStreamSyncHome | null> {
  const staleMs = input.staleMs ?? LOCK_STALE_MS;
  const heartbeatMs = input.heartbeatMs ?? LOCK_HEARTBEAT_MS;
  const homes = join(input.root, "stream-sync-homes");
  await mkdir(homes, { recursive: true });
  const home = bindStreamSyncHome({
    ownerAddress: input.ownerAddress,
    network: input.network,
    open: (id) => createFsStreamSyncFiles(join(homes, id)),
  });
  const lockPath = join(homes, `${home.id}.lock`);
  const token = randomBytes(8).toString("hex");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await writeFile(lockPath, `${process.pid}\n${token}`, { flag: "wx" });
      const beat = setInterval(() => {
        const now = new Date();
        void utimes(lockPath, now, now).catch(() => {});
      }, heartbeatMs);
      beat.unref();
      return {
        home,
        seedFiles: createFsStreamSyncFiles(join(homes, `${home.id}.seed`)),
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
