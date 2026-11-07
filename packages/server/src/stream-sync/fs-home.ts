/**
 * The stream-sync home of one (owner, network) in a data directory
 * (`stream-sync-homes/<id>/`), held by one process for as long as it lives.
 *
 * The holder owns an exclusive SQLite lock on `stream-sync-homes/<id>.lock.sqlite`
 * (`PRAGMA locking_mode=EXCLUSIVE` plus one write: SQLite then keeps the
 * file's EXCLUSIVE lock until the connection closes). The kernel holds that
 * lock: it is `fcntl` byte-range locking on macOS and Linux and `LockFileEx`
 * on Windows, and the kernel drops it when the process dies, however it dies.
 * No other process can take it while the holder lives, stalled or not, so no
 * clock, process id, token or heartbeat takes part in who holds the home. A
 * second process gets `SQLITE_BUSY` at once (no busy timeout) and gets `null`:
 * it runs no stream sync, and legacy sync is unaffected.
 *
 * The lock file is never deleted: removing it would let a new opener lock a
 * new inode while the old holder still holds the old one. It lives beside the
 * home directory, not inside it, so the lock outlives any cleanup of the home.
 * The lock needs a local file system: SQLite warns that advisory locks on
 * network file systems are not reliable.
 *
 * The staged Desktop seed rows live beside the home (`<id>.seed/`), under the
 * same lock, so a different owner never sees them. The old unbound
 * directories (`stream-sync/`, `stream-sync-seed/`) and the old `<id>.lock`
 * lease files are not read or migrated.
 */

import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import Database from "better-sqlite3";
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
  /** Release the lock. Safe to call twice. */
  close(): Promise<void>;
}

/**
 * Try once to take the exclusive lock. Returns the connection that holds it,
 * or `null` if another connection holds it or is taking it right now.
 */
function tryLock(lockPath: string): Database.Database | null {
  let db: Database.Database | undefined;
  try {
    db = new Database(lockPath, { timeout: 0 });
    // Set before the first read: keep every lock the connection takes.
    db.pragma("locking_mode=EXCLUSIVE");
    // The write takes the EXCLUSIVE lock; EXCLUSIVE mode then never gives it up.
    db.exec("BEGIN EXCLUSIVE; PRAGMA user_version = 1; COMMIT;");
    return db;
  } catch (error) {
    try {
      db?.close();
    } catch {
      // Already failing; the original error decides.
    }
    const code = (error as { code?: string }).code;
    if (code === "SQLITE_BUSY" || code === "SQLITE_LOCKED") return null;
    throw error;
  }
}

/**
 * Two openers that start at the same instant can each hold a SHARED lock and
 * both give way, so neither wins. A few short, jittered retries settle that;
 * a lock that a live holder keeps stays busy on every attempt.
 */
const LOCK_ATTEMPTS = 6;

export async function openFsStreamSyncHome(input: {
  /** The data directory root; homes live in `<root>/stream-sync-homes/`. */
  readonly root: string;
  readonly ownerAddress: `0x${string}`;
  readonly network: string;
}): Promise<FsStreamSyncHome | null> {
  const homes = join(input.root, "stream-sync-homes");
  await mkdir(homes, { recursive: true });
  const home = bindStreamSyncHome({
    ownerAddress: input.ownerAddress,
    network: input.network,
    open: (id) => createFsStreamSyncFiles(join(homes, id)),
  });
  const lockPath = join(homes, `${home.id}.lock.sqlite`);
  let lock: Database.Database | null = null;
  for (let attempt = 0; attempt < LOCK_ATTEMPTS && !lock; attempt += 1) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 5 + Math.random() * 25));
    }
    lock = tryLock(lockPath);
  }
  if (!lock) return null;
  const held = lock;
  return {
    home,
    seedFiles: createFsStreamSyncFiles(join(homes, `${home.id}.seed`)),
    close: async () => {
      if (held.open) held.close();
    },
  };
}
