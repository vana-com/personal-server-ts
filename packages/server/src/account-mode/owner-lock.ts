/**
 * One owner for one account-mode record folder, held by the kernel.
 *
 * The owner keeps an open SQLite connection to `.mode-owner.lock.db` inside
 * the folder, in rollback-journal mode, with `BEGIN EXCLUSIVE` open and never
 * committed. SQLite takes the file's EXCLUSIVE lock for that transaction, so
 * every other connection, in this process or another, gets `SQLITE_BUSY` at
 * once (no busy timeout). The lock is `fcntl` byte-range locking on macOS and
 * Linux and `LockFileEx` on Windows. The kernel drops it when the process dies,
 * however it dies, and keeps it while the process lives, stopped or not.
 *
 * No clock, process id, host name, token or heartbeat takes part in who owns
 * the folder, so there is no staleness decision and nothing to take over.
 * The lock file is never deleted, renamed or swept: removing it would let a new
 * owner lock a new inode while the old owner still holds the old one.
 *
 * Only this module may ever open the lock file. On Linux and macOS the lock is
 * a POSIX advisory lock, and the kernel drops all of a process's POSIX locks on
 * a file when that process closes any descriptor for it, however the descriptor
 * was opened: a plain `fs.readFileSync` of the lock file, a copy, a backup or a
 * second SQLite library would silently free it while this process still thinks
 * it owns the folder. (Measured with better-sqlite3 on Linux: an `fs` open and
 * close of the lock file frees the lock; opening another file, or a second
 * SQLite connection to the lock file, does not.) So the lock lives in its own
 * file, never in `index.db` or any file other code reads, and a test fails if
 * any other source file names it.
 *
 * Local file systems only. SQLite's own locks are advisory byte-range locks,
 * and network and synced folders do not give them the same meaning. A folder
 * that Linux reports as NFS, SMB/CIFS, AFS, Ceph or similar is refused. A
 * folder that merely syncs through a client (a cloud-storage folder) cannot be
 * detected here and is unsupported too.
 */

import { mkdir, realpath, statfs } from "node:fs/promises";
import { join } from "node:path";
import Database from "better-sqlite3";
import { ModeStoreOwnedError } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const LOCK_FILE = ".mode-owner.lock.db";

/**
 * Two starters that begin at the same instant can each hold a SHARED lock for
 * a moment and both give way, so neither wins. A few short, jittered retries
 * settle that; a lock that a live owner keeps stays busy on every attempt.
 */
const LOCK_ATTEMPTS = 6;

/** Linux `statfs` magic numbers of file systems whose locks are not local. */
const NETWORK_FILESYSTEM_TYPES = new Map<number, string>([
  [0x6969, "NFS"],
  [0x517b, "SMB"],
  [0xff534d42, "CIFS"],
  [0xfe534d42, "SMB2"],
  [0x73757245, "Coda"],
  [0x5346414f, "AFS"],
  [0x6b414653, "AFS"],
  [0x00c36400, "Ceph"],
  [0x564c, "NCP"],
  [0x0bd00bd0, "Lustre"],
  [0x47504653, "GPFS"],
]);

/** Thrown when the record folder is on a file system that cannot hold the lock. */
export class ModeStoreUnsupportedError extends Error {
  constructor(detail: string) {
    super(detail);
    this.name = "ModeStoreUnsupportedError";
  }
}

/** The network file system name for a Linux `statfs` type, or null. */
export function networkFilesystemName(type: number): string | null {
  return NETWORK_FILESYSTEM_TYPES.get(type) ?? null;
}

async function assertLocalFilesystem(dir: string): Promise<void> {
  // Only Linux reports a type that can be told apart here; elsewhere the
  // header's "local file systems only" is the whole guard.
  if (process.platform !== "linux") return;
  let type: number;
  try {
    type = (await statfs(dir)).type;
  } catch {
    return;
  }
  const name = networkFilesystemName(type);
  if (name) {
    throw new ModeStoreUnsupportedError(
      `the account mode record folder is on a ${name} file system; it needs a local file system`,
    );
  }
}

/**
 * Try once to take the exclusive lock. Returns the connection that holds it,
 * or `null` if another connection holds it or is taking it right now.
 */
function tryLock(lockPath: string): Database.Database | null {
  let db: Database.Database | undefined;
  try {
    db = new Database(lockPath, { timeout: 0 });
    // Keep every lock the connection takes, and never wait for one.
    db.pragma("busy_timeout = 0");
    db.pragma("locking_mode = EXCLUSIVE");
    // The first statement takes the EXCLUSIVE lock. It is never committed.
    db.exec("BEGIN EXCLUSIVE");
    const journalMode = db.pragma("journal_mode", { simple: true });
    if (journalMode !== "delete") {
      throw new ModeStoreUnsupportedError(
        `the account mode lock database is in ${String(journalMode)} journal mode; it needs rollback-journal mode`,
      );
    }
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

export interface OwnerLock {
  /** The canonical (symlink-free) folder every file operation must use. */
  readonly dir: string;
  /** Let go of the lock. Safe to call twice. Never touches the lock file. */
  release(): void;
}

/**
 * Take the folder's lock. Rejects with `ModeStoreOwnedError` while another
 * runtime, or another store object in this process, owns the folder.
 */
export async function acquireOwnerLock(dir: string): Promise<OwnerLock> {
  await mkdir(dir, { recursive: true });
  // One folder, one name: an alias or symlink to it contends on the same file.
  const canonical = await realpath(dir);
  await assertLocalFilesystem(canonical);
  const lockPath = join(canonical, LOCK_FILE);
  let db: Database.Database | null = null;
  for (let attempt = 0; attempt < LOCK_ATTEMPTS && !db; attempt += 1) {
    if (attempt > 0) {
      await new Promise((r) => setTimeout(r, 5 + Math.random() * 25));
    }
    db = tryLock(lockPath);
  }
  if (!db) {
    throw new ModeStoreOwnedError(
      "another runtime holds the account mode record folder",
    );
  }
  const held = db;
  return {
    dir: canonical,
    release() {
      if (!held.open) return;
      try {
        held.exec("ROLLBACK");
      } catch {
        // Closing the connection drops the lock either way.
      }
      held.close();
    },
  };
}
