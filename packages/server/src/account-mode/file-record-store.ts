/**
 * Durable per-owner mode records for the Node server.
 *
 * One small JSON file per owner under `dir`, outside the data database and the
 * data folder, so wiping either does not touch it. A save writes a temp file in
 * the same folder, syncs it, renames it over the record and syncs the folder:
 * a reader (or a restart after a crash) sees the old record or the new one,
 * never half of one.
 *
 * One runtime owns the folder at a time. `claim` creates `.owner.lock`
 * (written whole to a temp file, then hard-linked into place, so it is never
 * seen half written) holding the owner's pid, host and a token. A lock whose
 * pid is dead on this same host is taken over; a lock on another host, or with
 * a live pid, or unreadable, is never taken over: the claim fails closed with
 * `ModeStoreOwnedError`. The temp files of a crashed save are swept only by
 * the runtime that holds the lock, so a refused runtime cannot delete the temp
 * file of a save in progress. `save` is a compare-and-set against the record
 * on disk (see `assertMonotoneWrite`).
 *
 * Residual window: two runtimes that race to take over the same stale lock
 * both rename it aside, and the loser puts back what it moved (if the lock path
 * is still free). A third runtime can claim in that gap. The window needs a
 * crashed owner and three processes in the same few milliseconds, and the
 * compare-and-set in `save` still rejects any write that lowers an On.
 *
 * A record that cannot be read or does not have the expected shape is moved
 * aside (never deleted) and its owner loads as never seen, so the module
 * refuses that owner until the Account answers again.
 */

import { randomBytes } from "node:crypto";
import {
  link,
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { hostname } from "node:os";
import { join } from "node:path";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  assertMonotoneWrite,
  type DurableModeRecord,
  type ModeRecordStore,
  type ModeStoreLease,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const OWNER_FILE = /^([a-z0-9_-]{1,100})\.json$/;
const OWNER_NAME = /^[a-z0-9_-]{1,100}$/;
const TEMP_PREFIX = ".tmp-";
const LOCK_FILE = ".owner.lock";

export interface FileModeRecordStoreOptions {
  /** Called with the file name of each record that was moved aside. */
  onCorrupt?: (file: string, reason: string) => void;
}

function numberOrNull(value: unknown): value is number | null {
  return (
    value === null || (typeof value === "number" && Number.isFinite(value))
  );
}

function parseRecord(text: string): DurableModeRecord | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.switched !== "boolean") return null;
  if (!numberOrNull(v.switchedAt)) return null;
  if (!numberOrNull(v.cleanOffAt)) return null;
  if (!numberOrNull(v.offFetchStartMono)) return null;
  if (!(v.bootId === null || typeof v.bootId === "string")) return null;
  // A record written before the import flag existed owes no import.
  if (!(v.importPending === undefined || typeof v.importPending === "boolean"))
    return null;
  return {
    importPending: v.importPending === true,
    switched: v.switched,
    switchedAt: v.switchedAt as number | null,
    cleanOffAt: v.cleanOffAt as number | null,
    offFetchStartMono: v.offFetchStartMono as number | null,
    bootId: v.bootId as string | null,
  };
}

async function syncDirectory(dir: string): Promise<void> {
  const handle = await open(dir, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

interface LockBody {
  pid: number;
  host: string;
  token: string;
}

function parseLock(text: string): LockBody | null {
  try {
    const v = JSON.parse(text) as Partial<LockBody> | null;
    if (
      v &&
      typeof v.pid === "number" &&
      typeof v.host === "string" &&
      typeof v.token === "string"
    ) {
      return { pid: v.pid, host: v.host, token: v.token };
    }
  } catch {
    // fall through
  }
  return null;
}

function processIsGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ESRCH";
  }
}

export function createFileModeRecordStore(
  dir: string,
  options: FileModeRecordStoreOptions = {},
): ModeRecordStore {
  const lockPath = join(dir, LOCK_FILE);
  // Saves run one at a time, so the read, the check and the rename of one
  // cannot interleave with another's.
  let saving: Promise<unknown> = Promise.resolve();

  async function readLock(): Promise<{ text: string; body: LockBody | null }> {
    const text = await readFile(lockPath, "utf8");
    return { text, body: parseLock(text) };
  }

  /** Create the lock whole: write a temp file, then link it into place. */
  async function createLock(token: string): Promise<boolean> {
    const temp = join(dir, `${TEMP_PREFIX}lock-${token}`);
    const handle = await open(temp, "wx", 0o600);
    try {
      await handle.writeFile(
        JSON.stringify({ pid: process.pid, host: hostname(), token }),
        "utf8",
      );
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await link(temp, lockPath);
      return true;
    } catch (error) {
      // ENOENT: the runtime that holds the lock swept our temp file. Same answer.
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "EEXIST" || code === "ENOENT") return false;
      throw error;
    } finally {
      await unlink(temp).catch(() => {});
    }
  }

  /** Move a dead owner's lock aside. False when it is not ours to move. */
  async function takeOverStaleLock(): Promise<boolean> {
    let seen: { text: string; body: LockBody | null };
    try {
      seen = await readLock();
    } catch (error) {
      // Gone already: the next create decides.
      return (error as NodeJS.ErrnoException).code === "ENOENT";
    }
    const { body } = seen;
    if (!body || body.host !== hostname() || !processIsGone(body.pid)) {
      return false;
    }
    const aside = `${lockPath}.stale-${randomBytes(6).toString("hex")}`;
    try {
      await rename(lockPath, aside);
    } catch (error) {
      return (error as NodeJS.ErrnoException).code === "ENOENT";
    }
    const moved = await readFile(aside, "utf8").catch(() => "");
    if (moved !== seen.text) {
      // Someone replaced the lock between our read and our rename: this one
      // is live. Put it back if the path is still free.
      await link(aside, lockPath).catch(() => {});
      await unlink(aside).catch(() => {});
      return false;
    }
    await unlink(aside).catch(() => {});
    return true;
  }

  async function sweepTemps(): Promise<void> {
    for (const name of await readdir(dir)) {
      // A save that never reached its rename. The old record is intact.
      if (name.startsWith(TEMP_PREFIX))
        await unlink(join(dir, name)).catch(() => {});
    }
  }

  async function readCurrent(owner: string): Promise<DurableModeRecord | null> {
    let text: string;
    try {
      text = await readFile(join(dir, `${owner}.json`), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    const record = parseRecord(text);
    // Unreadable is not "absent": the next load moves it aside, then a save
    // can be based on that.
    if (!record)
      throw new ModeStoreConflictError("the stored record is unreadable");
    return record;
  }

  return {
    async claim() {
      await mkdir(dir, { recursive: true });
      const token = randomBytes(8).toString("hex");
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (await createLock(token)) {
          await sweepTemps();
          const lease: ModeStoreLease = {
            async release() {
              const held = await readLock().catch(() => null);
              if (held?.body?.token === token) {
                await unlink(lockPath).catch(() => {});
              }
            },
          };
          return lease;
        }
        if (!(await takeOverStaleLock())) break;
      }
      throw new ModeStoreOwnedError(
        "another runtime holds the account mode record folder",
      );
    },

    async load() {
      await mkdir(dir, { recursive: true });
      const records = new Map<string, DurableModeRecord>();
      for (const name of await readdir(dir)) {
        const match = OWNER_FILE.exec(name);
        if (!match) continue;
        const record = parseRecord(await readFile(join(dir, name), "utf8"));
        if (!record) {
          await rename(
            join(dir, name),
            join(dir, `${name}.corrupt-${Date.now()}`),
          );
          options.onCorrupt?.(name, "unreadable or malformed record");
          continue;
        }
        records.set(match[1], record);
      }
      return records;
    },

    save(owner, record, expected) {
      const run = async (): Promise<void> => {
        if (!OWNER_NAME.test(owner)) {
          throw new Error("account mode record owner is not a safe file name");
        }
        await mkdir(dir, { recursive: true });
        assertMonotoneWrite(await readCurrent(owner), expected, record);
        const temp = join(
          dir,
          `${TEMP_PREFIX}${owner}-${randomBytes(6).toString("hex")}`,
        );
        const handle = await open(temp, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify(record), "utf8");
          await handle.sync();
        } finally {
          await handle.close();
        }
        try {
          await rename(temp, join(dir, `${owner}.json`));
        } catch (error) {
          await unlink(temp).catch(() => {});
          throw error;
        }
        await syncDirectory(dir);
      };
      const result = saving.then(run, run);
      saving = result.catch(() => {});
      return result;
    },
  };
}
