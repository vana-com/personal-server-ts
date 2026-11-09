/**
 * Durable per-owner mode records for the Node server.
 *
 * One small JSON file per owner under `dir`, outside the data database and the
 * data folder, so wiping either does not touch it. A save writes a temp file in
 * the same folder, syncs it, renames it over the record and syncs the folder:
 * a reader (or a restart after a crash) sees the old record or the new one,
 * never half of one.
 *
 * Local file systems only. Network and synced folders are unsupported: the
 * ownership lock below is a kernel lock, and those folders do not keep its
 * meaning. A folder that Linux reports as a network file system is refused
 * (see `owner-lock.ts`); one that only syncs through a client cannot be
 * detected, and is unsupported too.
 *
 * One runtime owns the folder at a time, and the owner is the process that
 * holds the kernel lock of `.mode-owner.lock.db` (see `owner-lock.ts`). The
 * kernel frees it when the process dies and keeps it while the process lives,
 * stopped or not, so nothing here decides that an owner is stale or takes a
 * lock over. A refused runtime has no effect on the folder: `load` and `save`
 * reject until `claim` has succeeded, `claim` runs before `load`, and the
 * temp files of a crashed save are swept only by the runtime that holds the
 * lock. Releasing the lease waits for the saves already running, then lets go
 * of the lock; the lock file is never deleted. Lock files of older builds
 * (`.owner.lock`) are not read, and not removed.
 *
 * Because one runtime owns the folder, its saves run one at a time and `save`
 * is a compare-and-set against the record on disk (see `assertMonotoneWrite`).
 *
 * A record that cannot be read or does not have the expected shape is copied
 * aside (never deleted) and replaced, atomically, by a tombstone (history
 * unknown) for that owner. An unreadable record could have been an On, so the
 * owner must not load as never seen: a tombstone accepts no Off, and an On
 * replaces it with the import owed.
 */

import { randomBytes } from "node:crypto";
import {
  constants,
  copyFile,
  open,
  readdir,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import {
  ModeStoreConflictError,
  ModeStoreOwnedError,
  assertMonotoneWrite,
  tombstoneRecord,
  type DurableModeRecord,
  type ModeRecordStore,
  type ModeStoreLease,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { acquireOwnerLock, type OwnerLock } from "./owner-lock.js";

const OWNER_FILE = /^([a-z0-9_-]{1,100})\.json$/;
const OWNER_NAME = /^[a-z0-9_-]{1,100}$/;
const TEMP_PREFIX = ".tmp-";

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
  // Absent means false; only `true` is ever written.
  if (!(v.historyUnknown === undefined || v.historyUnknown === true))
    return null;
  // Absent means generation 0; a stored generation is a non-negative integer.
  if (!(
    v.generation === undefined ||
    (typeof v.generation === "number" &&
      Number.isSafeInteger(v.generation) &&
      v.generation >= 0)
  ))
    return null;
  return {
    importPending: v.importPending === true,
    switched: v.switched,
    switchedAt: v.switchedAt as number | null,
    cleanOffAt: v.cleanOffAt as number | null,
    offFetchStartMono: v.offFetchStartMono as number | null,
    bootId: v.bootId as string | null,
    ...(v.historyUnknown === true ? { historyUnknown: true as const } : {}),
    ...(typeof v.generation === "number" && v.generation > 0
      ? { generation: v.generation }
      : {}),
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

/** Write `record` whole to a temp file in `dir`, then rename it over `target`. */
async function writeRecordFile(
  dir: string,
  target: string,
  tempName: string,
  record: DurableModeRecord,
): Promise<void> {
  const temp = join(
    dir,
    `${TEMP_PREFIX}${tempName}-${randomBytes(6).toString("hex")}`,
  );
  const handle = await open(temp, "wx", 0o600);
  try {
    await handle.writeFile(JSON.stringify(record), "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, target);
  } catch (error) {
    await unlink(temp).catch(() => {});
    throw error;
  }
}

async function sweepTemps(dir: string): Promise<void> {
  for (const name of await readdir(dir)) {
    // A save that never reached its rename. The old record is intact.
    if (name.startsWith(TEMP_PREFIX))
      await unlink(join(dir, name)).catch(() => {});
  }
}

async function readCurrent(
  dir: string,
  owner: string,
): Promise<DurableModeRecord | null> {
  let text: string;
  try {
    text = await readFile(join(dir, `${owner}.json`), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  const record = parseRecord(text);
  // Unreadable is not "absent": the next load sets it aside and tombstones it.
  if (!record)
    throw new ModeStoreConflictError("the stored record is unreadable");
  return record;
}

/**
 * Keep an unreadable record's bytes under a new name, then replace the record
 * with a tombstone in one rename. A crash between the two steps leaves the
 * unreadable file in place, so the next load does both again: the owner never
 * has no file.
 */
async function tombstoneUnreadable(dir: string, name: string): Promise<void> {
  const record = join(dir, name);
  const aside = join(
    dir,
    `${name}.corrupt-${Date.now()}-${randomBytes(3).toString("hex")}`,
  );
  await copyFile(record, aside, constants.COPYFILE_EXCL);
  await writeRecordFile(
    dir,
    record,
    name.replace(/\.json$/, ""),
    tombstoneRecord(),
  );
}

export function createFileModeRecordStore(
  dir: string,
  options: FileModeRecordStoreOptions = {},
): ModeRecordStore {
  /** Set while this store holds the folder's kernel lock. */
  let held: OwnerLock | null = null;
  let claiming = false;
  // Saves run one at a time, so the read, the check and the rename of one
  // cannot interleave with another's. (One runtime owns the folder, so no
  // other process saves.)
  let saving: Promise<unknown> = Promise.resolve();

  /** The lock; throws unless this store holds it. */
  function owned(): OwnerLock {
    if (!held) {
      throw new ModeStoreOwnedError(
        "this runtime does not hold the account mode record folder",
      );
    }
    return held;
  }

  return {
    async claim() {
      if (held || claiming) {
        throw new ModeStoreOwnedError(
          "this store already holds, or is taking, the account mode record folder",
        );
      }
      claiming = true;
      try {
        const lock = await acquireOwnerLock(dir);
        try {
          // The owner alone clears the temp files of a crashed save.
          await sweepTemps(lock.dir);
        } catch (error) {
          // A failed claim must not strand the folder.
          lock.release();
          throw error;
        }
        held = lock;
        const lease: ModeStoreLease = {
          async release() {
            if (held !== lock) return;
            // Refuse new saves, finish the ones already running, then let go.
            held = null;
            await saving.catch(() => {});
            lock.release();
          },
        };
        return lease;
      } finally {
        claiming = false;
      }
    },

    async load() {
      const { dir: folder } = owned();
      const records = new Map<string, DurableModeRecord>();
      let changed = false;
      for (const name of await readdir(folder)) {
        const match = OWNER_FILE.exec(name);
        if (!match) continue;
        const record = parseRecord(await readFile(join(folder, name), "utf8"));
        if (!record) {
          await tombstoneUnreadable(folder, name);
          changed = true;
          options.onCorrupt?.(name, "unreadable or malformed record");
          records.set(match[1], tombstoneRecord());
          continue;
        }
        records.set(match[1], record);
      }
      if (changed) await syncDirectory(folder);
      return records;
    },

    save(owner, record, expected) {
      let folder: string;
      try {
        folder = owned().dir;
      } catch (error) {
        return Promise.reject(error);
      }
      const run = async (): Promise<void> => {
        if (!OWNER_NAME.test(owner)) {
          throw new Error("account mode record owner is not a safe file name");
        }
        assertMonotoneWrite(await readCurrent(folder, owner), expected, record);
        await writeRecordFile(
          folder,
          join(folder, `${owner}.json`),
          owner,
          record,
        );
        await syncDirectory(folder);
      };
      const result = saving.then(run, run);
      saving = result.catch(() => {});
      return result;
    },
  };
}
