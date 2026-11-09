/**
 * Durable per-owner mode records for the Node server.
 *
 * One small JSON file per owner under `dir`, outside the data database and the
 * data folder, so wiping either does not touch it. A save writes a temp file in
 * the same folder, syncs it, renames it over the record and syncs the folder:
 * a reader (or a restart after a crash) sees the old record or the new one,
 * never half of one.
 *
 * A record that cannot be read or does not have the expected shape is moved
 * aside (never deleted) and its owner loads as never seen, so the module
 * refuses that owner until the Account answers again.
 */

import { randomBytes } from "node:crypto";
import {
  mkdir,
  open,
  readdir,
  readFile,
  rename,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import type {
  ModeRecordStore,
  DurableModeRecord,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

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
  return {
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

export function createFileModeRecordStore(
  dir: string,
  options: FileModeRecordStoreOptions = {},
): ModeRecordStore {
  // Temp files from a crashed save are removed on this store's first load
  // only: a later load must not delete the temp file of a save in progress
  // (here, or in another process on the same folder).
  let sweptTemps = false;
  return {
    async load() {
      await mkdir(dir, { recursive: true });
      const records = new Map<string, DurableModeRecord>();
      const sweep = !sweptTemps;
      sweptTemps = true;
      for (const name of await readdir(dir)) {
        if (name.startsWith(TEMP_PREFIX)) {
          // A save that never reached its rename. The old record is intact.
          if (sweep) await unlink(join(dir, name)).catch(() => {});
          continue;
        }
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

    async save(owner, record) {
      if (!OWNER_NAME.test(owner)) {
        throw new Error("account mode record owner is not a safe file name");
      }
      await mkdir(dir, { recursive: true });
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
    },
  };
}
