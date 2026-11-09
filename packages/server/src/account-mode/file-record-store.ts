/**
 * Durable per-owner mode records for the Node server: one small JSON file per
 * owner under `dir`, outside the data database and the data folder. A save
 * writes a temp file, syncs it and renames it over the record, so a restart
 * sees the old record or the new one, never half of one. A file that cannot be
 * read or does not parse is ignored (and reported): the Account answers again.
 */

import { randomBytes } from "node:crypto";
import { mkdir, open, readdir, readFile, rename } from "node:fs/promises";
import { join } from "node:path";
import {
  parseRecord,
  type AccountModeRecord,
  type ModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";

const OWNER_FILE = /^([a-z0-9_-]{1,100})\.json$/;

export function createFileModeRecordStore(
  dir: string,
  options: { onCorrupt?: (file: string) => void } = {},
): ModeRecordStore {
  return {
    async load() {
      const records = new Map<string, AccountModeRecord>();
      let names: string[];
      try {
        names = await readdir(dir);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return records;
        throw error;
      }
      for (const name of names) {
        const match = OWNER_FILE.exec(name);
        if (!match) continue;
        try {
          const record = parseRecord(
            JSON.parse(await readFile(join(dir, name), "utf8")),
          );
          if (record) records.set(match[1], record);
          else options.onCorrupt?.(name);
        } catch {
          options.onCorrupt?.(name);
        }
      }
      return records;
    },
    async save(owner, record) {
      if (!OWNER_FILE.test(`${owner}.json`)) {
        throw new Error("account mode owner is not a safe file name");
      }
      await mkdir(dir, { recursive: true });
      const tmp = join(dir, `.${owner}.${randomBytes(6).toString("hex")}.tmp`);
      const handle = await open(tmp, "w", 0o600);
      try {
        await handle.writeFile(JSON.stringify(record));
        await handle.sync();
      } finally {
        await handle.close();
      }
      await rename(tmp, join(dir, `${owner}.json`));
      const dirHandle = await open(dir, "r");
      try {
        await dirHandle.sync();
      } finally {
        await dirHandle.close();
      }
    },
  };
}
