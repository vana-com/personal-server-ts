/**
 * The stream-sync home of one (owner, network) in a data directory
 * (`stream-sync-homes/<id>/`), held by one process through a lock file.
 *
 * The lock file `stream-sync-homes/<id>.lock` is created exclusively and holds
 * the owner process id. A second process that finds a live holder gets `null`
 * and runs no stream sync (legacy sync is unaffected). A lock whose process no
 * longer exists is stale and is taken over. The old unbound directory
 * (`stream-sync/`) is not read or migrated.
 */

import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  bindStreamSyncHome,
  type StreamSyncHome,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";

export interface FsStreamSyncHome {
  readonly home: StreamSyncHome;
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
  const lockPath = join(homes, `${home.id}.lock`);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await writeFile(lockPath, String(process.pid), { flag: "wx" });
      return {
        home,
        close: () => rm(lockPath, { force: true }),
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const holder = Number.parseInt(
      await readFile(lockPath, "utf8").catch(() => ""),
      10,
    );
    if (Number.isInteger(holder) && holder > 0 && alive(holder)) return null;
    await rm(lockPath, { force: true });
  }
  return null;
}
