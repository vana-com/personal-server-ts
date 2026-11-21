import { join } from "node:path";
import { sweepAliasSpool } from "@opendatalabs/personal-server-ts-core/localdb";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";

/** What `openAliasSpool` needs of a logger. */
export interface AliasSpoolLogger {
  warn(detail: object, message: string): void;
}

/**
 * The file space for the bodies of windowed alias reads, under `storageRoot`.
 * Its files hold the owner's data in plain text for the length of a response,
 * so only this process's user may enter the directory or read a file. A server
 * that stopped mid-read left files behind: they are removed here, before this
 * process serves a read, since it is the only one that writes to the directory.
 *
 * If the leftovers cannot be removed there is no spool: the failure is logged
 * and the host reads aliases on the capped in-memory path, as main does. A
 * spool that failed to open must not stop the sync that does not need it.
 */
export async function openAliasSpool(
  storageRoot: string,
  logger: AliasSpoolLogger,
): Promise<StreamSyncFiles | undefined> {
  const spool = createFsStreamSyncFiles(join(storageRoot, "alias-spool"), {
    private: true,
  });
  try {
    await sweepAliasSpool(spool);
  } catch (error) {
    logger.warn(
      { error: error instanceof Error ? error.message : String(error) },
      "alias spool could not be opened; large alias reads use the in-memory path",
    );
    return undefined;
  }
  return spool;
}
