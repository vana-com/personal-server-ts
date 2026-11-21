import { join } from "node:path";
import { sweepAliasSpool } from "@opendatalabs/personal-server-ts-core/localdb";
import type { StreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";

/**
 * The file space for the bodies of windowed alias reads, under `storageRoot`.
 * Its files hold the owner's data in plain text for the length of a response,
 * so only this process's user may enter the directory or read a file. A server
 * that stopped mid-read left files behind: they are removed here, before this
 * process serves a read, since it is the only one that writes to the directory.
 */
export async function openAliasSpool(
  storageRoot: string,
): Promise<StreamSyncFiles> {
  const spool = createFsStreamSyncFiles(join(storageRoot, "alias-spool"), {
    private: true,
  });
  await sweepAliasSpool(spool);
  return spool;
}
