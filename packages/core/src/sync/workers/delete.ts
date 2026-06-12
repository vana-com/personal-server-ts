import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

export interface DeleteWorkerDeps {
  storage: DataStoragePort;
  storageAdapter: StorageAdapter;
  gateway: GatewayClient;
  signer: ServerSigner;
  serverOwner: string;
  logger: Logger;
}

export interface DeleteScopeRemoteResult {
  scope: string;
  /** Synced versions de-registered at the gateway. */
  filesDeregistered: number;
  /** Ciphertext blobs hard-deleted from storage. */
  blobsDeleted: number;
  errors: Array<{ fileId: string | null; message: string }>;
}

/**
 * Propagate a scope deletion to the authoritative remote stores.
 *
 * NOT SUPPORTED on the DPv2 (DataPoint) gateway: there is no data-point
 * de-registration / deletion endpoint, and the DataPointRecord listing carries
 * no soft-delete (`deletedAt`) flag. Under the legacy file model this worker
 * de-registered each file then hard-deleted its blob; that path is gone with
 * `gateway.getFile` / `gateway.deleteFile` / `signFileDeletion`.
 *
 * Deleting the ciphertext blob alone would be unsafe: the data point would
 * stay listed, so any server syncing it would 404 on download and wedge its
 * sync cursor. So this is a no-op that logs the limitation. Local deletion
 * (index rows + on-disk blobs) still happens via the storage port's
 * `deleteScope`, independent of this worker — only the *remote* copy is left
 * in place until DPv2 grows a deletion API.
 */
export async function deleteScopeRemote(
  deps: DeleteWorkerDeps,
  scope: string,
): Promise<DeleteScopeRemoteResult> {
  const { storage, logger } = deps;

  // Count the synced versions we *would* have de-registered, for the log only.
  let syncedVersions = 0;
  const PAGE_SIZE = 1000;
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const entries = storage.listVersions(scope, { limit: PAGE_SIZE, offset });
    syncedVersions += entries.filter((e) => e.dataPointId !== null).length;
    if (entries.length < PAGE_SIZE) break;
  }

  if (syncedVersions > 0) {
    logger.warn(
      { scope, syncedVersions },
      "Remote scope deletion is not supported on the DPv2 gateway (no " +
        "de-registration endpoint); local data was removed but the remote " +
        "data point(s) and ciphertext blob(s) remain",
    );
  }

  return {
    scope,
    filesDeregistered: 0,
    blobsDeleted: 0,
    errors: [],
  };
}
