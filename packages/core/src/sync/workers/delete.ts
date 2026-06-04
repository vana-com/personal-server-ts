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

// Defensive upper bound on versions enumerated per scope delete.
const MAX_VERSIONS = 10_000;

/**
 * Propagate a scope deletion to the authoritative stores, run BEFORE the local index/blobs are
 * removed. For each synced version (fileId != null):
 *   1. recover the storage URL from the gateway file record (the local index doesn't persist it),
 *      then hard-delete the ciphertext blob (R2) — the only step that actually destroys the data;
 *   2. de-register the file at the gateway with an owner-signed FileDeletion (soft-delete /
 *      availability=deleted), so sync stops re-listing it.
 *
 * Best-effort and idempotent: per-file failures are collected, not thrown, so the caller can still
 * complete the local delete; the gateway treats 409 as success and a missing blob/record is a no-op.
 */
export async function deleteScopeRemote(
  deps: DeleteWorkerDeps,
  scope: string,
): Promise<DeleteScopeRemoteResult> {
  const { storage, storageAdapter, gateway, signer, serverOwner, logger } =
    deps;
  const result: DeleteScopeRemoteResult = {
    scope,
    filesDeregistered: 0,
    blobsDeleted: 0,
    errors: [],
  };

  const entries = storage.listVersions(scope, {
    limit: MAX_VERSIONS,
    offset: 0,
  });
  for (const entry of entries) {
    // Local-only versions (never uploaded) have no remote state to clean up.
    if (!entry.fileId) continue;
    const fileId = entry.fileId;
    try {
      const record = await gateway.getFile(fileId);
      if (record?.url) {
        const deleted = await storageAdapter.delete(record.url);
        if (deleted) result.blobsDeleted += 1;
      }
      const signature = await signer.signFileDeletion({
        ownerAddress: serverOwner as `0x${string}`,
        fileId: fileId as `0x${string}`,
      });
      await gateway.deleteFile({
        fileId,
        ownerAddress: serverOwner,
        signature,
      });
      result.filesDeregistered += 1;
    } catch (err) {
      result.errors.push({ fileId, message: (err as Error).message });
      logger.warn(
        { scope, fileId, error: (err as Error).message },
        "Remote delete failed for file (continuing)",
      );
    }
  }

  logger.info(
    {
      scope,
      filesDeregistered: result.filesDeregistered,
      blobsDeleted: result.blobsDeleted,
      errors: result.errors.length,
    },
    "Remote scope deletion complete",
  );
  return result;
}
