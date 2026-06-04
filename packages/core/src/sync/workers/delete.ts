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

// Page size for draining all versions of a scope from the local index (no silent truncation).
const PAGE_SIZE = 1000;

/**
 * Propagate a scope deletion to the authoritative stores, run BEFORE the local index/blobs are
 * removed. For each synced version (fileId != null):
 *   1. capture the storage URL from the gateway file record (the local index doesn't persist it);
 *   2. de-register the file at the gateway with an owner-signed FileDeletion (soft-delete /
 *      availability=deleted), so sync stops re-listing it;
 *   3. hard-delete the ciphertext blob (R2) — the actual data destruction.
 *
 * De-register BEFORE deleting the blob on purpose: the worst partial failure is then an orphaned but
 * *unlisted* blob (recoverable by GC), never a still-listed file with a missing blob — the latter
 * would make the download worker throw and wedge the sync cursor indefinitely.
 *
 * Best-effort and idempotent: all versions are paginated (no truncation), per-file failures are
 * collected not thrown so the caller can still complete the local delete, the gateway treats 409 as
 * success, and a missing blob/record is a no-op.
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

  for (let offset = 0; ; offset += PAGE_SIZE) {
    const entries = storage.listVersions(scope, { limit: PAGE_SIZE, offset });
    for (const entry of entries) {
      // Local-only versions (never uploaded) have no remote state to clean up.
      if (!entry.fileId) continue;
      const fileId = entry.fileId;
      try {
        // 1. Capture the storage URL before de-registering (read-only; works regardless of state).
        const record = await gateway.getFile(fileId);
        // 2. De-register first → hides the file from the default list, so a subsequent blob-delete
        //    failure can't strand a listed-but-blobless file (which would wedge the cursor).
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
        // 3. Destroy the ciphertext blob.
        if (record?.url) {
          const deleted = await storageAdapter.delete(record.url);
          if (deleted) result.blobsDeleted += 1;
        }
      } catch (err) {
        result.errors.push({ fileId, message: (err as Error).message });
        logger.warn(
          { scope, fileId, error: (err as Error).message },
          "Remote delete failed for file (continuing)",
        );
      }
    }
    if (entries.length < PAGE_SIZE) break;
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
