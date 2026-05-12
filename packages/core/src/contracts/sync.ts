import type { SyncManager, SyncStatus } from "../sync/index.js";
import { contractOk, type ContractResult } from "./http.js";

export interface SyncFileContractInput {
  syncManager: Pick<SyncManager, "trigger"> | null;
  fileId: string;
}

export async function triggerSyncContract(
  syncManager: Pick<SyncManager, "trigger"> | null,
): Promise<ContractResult> {
  if (!syncManager) {
    return contractOk({ status: "disabled", message: "Sync is not enabled" });
  }
  void syncManager.trigger().catch(() => undefined);
  return contractOk({ status: "started", message: "Sync triggered" }, 202);
}

export function getSyncStatusContract(
  syncManager: Pick<SyncManager, "getStatus"> | null,
): ContractResult<SyncStatus> {
  if (!syncManager) {
    return contractOk({
      enabled: false,
      running: false,
      syncing: false,
      lastSync: null,
      lastProcessedTimestamp: null,
      pendingFiles: 0,
      errors: [],
    });
  }
  return contractOk(syncManager.getStatus());
}

export async function syncFileContract(
  input: SyncFileContractInput,
): Promise<ContractResult> {
  if (!input.syncManager) {
    return contractOk({
      fileId: input.fileId,
      status: "disabled",
      message: "Sync is not enabled",
    });
  }
  void input.syncManager.trigger().catch(() => undefined);
  return contractOk({ fileId: input.fileId, status: "started" }, 202);
}
