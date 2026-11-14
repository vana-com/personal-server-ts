import type { SyncManager, SyncStatus } from "../sync/index.js";
import { contractOk, type ContractResult } from "./http.js";

export interface SyncFileContractInput {
  syncManager: Pick<SyncManager, "trigger"> | null;
  fileId: string;
}

export interface TriggerSyncOptions {
  /**
   * The caller is a signal (a window came back, the network returned), not a
   * request to sync. The manager reads the registry's change marker and runs a
   * cycle only when it moved (`SyncManager.requestPull`).
   */
  whenChanged?: boolean;
}

export async function triggerSyncContract(
  syncManager:
    | (Pick<SyncManager, "trigger"> & Partial<Pick<SyncManager, "requestPull">>)
    | null,
  options: TriggerSyncOptions = {},
): Promise<ContractResult> {
  if (!syncManager) {
    return contractOk({ status: "disabled", message: "Sync is not enabled" });
  }
  // A manager that cannot pull on a signal answers it with a full cycle.
  const start =
    options.whenChanged && syncManager.requestPull
      ? syncManager.requestPull()
      : syncManager.trigger();
  void start.catch(() => undefined);
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
      hydratedScopes: [],
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
