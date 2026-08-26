import type { Logger } from "../../logger/index.js";
import type {
  DataPointFeedPort,
  DataPointFeedRecord,
  DataStoragePort,
  DeleteDataPort,
  PendingBlobDeletionStore,
} from "../../ports/index.js";
import { computeDataPointId } from "../data-point-id.js";
import {
  deletionTimestamp,
  type ScopeDeletionTracker,
} from "../scope-deletions.js";

export interface DeleteScopeDeps {
  storage: DataStoragePort;
  /** Data owner; absent only on an unconfigured host (no key material). */
  serverOwner?: string;
  /**
   * Remote deletion (gateway tombstone + storage blobs). Absent when the host
   * runs without sync (no owner key material): deletion is then local-only
   * and reported as such, never silently "durable".
   */
  deleteData?: DeleteDataPort | null;
  /** Retry marker for blob deletion that failed after the tombstone landed. */
  pendingBlobDeletions?: PendingBlobDeletionStore;
  /**
   * Read-side deletion memory. A landed tombstone is recorded here so this
   * replica's reads answer 410 immediately, before any sync cycle.
   */
  scopeDeletions?: ScopeDeletionTracker;
  /**
   * Deletion-aware registry lookup, re-read right before any scope-wide blob
   * delete (initial and retry) to notice a scope re-added after its
   * tombstone.
   */
  dataPointFeed?: DataPointFeedPort;
  logger: Logger;
  now?: () => Date;
}

export type DeleteStepStatus = "ok" | "skipped" | "failed";

export interface DeleteScopeStep {
  status: DeleteStepStatus;
  /** Why the step was skipped (e.g. "not-registered", "sync-disabled"). */
  reason?: string;
  /** Error message when status is "failed". */
  error?: string;
}

export interface DeleteScopeResult {
  scope: string;
  /** DPv2 identity: keccak256(abi.encode(owner, scope)); null without an owner. */
  dataPointId: string | null;
  /**
   * True once the gateway holds the tombstone (or never held the point at
   * all): sync can no longer resurrect the scope on any replica. False when
   * only the local copy was removed.
   */
  durable: boolean;
  steps: {
    gateway: DeleteScopeStep & {
      /** Tombstone version at the gateway (previous current + 1). */
      version?: string;
      deletedAt?: string | null;
    };
    storage: DeleteScopeStep & { blobsDeleted?: number | null };
    local: DeleteScopeStep & { deletedCount?: number };
  };
  /**
   * True when the tombstone landed but blob deletion did not: a retry marker
   * was recorded and a later sync cycle finishes it.
   */
  pendingBlobDeletion: boolean;
}

/**
 * Durable scope deletion, in the only order that cannot resurrect data:
 *
 *   1. gateway tombstone  (owner-signed AddData at current + 1; the fact)
 *   2. storage blobs      (every version's ciphertext)
 *   3. local copy         (index rows + files + sidecars)
 *
 * The local delete never runs before the gateway has acknowledged: until the
 * registry says "deleted", the next sync cycle would re-pull the point from
 * the still-live row. A storage failure after step 1 is reported AND leaves
 * a retry marker; it does not block step 3 because the tombstone already
 * makes the deletion stick.
 *
 * Not serialised here: the sync manager runs this under the same lock as its
 * upload/download cycles so a delete cannot interleave with an upload of the
 * same scope on this replica (see engine/sync-manager.ts). Uploads racing on
 * another replica are handled by the upload worker's deletion guard and the
 * download worker's reconcile.
 *
 * Step 2 is scope-wide (every version's ciphertext under one storage prefix),
 * so a re-add another replica lands between step 1 and step 2 would lose its
 * blob to it. The registry is therefore re-read immediately before the blob
 * delete: a live row means a re-add won the race and the blobs are left alone
 * (the pre-tombstone ciphertext stays, owner-decryptable only, until the next
 * delete). The residual window is one storage round-trip; closing it fully
 * needs a version-bounded delete on the storage side.
 */
export async function deleteScope(
  deps: DeleteScopeDeps,
  scope: string,
): Promise<DeleteScopeResult> {
  const { storage, deleteData, pendingBlobDeletions, scopeDeletions, logger } =
    deps;
  const now = deps.now ?? (() => new Date());
  const dataPointId = deps.serverOwner
    ? computeDataPointId(deps.serverOwner, scope)
    : null;
  const result: DeleteScopeResult = {
    scope,
    dataPointId,
    durable: false,
    steps: {
      gateway: { status: "skipped", reason: "sync-disabled" },
      storage: { status: "skipped", reason: "sync-disabled" },
      local: { status: "skipped" },
    },
    pendingBlobDeletion: false,
  };

  if (deleteData) {
    // 1. Gateway tombstone: the durable fact. Nothing else happens if it
    // fails, so the owner gets a clear "nothing was deleted" instead of a
    // local delete that sync silently undoes.
    try {
      const outcome = await deleteData.tombstone(scope);
      if (outcome.status === "not-registered") {
        result.steps.gateway = { status: "skipped", reason: "not-registered" };
      } else {
        result.steps.gateway = {
          status: "ok",
          ...(outcome.status === "already-deleted" && {
            reason: "already-deleted",
          }),
          version: outcome.version,
          deletedAt: outcome.deletedAt,
        };
        // Reads on this replica must refuse the scope from this point on,
        // without waiting for the feed to echo the tombstone back. A missing
        // `deletedAt` (gateway did not echo one) is taken as "now": later
        // than any local entry the deletion covers, so nothing slips through.
        scopeDeletions?.markDeleted(
          scope,
          outcome.deletedAt ?? now().toISOString(),
          "local-delete",
        );
      }
      result.durable = true;
    } catch (err) {
      const message = errorMessage(err);
      result.steps.gateway = { status: "failed", error: message };
      result.steps.storage = { status: "skipped", reason: "gateway-failed" };
      result.steps.local = { status: "skipped", reason: "gateway-failed" };
      logger.error(
        { scope, dataPointId, error: message },
        "Gateway tombstone failed; scope NOT deleted (local copy kept so sync cannot resurrect a half-deleted scope)",
      );
      return result;
    }

    // 2. Storage blobs. Best-effort once the tombstone exists: a failure is
    // reported and remembered for a later cycle, never hidden. Guarded by a
    // registry re-read so a concurrent re-add keeps its ciphertext.
    const registry = await registryState(deps, scope);
    if (registry.status === "live") {
      result.steps.storage = { status: "skipped", reason: "re-added" };
      await pendingBlobDeletions?.remove(scope);
      logger.warn(
        {
          scope,
          dataPointId: registry.record.id,
          version: registry.record.expectedVersion,
        },
        "Scope was re-added after its tombstone; leaving storage blobs so the live version's ciphertext survives",
      );
    } else {
      try {
        if (registry.status === "unknown") {
          // Cannot tell whether a re-add landed: do not delete on a guess.
          // The retry marker re-checks on a later cycle.
          throw registry.error;
        }
        const outcome = await deleteData.deleteBlobs(scope);
        result.steps.storage = {
          status: "ok",
          blobsDeleted: outcome.blobsDeleted,
        };
        await pendingBlobDeletions?.remove(scope);
      } catch (err) {
        const message = errorMessage(err);
        result.steps.storage = { status: "failed", error: message };
        if (pendingBlobDeletions) {
          try {
            await pendingBlobDeletions.add(scope);
            result.pendingBlobDeletion = true;
          } catch (markerErr) {
            logger.error(
              { scope, error: errorMessage(markerErr) },
              "Could not record pending blob deletion marker",
            );
          }
        }
        logger.warn(
          {
            scope,
            error: message,
            pendingBlobDeletion: result.pendingBlobDeletion,
          },
          "Storage blob deletion failed after gateway tombstone; will retry",
        );
      }
    }
  }

  // 3. Local copy. Safe now: the registry row is a tombstone (or the point
  // was never registered / sync is off), so nothing can re-pull it.
  try {
    const deletedCount = await storage.deleteScope(scope);
    result.steps.local = { status: "ok", deletedCount };
  } catch (err) {
    const message = errorMessage(err);
    result.steps.local = { status: "failed", error: message };
    logger.error({ scope, error: message }, "Local scope deletion failed");
  }

  logger.info(
    {
      scope,
      dataPointId,
      durable: result.durable,
      gateway: result.steps.gateway.status,
      storage: result.steps.storage.status,
      local: result.steps.local.status,
    },
    "Scope deletion finished",
  );
  return result;
}

export interface RetryPendingBlobDeletionsResult {
  completed: string[];
  /** Markers dropped because the scope was re-added after its tombstone. */
  superseded: string[];
  failed: Array<{ scope: string; error: string }>;
}

/**
 * Finish blob deletions whose tombstone landed but whose storage DELETE did
 * not. Runs at the start of every sync cycle; each scope is retried until
 * storage acknowledges (2xx or 404), then the marker is cleared.
 *
 * A marker can outlive its tombstone: if the owner re-added the scope on any
 * replica in the meantime, the registry row is live again and the storage
 * prefix now holds the re-add's ciphertext. Deleting the prefix would leave a
 * live row whose bytes 404 for every reader, so when the feed shows the scope
 * live the marker is dropped instead and the pre-tombstone ciphertext stays
 * (owner-decryptable only; the next delete of the scope removes it).
 */
export async function retryPendingBlobDeletions(
  deps: Pick<
    DeleteScopeDeps,
    | "deleteData"
    | "pendingBlobDeletions"
    | "dataPointFeed"
    | "serverOwner"
    | "logger"
  >,
): Promise<RetryPendingBlobDeletionsResult> {
  const { deleteData, pendingBlobDeletions, dataPointFeed, serverOwner } = deps;
  const { logger } = deps;
  const result: RetryPendingBlobDeletionsResult = {
    completed: [],
    superseded: [],
    failed: [],
  };
  if (!deleteData || !pendingBlobDeletions) return result;

  const scopes = await pendingBlobDeletions.list();
  for (const scope of scopes) {
    try {
      const registry = await registryState(
        { dataPointFeed, serverOwner },
        scope,
      );
      if (registry.status === "unknown") throw registry.error;
      if (registry.status === "live") {
        await pendingBlobDeletions.remove(scope);
        result.superseded.push(scope);
        logger.warn(
          {
            scope,
            dataPointId: registry.record.id,
            version: registry.record.expectedVersion,
          },
          "Scope was re-added after its tombstone; dropping the pending blob deletion so the live version's ciphertext survives",
        );
        continue;
      }
      await deleteData.deleteBlobs(scope);
      await pendingBlobDeletions.remove(scope);
      result.completed.push(scope);
      logger.info({ scope }, "Completed pending blob deletion");
    } catch (err) {
      const message = errorMessage(err);
      result.failed.push({ scope, error: message });
      logger.warn(
        { scope, error: message },
        "Pending blob deletion failed again",
      );
    }
  }
  return result;
}

type RegistryState =
  | { status: "live"; record: DataPointFeedRecord }
  | { status: "deleted-or-absent" }
  | { status: "unknown"; error: Error };

/**
 * What the registry currently says about `scope`, read right before a
 * scope-wide blob delete. "live" means a re-add landed after the tombstone
 * and the storage prefix now holds ciphertext that must survive. Without a
 * feed or owner wired there is nothing to ask, so the delete proceeds.
 */
async function registryState(
  deps: Pick<DeleteScopeDeps, "dataPointFeed" | "serverOwner">,
  scope: string,
): Promise<RegistryState> {
  if (!deps.dataPointFeed || !deps.serverOwner) {
    return { status: "deleted-or-absent" };
  }
  let record: DataPointFeedRecord | null;
  try {
    record = await deps.dataPointFeed.getDataPoint({
      ownerAddress: deps.serverOwner,
      scope,
    });
  } catch (err) {
    return {
      status: "unknown",
      error: err instanceof Error ? err : new Error(String(err)),
    };
  }
  if (record !== null && deletionTimestamp(record) === null) {
    return { status: "live", record };
  }
  return { status: "deleted-or-absent" };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
