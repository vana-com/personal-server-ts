import type { Logger } from "../../logger/index.js";
import type {
  DataPointFeedPort,
  DataPointFeedRecord,
  DataStoragePort,
  DeleteDataPort,
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "../../ports/index.js";
import { computeDataPointId } from "../data-point-id.js";
import {
  deletionTimestamp,
  isEntryCoveredByTombstone,
  tombstoneVersion,
  type ScopeDeletionTracker,
} from "../scope-deletions.js";

/**
 * Exact blob deletes sent per pass. vana-storage allows 30 DELETE requests
 * per owner per 60 seconds. A DELETE request's own pass and the next sync
 * cycle's retry pass can land inside one window, so each pass sends at most
 * half the budget; whatever does not fit is queued and drained on later
 * cycles, and a 429 simply re-queues its key.
 */
export const BLOB_DELETE_BATCH_SIZE = 15;

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
  /** Exact-key retry markers for blob deletes that did not finish. */
  pendingBlobDeletions?: PendingBlobDeletionStore;
  /**
   * Read-side deletion memory. A landed tombstone is recorded here so this
   * replica's reads answer 410 immediately, before any sync cycle.
   */
  scopeDeletions?: ScopeDeletionTracker;
  /**
   * Deletion-aware registry lookup, re-read right after the tombstone attempt
   * (a registration racing a "not-registered" answer) and by the retry to
   * expand a marker whose tombstone version was not known.
   */
  dataPointFeed?: DataPointFeedPort;
  logger: Logger;
  now?: () => Date;
}

export type DeleteStepStatus = "ok" | "skipped" | "failed" | "deferred";

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
    /**
     * Storage step. "ok": every blob key the tombstone covers is gone.
     * "deferred": some keys are queued for later passes (rate-limit batch,
     * or a tombstone version the gateway did not report). "failed": at
     * least one delete errored; the failed keys are queued too.
     */
    storage: DeleteScopeStep & {
      blobsDeleted?: number;
      blobsMissing?: number;
      blobsPending?: number;
    };
    local: DeleteScopeStep & { deletedCount?: number };
  };
  /**
   * True when the tombstone landed but blob deletion did not finish: exact
   * retry markers were recorded and later sync cycles finish them.
   */
  pendingBlobDeletion: boolean;
}

/**
 * The exact storage keys a tombstone covers for `scope`, as version strings:
 *   - every registry version up to and including the tombstone's (versions
 *     are a dense, strictly increasing integer sequence per scope, and an
 *     absent key answers 404, so the range is exact and complete across
 *     replicas without listing storage);
 *   - plus the version of every local entry the tombstone covers, whatever
 *     its number: an upload that landed under a key the registry never saw
 *     (crashed before registering, or rebased later) is still deleted data.
 * A re-add registered after the tombstone lives under a higher version key,
 * so it is never in this set and survives by construction. With no tombstone
 * version (never registered, or the gateway did not report one) only the
 * local entries' keys can be enumerated.
 */
export function planBlobDeletions(
  storage: Pick<DataStoragePort, "listVersions">,
  scope: string,
  tombstoneVersionValue: string | null,
): string[] {
  const keys = new Set<string>();
  const tombstone = { version: tombstoneVersionValue };
  const PAGE_SIZE = 500;
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const entries = storage.listVersions(scope, { limit: PAGE_SIZE, offset });
    for (const entry of entries) {
      if (isEntryCoveredByTombstone(entry, tombstone)) {
        keys.add(String(entry.version));
      }
    }
    if (entries.length < PAGE_SIZE) break;
  }
  if (tombstoneVersionValue !== null) {
    const last = BigInt(tombstoneVersionValue);
    for (let version = 1n; version <= last; version += 1n) {
      keys.add(version.toString());
    }
  }
  return [...keys].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
}

/**
 * Durable scope deletion, in the only order that cannot resurrect data:
 *
 *   1. gateway tombstone  (owner-signed AddData at current + 1; the fact)
 *   2. storage blobs      (exact keys of every version the tombstone covers)
 *   3. local copy         (index rows + files + sidecars)
 *
 * The local delete never runs before the gateway has acknowledged: until the
 * registry says "deleted", the next sync cycle would re-pull the point from
 * the still-live row. Step 2 deletes exact per-version keys, never the scope
 * prefix, so a re-add another replica lands at any time keeps its ciphertext
 * (it is registered above the tombstone version and stored under that key).
 * Keys that could not be deleted in this pass are queued as exact retry
 * markers; step 3 does not wait for them because the tombstone already makes
 * the deletion stick.
 *
 * Not serialised here: the sync manager runs this under the same lock as its
 * upload/download cycles so a delete cannot interleave with an upload of the
 * same scope on this replica (see engine/sync-manager.ts). Uploads racing on
 * another replica are handled by the upload worker's deletion guard and the
 * download worker's reconcile.
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
    let tombstoneVersionValue: string | null = null;
    let tombstoneKnown = false;
    try {
      let outcome = await deleteData.tombstone(scope);
      if (outcome.status === "not-registered") {
        // "Nothing to tombstone" is only durable if the registry still has
        // no row. A registration racing our lookup would otherwise survive
        // the local delete and sync would restore the scope: re-read, and
        // tombstone the row that appeared. If it keeps appearing, or the
        // registry cannot be asked, refuse rather than delete on a guess.
        let registry = await registryState(deps, scope);
        if (registry.status === "live") {
          outcome = await deleteData.tombstone(scope);
          registry = await registryState(deps, scope);
        }
        if (
          outcome.status === "not-registered" &&
          registry.status !== "deleted-or-absent"
        ) {
          throw registry.status === "unknown"
            ? registry.error
            : new Error(
                "Scope was registered concurrently while it was being deleted; retry the delete",
              );
        }
      }
      if (outcome.status === "not-registered") {
        result.steps.gateway = { status: "skipped", reason: "not-registered" };
      } else {
        tombstoneKnown = true;
        tombstoneVersionValue = tombstoneVersion({
          expectedVersion: outcome.version,
        });
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
          {
            deletedAt: outcome.deletedAt ?? now().toISOString(),
            version: outcome.version,
          },
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

    // 2. Storage blobs: exact keys, one pass of at most a batch, the rest
    // queued. A tombstone whose version the gateway did not report cannot be
    // expanded into registry keys yet; a version-less marker asks the retry
    // to expand it once the registry answers.
    const keys = planBlobDeletions(storage, scope, tombstoneVersionValue);
    const expansionMarker: PendingBlobDeletion[] =
      tombstoneKnown && tombstoneVersionValue === null
        ? [{ scope, version: null }]
        : [];
    const storageStep = await deleteBlobKeys(
      { deleteData, pendingBlobDeletions, logger },
      scope,
      keys,
      expansionMarker,
    );
    result.steps.storage = storageStep.step;
    result.pendingBlobDeletion = storageStep.pending > 0;
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

/**
 * Delete one pass worth of exact keys and reconcile the retry markers:
 * completed keys (deleted or already absent) leave the store, failed and
 * not-yet-attempted keys enter it.
 */
async function deleteBlobKeys(
  deps: Pick<DeleteScopeDeps, "deleteData" | "pendingBlobDeletions" | "logger">,
  scope: string,
  keys: string[],
  extraMarkers: PendingBlobDeletion[],
): Promise<{ step: DeleteScopeResult["steps"]["storage"]; pending: number }> {
  const { deleteData, pendingBlobDeletions, logger } = deps;
  const batch = keys.slice(0, BLOB_DELETE_BATCH_SIZE);
  const deferred = keys.slice(BLOB_DELETE_BATCH_SIZE);
  let outcome: Awaited<ReturnType<DeleteDataPort["deleteBlobVersions"]>>;
  try {
    outcome =
      batch.length > 0 && deleteData
        ? await deleteData.deleteBlobVersions(scope, batch)
        : { deleted: [], missing: [], failed: [] };
  } catch (err) {
    // The port reports per-key failures; a thrown error means none of the
    // batch can be trusted as done.
    outcome = {
      deleted: [],
      missing: [],
      failed: batch.map((version) => ({ version, error: errorMessage(err) })),
    };
  }
  const completed = [...outcome.deleted, ...outcome.missing].map(
    (version): PendingBlobDeletion => ({ scope, version }),
  );
  const remaining: PendingBlobDeletion[] = [
    ...outcome.failed.map(({ version }) => ({ scope, version })),
    ...deferred.map((version) => ({ scope, version })),
    ...extraMarkers,
  ];
  let recorded = remaining.length;
  if (pendingBlobDeletions) {
    try {
      if (completed.length > 0) await pendingBlobDeletions.remove(completed);
      if (remaining.length > 0) await pendingBlobDeletions.add(remaining);
    } catch (markerErr) {
      recorded = 0;
      logger.error(
        { scope, error: errorMessage(markerErr), keys: remaining.length },
        "Could not record pending blob deletion markers",
      );
    }
  } else if (remaining.length > 0) {
    recorded = 0;
    logger.error(
      { scope, keys: remaining.length },
      "Blob deletions left unfinished with no marker store to retry them",
    );
  }
  const counts = {
    blobsDeleted: outcome.deleted.length,
    blobsMissing: outcome.missing.length,
    blobsPending: remaining.length,
  };
  if (outcome.failed.length > 0) {
    const first = outcome.failed[0];
    logger.warn(
      {
        scope,
        failed: outcome.failed.length,
        pending: recorded,
        error: first.error,
      },
      "Storage blob deletion failed for some keys after gateway tombstone; will retry",
    );
    return {
      step: {
        status: "failed",
        error: `${outcome.failed.length} blob delete(s) failed: ${first.error}`,
        ...counts,
      },
      pending: recorded,
    };
  }
  if (remaining.length > 0) {
    logger.info(
      { scope, ...counts },
      "Storage blob deletion continues on later sync cycles (rate-limited batch)",
    );
    return { step: { status: "deferred", ...counts }, pending: recorded };
  }
  return { step: { status: "ok", ...counts }, pending: 0 };
}

export interface RetryPendingBlobDeletionsResult {
  /** Exact keys finished this pass (deleted, or already absent). */
  completed: PendingBlobDeletion[];
  /** Version-less markers dropped because the scope is live again. */
  superseded: string[];
  failed: Array<{ scope: string; version: string | null; error: string }>;
  /** Keys still queued after this pass. */
  remaining: number;
}

/**
 * Finish blob deletions whose tombstone landed but whose storage deletes did
 * not: one batch of exact keys per sync cycle, each key retried until storage
 * acknowledges (2xx or 404), then cleared. Version-less markers (the gateway
 * did not report a tombstone version at delete time) are expanded into exact
 * keys from the registry first; if the registry shows the scope live again
 * the old tombstone's version is unknowable, so the marker is dropped and the
 * pre-tombstone ciphertext stays (owner-decryptable only) until the next
 * delete of that scope.
 */
export async function retryPendingBlobDeletions(
  deps: Pick<
    DeleteScopeDeps,
    | "deleteData"
    | "pendingBlobDeletions"
    | "dataPointFeed"
    | "serverOwner"
    | "logger"
  > & {
    /** Local index, for expanding version-less markers into exact keys. */
    storage?: Pick<DataStoragePort, "listVersions">;
  },
): Promise<RetryPendingBlobDeletionsResult> {
  const { deleteData, pendingBlobDeletions, logger } = deps;
  const result: RetryPendingBlobDeletionsResult = {
    completed: [],
    superseded: [],
    failed: [],
    remaining: 0,
  };
  if (!deleteData || !pendingBlobDeletions) return result;

  let keys = await pendingBlobDeletions.list();
  if (keys.length === 0) return result;

  // Expand version-less markers into exact keys.
  for (const marker of keys.filter((key) => key.version === null)) {
    const registry = await registryState(deps, marker.scope);
    if (registry.status === "unknown") {
      result.failed.push({
        scope: marker.scope,
        version: null,
        error: registry.error.message,
      });
      continue;
    }
    if (registry.status === "live") {
      await pendingBlobDeletions.remove([marker]);
      result.superseded.push(marker.scope);
      logger.warn(
        {
          scope: marker.scope,
          dataPointId: registry.record.id,
          version: registry.record.expectedVersion,
        },
        "Scope was re-added after its tombstone; dropping the unexpanded blob deletion marker so the live version's ciphertext survives",
      );
      continue;
    }
    const expanded = planBlobDeletions(
      deps.storage ?? { listVersions: () => [] },
      marker.scope,
      registry.status === "deleted" ? registry.version : null,
    ).map((version): PendingBlobDeletion => ({ scope: marker.scope, version }));
    await pendingBlobDeletions.remove([marker]);
    await pendingBlobDeletions.add(expanded);
  }
  keys = (await pendingBlobDeletions.list()).filter(
    (key) => key.version !== null,
  );

  // One rate-limited batch across scopes, in stored order.
  const batch = keys.slice(0, BLOB_DELETE_BATCH_SIZE);
  const byScope = new Map<string, string[]>();
  for (const key of batch) {
    const versions = byScope.get(key.scope) ?? [];
    versions.push(key.version as string);
    byScope.set(key.scope, versions);
  }
  for (const [scope, versions] of byScope) {
    let outcome: Awaited<ReturnType<DeleteDataPort["deleteBlobVersions"]>>;
    try {
      outcome = await deleteData.deleteBlobVersions(scope, versions);
    } catch (err) {
      const message = errorMessage(err);
      for (const version of versions) {
        result.failed.push({ scope, version, error: message });
      }
      logger.warn(
        { scope, error: message },
        "Pending blob deletion failed again",
      );
      continue;
    }
    const completed = [...outcome.deleted, ...outcome.missing].map(
      (version): PendingBlobDeletion => ({ scope, version }),
    );
    if (completed.length > 0) {
      await pendingBlobDeletions.remove(completed);
      result.completed.push(...completed);
      logger.info(
        {
          scope,
          deleted: outcome.deleted.length,
          missing: outcome.missing.length,
        },
        "Completed pending blob deletions",
      );
    }
    for (const failure of outcome.failed) {
      result.failed.push({ scope, ...failure });
    }
    if (outcome.failed.length > 0) {
      logger.warn(
        {
          scope,
          failed: outcome.failed.length,
          error: outcome.failed[0].error,
        },
        "Pending blob deletion failed again",
      );
    }
  }
  result.remaining = (await pendingBlobDeletions.list()).length;
  return result;
}

type RegistryState =
  | { status: "live"; record: DataPointFeedRecord }
  | { status: "deleted"; version: string | null }
  | { status: "deleted-or-absent" }
  | { status: "unknown"; error: Error };

/**
 * What the registry currently says about `scope`. "live" means a row exists
 * that is not a tombstone; "deleted" carries the tombstone's version;
 * "deleted-or-absent" is used when nothing can be asked (no feed or owner
 * wired) or the row is gone.
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
  if (record === null) return { status: "deleted-or-absent" };
  if (deletionTimestamp(record) === null) return { status: "live", record };
  return { status: "deleted", version: tombstoneVersion(record) };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
