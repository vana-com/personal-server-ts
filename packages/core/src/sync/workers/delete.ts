import type { Logger } from "../../logger/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import { withScopeLock } from "../../additions/scope-lock.js";
import type {
  DataPointFeedPort,
  DataPointFeedRecord,
  DataStoragePort,
  DeleteDataPort,
  PendingBlobDeletion,
  PendingBlobDeletionStore,
} from "../../ports/index.js";
import { computeDataPointId } from "../data-point-id.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";
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
      /** Tombstone version at the gateway; null when it did not report one. */
      version?: string | null;
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

export interface BlobDeletionPlan {
  /**
   * Exact keys of covered local entries that lie outside the registry range:
   * an upload that landed under a key the registry never saw (crashed before
   * registering, or rebased later) is still deleted data. Bounded by the
   * local index size.
   */
  keys: string[];
  /**
   * Every registry version up to and including the tombstone's, as inclusive
   * bounds. Versions are a dense, strictly increasing integer sequence per
   * scope and an absent key answers 404, so the range is exact and complete
   * across replicas without listing storage. Kept as bounds, never
   * materialised: a large tombstone version costs nothing until its keys are
   * actually sent, a batch at a time. Null without a tombstone version.
   */
  range: { from: string; to: string } | null;
}

/**
 * The storage keys a tombstone covers for `scope`. A re-add registered after
 * the tombstone lives under a higher version key, so it is never in this set
 * and survives by construction. With no tombstone version (never registered,
 * or the gateway did not report one) only the local entries' keys can be
 * enumerated.
 */
export function planBlobDeletions(
  storage: Pick<DataStoragePort, "listVersions">,
  scope: string,
  tombstoneVersionValue: string | null,
): BlobDeletionPlan {
  const tombstone = { version: tombstoneVersionValue };
  const last =
    tombstoneVersionValue === null ? null : BigInt(tombstoneVersionValue);
  const keys = new Set<string>();
  const PAGE_SIZE = 500;
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const entries = storage.listVersions(scope, { limit: PAGE_SIZE, offset });
    for (const entry of entries) {
      if (!isEntryCoveredByTombstone(entry, tombstone)) continue;
      const version = BigInt(entry.version);
      if (last !== null && version >= 1n && version <= last) continue;
      keys.add(version.toString());
    }
    if (entries.length < PAGE_SIZE) break;
  }
  return {
    keys: [...keys].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)),
    range:
      last === null || last < 1n ? null : { from: "1", to: last.toString() },
  };
}

/**
 * A local entry the tombstone covered, as it stood when the tombstone landed:
 * its immutable row identity (`id`, `path`) and its collection stamp.
 */
type CoveredEntry = Pick<IndexEntry, "id" | "path" | "collectedAt">;

/**
 * The entries `tombstoneVersionValue` covers, read once when the tombstone
 * lands and before any remote await. This fence is the only thing step 3 may
 * erase: an entry that arrives later is outside it, whatever its marker.
 */
function captureCoveredEntries(
  storage: Pick<DataStoragePort, "listVersions">,
  scope: string,
  tombstoneVersionValue: string | null,
): CoveredEntry[] {
  const tombstone = { version: tombstoneVersionValue };
  const covered: CoveredEntry[] = [];
  const PAGE_SIZE = 500;
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const entries = storage.listVersions(scope, { limit: PAGE_SIZE, offset });
    for (const entry of entries) {
      if (isEntryCoveredByTombstone(entry, tombstone)) {
        covered.push({
          id: entry.id,
          path: entry.path,
          collectedAt: entry.collectedAt,
        });
      }
    }
    if (entries.length < PAGE_SIZE) break;
  }
  return covered;
}

/**
 * Erase exactly the fenced versions, one at a time, each through the storage's
 * fenced erase. The storage checks the row's id and path at the erase itself,
 * under its own lock or transaction, so a replacement that took a fenced stamp
 * after capture is left alone and reported as not erased. No snapshot is taken
 * here, because a snapshot is stale by the time the erase runs.
 *
 * The scope's first-seen sidecar was derived from the fenced rows, so it is
 * dropped after the erases, under the scope lock: a rebuild that read the old
 * rows cannot write it back once this returns. The next read rebuilds it from
 * the rows that survive (a re-add starts afresh there).
 */
async function eraseCoveredEntries(
  storage: Pick<DataStoragePort, "deleteVersion" | "deleteFirstSeenLedger">,
  scope: string,
  fence: CoveredEntry[],
): Promise<number> {
  if (fence.length === 0) return 0;
  let erased = 0;
  try {
    for (const captured of fence) {
      const removed = await storage.deleteVersion(scope, captured.collectedAt, {
        id: captured.id,
        path: captured.path,
      });
      if (removed) erased += 1;
    }
  } finally {
    await withScopeLock(scope, async () => {
      await storage.deleteFirstSeenLedger?.(scope);
    });
  }
  return erased;
}

/** Take up to `count` versions from the head of a range; `rest` is what remains. */
function takeFromRange(
  range: { from: string; to: string },
  count: number,
): { versions: string[]; rest: { from: string; to: string } | null } {
  const from = BigInt(range.from);
  const to = BigInt(range.to);
  const versions: string[] = [];
  let cursor = from;
  while (cursor <= to && versions.length < count) {
    versions.push(cursor.toString());
    cursor += 1n;
  }
  return {
    versions,
    rest: cursor <= to ? { from: cursor.toString(), to: range.to } : null,
  };
}

function rangeSize(range: { from: string; to: string }): bigint {
  return BigInt(range.to) - BigInt(range.from) + 1n;
}

/**
 * Count of blob keys a marker list still stands for, clamped for reporting.
 * An unexpanded marker (range not known yet) counts as one.
 */
function countPendingKeys(markers: PendingBlobDeletion[]): number {
  let total = 0n;
  for (const marker of markers) {
    if (marker.version !== null) total += 1n;
    else if (marker.range) total += rangeSize(marker.range);
    else total += 1n;
  }
  return total > BigInt(Number.MAX_SAFE_INTEGER)
    ? Number.MAX_SAFE_INTEGER
    : Number(total);
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
  // Set only once a gateway tombstone has landed (see step 2).
  let covered: CoveredEntry[] | null = null;

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
        tombstoneVersionValue =
          outcome.version === null
            ? null
            : tombstoneVersion({ expectedVersion: outcome.version });
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
    // queued. A repeated delete of a scope whose cleanup is still running
    // resumes from the queue: only work not taken on before is recorded, and
    // the pass drains the scope's queue head, so no confirmed key is re-sent
    // and no queued key is dropped. A tombstone whose version the gateway did
    // not report cannot be expanded into registry keys yet; a version-less
    // marker asks the retry to expand it once the registry answers.
    // Fence first: the covered entries as they stand before the remote await.
    covered = captureCoveredEntries(storage, scope, tombstoneVersionValue);
    const plan = planBlobDeletions(storage, scope, tombstoneVersionValue);
    const storageStep = await deleteScopeBlobs(
      { deleteData, pendingBlobDeletions, logger },
      scope,
      plan,
      tombstoneKnown && tombstoneVersionValue === null,
    );
    result.steps.storage = storageStep.step;
    result.pendingBlobDeletion = storageStep.pending > 0;
  }

  // 3. Local copy. Safe now: the registry row is a tombstone (or the point
  // was never registered / sync is off), so nothing can re-pull it. Only the
  // versions fenced in step 2 are erased: a row that arrived while the remote
  // deletes were in flight is outside the fence and stays. With no gateway
  // there is no fence and the whole local copy goes.
  try {
    const deletedCount = covered
      ? await eraseCoveredEntries(storage, scope, covered)
      : await storage.deleteScope(scope);
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
 * Where a repeated delete of `scope` resumes: the highest tombstone version
 * whose covered range was already taken on. The store's watermark says so
 * directly; a queued range also proves its own upper bound was planned
 * (which covers marker files written before the watermark existed).
 */
async function resumePoint(
  store: PendingBlobDeletionStore,
  scope: string,
  markers: PendingBlobDeletion[],
): Promise<bigint | null> {
  const stored = store.plannedThrough
    ? await store.plannedThrough(scope)
    : null;
  let through = stored === null ? null : BigInt(stored);
  for (const marker of markers) {
    if (marker.scope !== scope || marker.version !== null || !marker.range) {
      continue;
    }
    const to = BigInt(marker.range.to);
    if (through === null || to > through) through = to;
  }
  return through;
}

/**
 * The part of `plan` not taken on yet: its exact keys, and the registry range
 * above `through`. Keys at or below `through` are already deleted or still
 * queued, so planning them again would only re-send confirmed deletes.
 */
function unplannedWork(
  scope: string,
  plan: BlobDeletionPlan,
  through: bigint | null,
): PendingBlobDeletion[] {
  const work: PendingBlobDeletion[] = plan.keys.map((version) => ({
    scope,
    version,
  }));
  if (plan.range) {
    let from = BigInt(plan.range.from);
    if (through !== null && through + 1n > from) from = through + 1n;
    if (from <= BigInt(plan.range.to)) {
      work.push({
        scope,
        version: null,
        range: { from: from.toString(), to: plan.range.to },
      });
    }
  }
  return work;
}

/** Record work and its watermark together when the store supports it. */
async function recordPlannedWork(
  store: PendingBlobDeletionStore,
  scope: string,
  work: PendingBlobDeletion[],
  through: string | null,
): Promise<void> {
  if (store.enqueue) await store.enqueue(scope, work, through);
  else await store.add(work);
}

interface ScopePassOutcome {
  deleted: string[];
  missing: string[];
  failed: Array<{ version: string; error: string }>;
}

/**
 * Send one rate-limited batch taken from `markers` (exact keys first, then
 * range heads, in stored order) and reconcile the store: acknowledged exact
 * markers (2xx or 404) leave it, a failed key taken from a range becomes an
 * exact marker, and each consumed range is advanced in place. A key queued
 * twice (an exact marker inside a range) is sent once.
 */
async function drainOnePass(
  deleteData: DeleteDataPort,
  store: PendingBlobDeletionStore,
  markers: PendingBlobDeletion[],
): Promise<Map<string, ScopePassOutcome>> {
  let budget = BLOB_DELETE_BATCH_SIZE;
  const byScope = new Map<string, string[]>();
  const queued = new Set<string>();
  const exactOrigin = new Set<string>();
  const advancedRanges: Array<{
    old: PendingBlobDeletion;
    next: PendingBlobDeletion | null;
  }> = [];
  const keyOf = (scope: string, version: string) => `${scope}\u0000${version}`;
  const take = (scope: string, version: string): boolean => {
    const id = keyOf(scope, version);
    if (queued.has(id)) return false;
    queued.add(id);
    const versions = byScope.get(scope) ?? [];
    versions.push(version);
    byScope.set(scope, versions);
    return true;
  };
  for (const marker of markers) {
    if (budget === 0) break;
    if (marker.version !== null) {
      exactOrigin.add(keyOf(marker.scope, marker.version));
      if (take(marker.scope, marker.version)) budget -= 1;
    }
  }
  for (const marker of markers) {
    if (budget === 0) break;
    if (marker.version === null && marker.range) {
      const taken = takeFromRange(marker.range, budget);
      for (const version of taken.versions) {
        if (take(marker.scope, version)) budget -= 1;
      }
      advancedRanges.push({
        old: marker,
        next: taken.rest
          ? { scope: marker.scope, version: null, range: taken.rest }
          : null,
      });
    }
  }

  const outcomes = new Map<string, ScopePassOutcome>();
  for (const [scope, versions] of byScope) {
    let outcome: ScopePassOutcome;
    try {
      outcome = await deleteData.deleteBlobVersions(scope, versions);
    } catch (err) {
      // The port reports per-key failures; a thrown error means none of the
      // batch can be trusted as done.
      const message = errorMessage(err);
      outcome = {
        deleted: [],
        missing: [],
        failed: versions.map((version) => ({ version, error: message })),
      };
    }
    outcomes.set(scope, outcome);
    const completed = [...outcome.deleted, ...outcome.missing]
      .filter((version) => exactOrigin.has(keyOf(scope, version)))
      .map((version): PendingBlobDeletion => ({ scope, version }));
    if (completed.length > 0) await store.remove(completed);
    // A failed key that came from a range becomes an exact marker; a failed
    // exact marker simply stays.
    const failedFromRange = outcome.failed
      .filter(({ version }) => !exactOrigin.has(keyOf(scope, version)))
      .map(({ version }): PendingBlobDeletion => ({ scope, version }));
    if (failedFromRange.length > 0) await store.add(failedFromRange);
  }
  // Advance the ranges only now: a crash mid-pass re-sends already-deleted
  // keys (404, harmless) rather than skipping keys that were never sent. The
  // successor is persisted before its predecessor is dropped, so a failed or
  // interrupted write leaves the old range standing, never a gap.
  for (const { old, next } of advancedRanges) {
    if (next) await store.add([next]);
    await store.remove([old]);
  }
  return outcomes;
}

/**
 * The storage step of one DELETE call: record the work not taken on yet
 * (with the scope's planned watermark), then send one batch from the head of
 * the scope's queue and report what is still owed. A first delete and a
 * repeat of it run the same path, so a repeat resumes where the queue stands.
 */
async function deleteScopeBlobs(
  deps: { deleteData: DeleteDataPort } & Pick<
    DeleteScopeDeps,
    "pendingBlobDeletions" | "logger"
  >,
  scope: string,
  plan: BlobDeletionPlan,
  versionUnknown: boolean,
): Promise<{ step: DeleteScopeResult["steps"]["storage"]; pending: number }> {
  const { deleteData, logger } = deps;
  const withUnknown = (work: PendingBlobDeletion[]) =>
    versionUnknown ? [...work, { scope, version: null }] : work;
  let work = withUnknown(unplannedWork(scope, plan, null));
  let store: PendingBlobDeletionStore | null =
    deps.pendingBlobDeletions ?? null;
  if (store) {
    try {
      const through = await resumePoint(store, scope, await store.list());
      work = withUnknown(unplannedWork(scope, plan, through));
      await recordPlannedWork(store, scope, work, plan.range?.to ?? null);
    } catch (markerErr) {
      logger.error(
        { scope, error: errorMessage(markerErr), keys: countPendingKeys(work) },
        "Could not record pending blob deletion markers",
      );
      store = null;
    }
  }
  // Without a durable marker store this pass still sends its batch; what it
  // cannot send is reported, not recorded.
  const recorded = store !== null;
  const passStore = store ?? createMemoryPendingBlobDeletionStore();
  if (!recorded) await passStore.add(work);

  let outcome: ScopePassOutcome;
  let remainingKeys: number;
  try {
    const queued = (await passStore.list()).filter((m) => m.scope === scope);
    outcome = (await drainOnePass(deleteData, passStore, queued)).get(
      scope,
    ) ?? { deleted: [], missing: [], failed: [] };
    remainingKeys = countPendingKeys(
      (await passStore.list()).filter((m) => m.scope === scope),
    );
  } catch (markerErr) {
    // A marker write failed mid-pass. The store never loses owed keys (see
    // drainOnePass), so the queue still holds this scope's work.
    const message = errorMessage(markerErr);
    logger.error(
      { scope, error: message },
      "Could not update pending blob deletion markers",
    );
    return {
      step: { status: "failed", error: message },
      pending: recorded ? 1 : 0,
    };
  }
  if (!recorded && remainingKeys > 0) {
    logger.error(
      { scope, keys: remainingKeys },
      "Blob deletions left unfinished with no marker store to retry them",
    );
  }
  const pending = recorded ? remainingKeys : 0;
  const counts = {
    blobsDeleted: outcome.deleted.length,
    blobsMissing: outcome.missing.length,
    blobsPending: remainingKeys,
  };
  if (outcome.failed.length > 0) {
    const first = outcome.failed[0];
    logger.warn(
      { scope, failed: outcome.failed.length, pending, error: first.error },
      "Storage blob deletion failed for some keys after gateway tombstone; will retry",
    );
    return {
      step: {
        status: "failed",
        error: `${outcome.failed.length} blob delete(s) failed: ${first.error}`,
        ...counts,
      },
      pending,
    };
  }
  if (remainingKeys > 0) {
    logger.info(
      { scope, ...counts },
      "Storage blob deletion continues on later sync cycles (rate-limited batch)",
    );
    return { step: { status: "deferred", ...counts }, pending };
  }
  return { step: { status: "ok", ...counts }, pending: 0 };
}

export interface RetryPendingBlobDeletionsResult {
  /** Exact keys finished this pass (deleted, or already absent). */
  completed: PendingBlobDeletion[];
  /** Unexpanded markers dropped because the scope is live again. */
  superseded: string[];
  failed: Array<{ scope: string; version: string | null; error: string }>;
  /** Markers still queued after this pass (a range counts once). */
  remaining: number;
}

/**
 * Finish blob deletions whose tombstone landed but whose storage deletes did
 * not: one batch of exact keys per sync cycle, taken from exact-key markers
 * first and then from the head of range markers (which advance in place),
 * each key retried until storage acknowledges (2xx or 404). Unexpanded
 * markers (the gateway did not report a tombstone version at delete time)
 * are expanded from the registry first; if the registry shows the scope live
 * again the old tombstone's version is unknowable, so the marker is dropped
 * and the pre-tombstone ciphertext stays (owner-decryptable only) until the
 * next delete of that scope.
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
    /** Local index, for expanding unexpanded markers into exact keys. */
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

  let markers = await pendingBlobDeletions.list();
  if (markers.length === 0) return result;

  // Expand markers whose tombstone version was unknown at delete time.
  for (const marker of markers.filter(
    (key) => key.version === null && !key.range,
  )) {
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
    const plan = planBlobDeletions(
      deps.storage ?? { listVersions: () => [] },
      marker.scope,
      registry.status === "deleted" ? registry.version : null,
    );
    // Only the part not taken on yet: a repeated delete may already have
    // queued (or finished) the same tombstone's range.
    const expanded = unplannedWork(
      marker.scope,
      plan,
      await resumePoint(pendingBlobDeletions, marker.scope, markers),
    );
    // Persist the expansion before dropping the unexpanded marker: a failed or
    // interrupted write leaves the marker to expand again (the same keys), and
    // never drops keys that are still owed.
    await recordPlannedWork(
      pendingBlobDeletions,
      marker.scope,
      expanded,
      plan.range?.to ?? null,
    );
    await pendingBlobDeletions.remove([marker]);
  }
  markers = await pendingBlobDeletions.list();

  // One rate-limited batch in stored order: exact keys, then range heads.
  const outcomes = await drainOnePass(
    deleteData,
    pendingBlobDeletions,
    markers,
  );
  for (const [scope, outcome] of outcomes) {
    result.completed.push(
      ...[...outcome.deleted, ...outcome.missing].map(
        (version): PendingBlobDeletion => ({ scope, version }),
      ),
    );
    for (const failure of outcome.failed) {
      result.failed.push({ scope, ...failure });
    }
    if (outcome.deleted.length + outcome.missing.length > 0) {
      logger.info(
        {
          scope,
          deleted: outcome.deleted.length,
          missing: outcome.missing.length,
        },
        "Completed pending blob deletions",
      );
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
