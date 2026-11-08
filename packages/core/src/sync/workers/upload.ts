import { isMemoryScope } from "../../policy/reserved-scopes.js";
import { isReplicaScope } from "../../replication/namespace.js";
import type { DurableAdditionsService } from "../../additions/durable.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import {
  publishVersion,
  type FencedPublicationPort,
  type PublicationRecord,
} from "../../publication/publish.js";
export { parseGatewayNextVersion } from "../../publication/publish.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type {
  DataPointFeedPort,
  DataPointFeedRecord,
  DataStoragePort,
  PendingBlobDeletionStore,
} from "../../ports/index.js";
import { computeDataPointId } from "../data-point-id.js";
import {
  deletionTimestamp,
  isEntryCoveredByTombstone,
  tombstoneVersion,
  type ScopeDeletionTracker,
} from "../scope-deletions.js";
import type { LineageGatewayPort } from "../../lineage/gateway.js";
import {
  MAX_UPLOAD_BODY_BYTES,
  createUploadStateTracker,
  exceedsUploadCap,
  isUsableUploadSize,
  type RowIdentity,
  type UploadStateTracker,
} from "../upload-state.js";
import {
  uploadAttemptKey,
  type UploadAttemptLedger,
} from "../upload-attempts.js";

export { computeDataPointId } from "../data-point-id.js";
export { isEntryCoveredByTombstone } from "../scope-deletions.js";

export interface UploadWorkerDeps {
  additions?: DurableAdditionsService;
  fencedPublication?: FencedPublicationPort;
  storage: DataStoragePort;
  storageAdapter: StorageAdapter;
  gateway: GatewayClient;
  signer: Pick<ServerSigner, "signAddData" | "signLineageAttestation">;
  masterKey: Uint8Array;
  serverOwner: string;
  logger: Logger;
  /**
   * Registers derivative records (envelopes stamped with `$lineage`) with
   * their lineage. The SDK client's registerDataPoint sends only the AddData
   * fields, so a derivative needs this direct client; without it a derivative
   * upload fails (and retries next cycle) rather than silently registering as
   * a root record whose lineage exists only inside the ciphertext.
   */
  lineageGateway?: Pick<LineageGatewayPort, "registerDataPoint">;
  /**
   * Deletion-aware registry lookup. When present, an unsynced entry for a
   * scope the gateway has tombstoned is dropped instead of uploaded (unless
   * it was ingested AFTER the deletion, which is a legitimate re-add and is
   * registered strictly after the tombstone version). Without it the worker
   * behaves as before and cannot see deletions.
   */
  dataPointFeed?: DataPointFeedPort;
  /**
   * Read-side deletion memory. A successful registration marks the scope
   * live again (a re-add after a tombstone must not keep answering 410).
   */
  scopeDeletions?: ScopeDeletionTracker;
  /**
   * Compatibility input for existing hosts. Publication never reclaims a
   * version key; exact-key cleanup belongs to the durable deletion worker.
   */
  pendingBlobDeletions?: PendingBlobDeletionStore;
  /**
   * Owner-visible record of entries that are too large to upload and of
   * failing uploads that back off. The sync manager owns one and reports it
   * in its status. Without it, `uploadAll` keeps no memory across calls: the
   * size cap still applies, but failures are retried on every call.
   */
  uploadState?: UploadStateTracker;
  /**
   * Durable markers for attempts in flight. Without it an attempt that kills
   * the process leaves no trace, and the same entry is picked again after
   * every restart. The sync manager builds one from the host's store.
   */
  uploadAttempts?: UploadAttemptLedger;
}

/** An upload attempt that ran past its deadline and was aborted. */
export class UploadDeadlineError extends Error {
  constructor(readonly deadlineMs: number) {
    super(
      `Upload attempt passed its ${deadlineMs} ms deadline and was aborted`,
    );
    this.name = "UploadDeadlineError";
  }
}

/** One attempt's budget. Long enough for a slow link, short of forever. */
export const DEFAULT_UPLOAD_ATTEMPT_DEADLINE_MS = 10 * 60_000;

export interface UploadResult {
  path: string;
  /** Storage URL the encrypted blob was written to (version-keyed). */
  url: string;
  /**
   * DPv2 data-point id assigned by the gateway. Present whenever this run
   * either freshly registered the data point or found one already attached
   * to the index entry from a prior run.
   */
  dataPointId: string;
}

/** Default most unsynced rows read per cycle (index rows only, no bodies). */
export const UPLOAD_SCAN_BUDGET = 2000;

export interface UploadAllOptions {
  batchSize?: number;
  /**
   * Most unsynced rows read in one cycle, on a host with `findUnsyncedPage`.
   * A larger backlog is swept in windows of this size across cycles.
   * Default `UPLOAD_SCAN_BUDGET`.
   */
  scanBudget?: number;
  onError?: (entry: IndexEntry, error: Error) => void;
  /** Clock for the coalesced-scope quiet window. Defaults to the wall clock. */
  now?: () => Date;
  /**
   * Deadline for one entry's attempt. Past it the attempt is aborted, counted
   * as a caught failure and the next entry proceeds.
   */
  attemptDeadlineMs?: number;
}

/**
 * Thrown when an unsynced entry's local payload file is gone, so the entry was
 * dropped from the index rather than uploaded. `uploadAll` treats it as a
 * silent self-heal, not a sync failure — it must not surface to the user or
 * poison the settle-wait (there is nothing to retry).
 */
export class OrphanedEntryError extends Error {
  constructor(path: string) {
    super(`Orphaned index entry dropped (payload missing): ${path}`);
    this.name = "OrphanedEntryError";
  }
}

/**
 * Thrown when an unsynced entry belongs to a scope the gateway has tombstoned
 * and the entry predates that deletion: uploading it would resurrect data the
 * owner deleted, so the local copy is dropped instead. Like
 * `OrphanedEntryError`, `uploadAll` treats it as a silent self-heal.
 */
export class DeletedScopeEntryError extends Error {
  constructor(path: string, deletedAt: string) {
    super(`Dropped local entry for a scope deleted at ${deletedAt}: ${path}`);
    this.name = "DeletedScopeEntryError";
  }
}

/**
 * Thrown before anything is read when an unsynced entry's upload body would
 * pass `MAX_UPLOAD_BODY_BYTES`. The entry stays local and readable; it can
 * never sync, so retrying it is wasted work.
 */
export class UploadTooLargeError extends Error {
  constructor(
    readonly path: string,
    readonly sizeBytes: number,
  ) {
    super(
      `Too large to sync: ${path} is ${sizeBytes} bytes and an upload body is limited to ${MAX_UPLOAD_BODY_BYTES} bytes`,
    );
    this.name = "UploadTooLargeError";
  }
}

/**
 * Thrown before anything is read when an unsynced entry's stored size is
 * missing or not a positive finite number. The cap cannot be checked, so the
 * entry is held back (fail closed) and stays local.
 */
export class UploadUnsizableError extends Error {
  constructor(
    readonly path: string,
    readonly sizeBytes: unknown,
  ) {
    super(`No usable stored size for ${path}: ${String(sizeBytes)}`);
    this.name = "UploadUnsizableError";
  }
}

/**
 * Drop an unsynced entry the gateway tombstone covers and signal it as a
 * self-heal. Returns without effect when the entry was ingested with
 * knowledge of the tombstone (`afterTombstoneVersion`): a legitimate re-add.
 *
 * Remote cleanup belongs to the deletion pipeline. Registry refusal does
 * not grant this publisher authority to delete a potentially committed blob.
 */
async function dropIfCoveredByDeletion(
  deps: Pick<UploadWorkerDeps, "storage" | "logger">,
  entry: IndexEntry,
  tombstone: Pick<DataPointFeedRecord, "expectedVersion">,
  deletedAt: string,
): Promise<void> {
  const version = tombstoneVersion(tombstone);
  if (!isEntryCoveredByTombstone(entry, { version })) return;
  await deps.storage.deleteVersion(entry.scope, entry.collectedAt);
  deps.logger.warn(
    {
      path: entry.path,
      scope: entry.scope,
      deletedAt,
      tombstoneVersion: version,
      entryVersion: entry.version,
      afterTombstoneVersion: entry.afterTombstoneVersion ?? null,
    },
    "Dropped unsynced local entry: the gateway reports its scope as deleted",
  );
  throw new DeletedScopeEntryError(entry.path, deletedAt);
}

/**
 * A filesystem "file not found" from readEnvelope. Matched strictly on the
 * Node error code, never on message text: the only storage adapter that
 * implements `dropUnsyncedEntry` (node-data-storage, backed by fs) always sets
 * `code: "ENOENT"` on a missing file, and message-substring matching would let
 * an unrelated validation/adapter error that merely mentions "no such file"
 * trigger a destructive index-row drop.
 */
function isMissingPayloadError(err: unknown): boolean {
  return err instanceof Error && (err as { code?: unknown }).code === "ENOENT";
}

/**
 * Upload a single unsynced index entry:
 * 1. Read local data file from disk
 * 2. Derive scope key from master key → hex-encode as OpenPGP password
 * 3. Encrypt envelope with OpenPGP password-based encryption → ciphertext
 * 4. Compute dataHash / metadataHash commitments (scope-addressed, no schema)
 * 5. Upload ciphertext to storage backend, version-keyed `{scope}/{version}`
 * 6. Register DPv2 data point on-chain (AddData) if not already
 * 7. Persist the gateway-assigned dataPointId (marks the entry synced)
 */
export async function uploadOne(
  deps: UploadWorkerDeps,
  entry: IndexEntry,
  options?: { signal?: AbortSignal },
): Promise<UploadResult> {
  const signal = options?.signal;
  if (isReplicaScope(entry.scope))
    throw new Error("replica scopes require immutable transport");
  const {
    storage,
    storageAdapter,
    gateway,
    signer,
    masterKey,
    serverOwner,
    logger,
  } = deps;

  // Decide from the stored size alone, before anything is read, parsed or
  // encrypted: a body over the request limit can never be accepted.
  if (!entry.dataPointId) {
    if (!isUsableUploadSize(entry.sizeBytes))
      throw new UploadUnsizableError(entry.path, entry.sizeBytes);
    if (exceedsUploadCap(entry.sizeBytes))
      throw new UploadTooLargeError(entry.path, entry.sizeBytes);
  }

  // 1. Read local data file
  let envelope;
  try {
    envelope = await storage.readEnvelope(entry.scope, entry.collectedAt);
  } catch (err) {
    // The index row points at a payload file that no longer exists on disk
    // (a manual `data/<scope>` deletion, or an interrupted cleanup). This
    // entry can never upload — its source bytes are gone — so retrying it
    // every cycle head-blocks the scope forever (ENOENT loop). Drop the
    // orphaned row and skip it instead. Unsynced entries carry no fileId, so
    // this is index-only; nothing on the gateway is affected.
    if (isMissingPayloadError(err) && storage.dropUnsyncedEntry) {
      const dropped = await storage.dropUnsyncedEntry(entry.path);
      if (dropped) {
        logger.warn(
          { path: entry.path, scope: entry.scope },
          "Dropped orphaned index entry: local payload file is missing",
        );
        throw new OrphanedEntryError(entry.path);
      }
    }
    throw err;
  }
  signal?.throwIfAborted();

  const readHead = async (): Promise<PublicationRecord | null> =>
    deps.dataPointFeed
      ? deps.dataPointFeed.getDataPoint({
          ownerAddress: serverOwner,
          scope: entry.scope,
        })
      : gateway.getDataPoint(computeDataPointId(serverOwner, entry.scope));
  const checkHead = async (remote: PublicationRecord | null) => {
    const deletedAt =
      remote?.deletedAt ??
      (remote?.addedAt
        ? deletionTimestamp({ ...remote, addedAt: remote.addedAt })
        : null);
    if (remote && deletedAt !== null)
      await dropIfCoveredByDeletion(deps, entry, remote, deletedAt);
  };
  const initialHead =
    !entry.dataPointId && deps.dataPointFeed ? await readHead() : undefined;
  await checkHead(initialHead ?? null);
  const proof = entry.dataPointId
    ? {
        dataPointId: entry.dataPointId,
        url: storageAdapter.urlForKey(`${entry.scope}/${entry.version}`),
        version: BigInt(entry.version),
        sizeBytes: entry.sizeBytes,
      }
    : await publishVersion({
        ownerAddress: serverOwner,
        envelope,
        preferredVersion: BigInt(entry.version),
        masterKey,
        storageAdapter,
        gateway,
        signer,
        lineageGateway: deps.lineageGateway,
        fencedPublication: deps.fencedPublication,
        signal,
        head: initialHead,
        readHead,
        checkHead,
        acknowledgedDeletionVersion:
          entry.afterTombstoneVersion == null
            ? undefined
            : BigInt(entry.afterTombstoneVersion),
        // The marker is written at ingest, after the owner deleted the scope
        // and imported it again: a deliberate re-add, not a recovery.
        deletionAcknowledgedAtIngest: entry.afterTombstoneVersion != null,
      });
  const { dataPointId, url, sizeBytes } = proof;
  if (!entry.dataPointId) {
    if (proof.version !== BigInt(entry.version))
      await storage.updateEntryVersion(entry.path, Number(proof.version));
    await storage.updateDataPointId(entry.path, dataPointId);
    deps.scopeDeletions?.markLive(entry.scope);
  }

  if (deps.additions) {
    await deps.additions.recordUpload(
      {
        scope: entry.scope,
        collectedAt: envelope.collectedAt,
        data: envelope.data as Record<string, unknown>,
      },
      { envelope, encryptedSize: sizeBytes },
    );
  }

  logger.info(
    {
      path: entry.path,
      scope: entry.scope,
      version: entry.version,
      url,
      dataPointId,
    },
    "Uploaded and registered DPv2 data point",
  );

  return { path: entry.path, url, dataPointId };
}

/**
 * Agent-memory scopes (see `isMemoryScope`): every save stores a full snapshot,
 * so publishing each intermediate one would cost a registration per save.
 */
export function isCoalescedScope(scope: string): boolean {
  return isMemoryScope(scope);
}

/**
 * A coalesced scope is published once its newest snapshot has been quiet this
 * long (saves have stopped) ...
 */
export const COALESCE_QUIET_MS = 2 * 60_000;
/** ... or once its oldest unpublished snapshot has waited this long. */
export const COALESCE_MAX_WAIT_MS = 10 * 60_000;

interface CoalescedScope {
  /** The scope's latest local version: what readers serve. */
  head: IndexEntry;
  /** Still inside the quiet window: publish on a later pass. */
  deferred: boolean;
}

const at = (entry: IndexEntry) => Date.parse(entry.collectedAt);
const identityOf = (entry: IndexEntry): RowIdentity => ({
  id: entry.id,
  sizeBytes: entry.sizeBytes,
});
const VERSION_PAGE = 200;

/**
 * One plan per coalesced scope in the batch. The head is the scope's latest
 * local version (`findEntry`), not the batch's latest. Only the head is ever
 * published: readers serve the latest version, which is a full state, so an
 * older unpublished snapshot is never what anyone sees and publishing it would
 * roll the scope back.
 */
function coalescePlan(
  deps: UploadWorkerDeps,
  entries: readonly IndexEntry[],
  nowMs: number,
): Map<string, CoalescedScope> {
  // One pass, one small aggregate per scope: the batch's newest row and the
  // oldest time. Nothing is copied per row, so the cost is linear in the
  // entries however many versions one scope holds.
  const aggregates = new Map<
    string,
    { batchHead: IndexEntry; oldestMs: number }
  >();
  for (const entry of entries) {
    if (!isCoalescedScope(entry.scope)) continue;
    const known = aggregates.get(entry.scope);
    if (!known) {
      aggregates.set(entry.scope, { batchHead: entry, oldestMs: at(entry) });
      continue;
    }
    if (at(entry) > at(known.batchHead)) known.batchHead = entry;
    if (at(entry) < known.oldestMs) known.oldestMs = at(entry);
  }
  const plans = new Map<string, CoalescedScope>();
  for (const [scope, { batchHead, oldestMs }] of aggregates) {
    const latest = deps.storage.findEntry?.({ scope });
    const head = latest && at(latest) >= at(batchHead) ? latest : batchHead;
    const oldest = Math.min(oldestMs, at(head));
    const deferred =
      head.dataPointId === null &&
      nowMs - at(head) < COALESCE_QUIET_MS &&
      nowMs - oldest < COALESCE_MAX_WAIT_MS;
    plans.set(scope, { head, deferred });
  }
  return plans;
}

/** Every unpublished version of `head`'s scope older than `head`. */
function olderUnsynced(deps: UploadWorkerDeps, head: IndexEntry): IndexEntry[] {
  const older: IndexEntry[] = [];
  for (let offset = 0; ; offset += VERSION_PAGE) {
    const page = deps.storage.listVersions(head.scope, {
      limit: VERSION_PAGE,
      offset,
    });
    for (const entry of page) {
      if (
        entry.id !== head.id &&
        entry.dataPointId === null &&
        at(entry) < at(head)
      ) {
        older.push(entry);
      }
    }
    if (page.length < VERSION_PAGE) return older;
  }
}

/**
 * Erase the older unsynced snapshots of a coalesced scope once its newest
 * snapshot is published. Fenced to the exact rows selected, so a row that
 * changed since is left alone. A failed erase is logged; the row stays and is
 * superseded again on the next pass.
 */
async function eraseSuperseded(
  deps: UploadWorkerDeps,
  entries: readonly IndexEntry[],
): Promise<void> {
  for (const entry of entries) {
    try {
      await deps.storage.deleteVersion(entry.scope, entry.collectedAt, {
        id: entry.id,
        path: entry.path,
      });
    } catch (err) {
      deps.logger.warn(
        {
          path: entry.path,
          scope: entry.scope,
          error: err instanceof Error ? err.message : String(err),
        },
        "Failed to erase a superseded memory snapshot",
      );
    }
  }
}

/**
 * Note an entry whose stored size means it can never be uploaded (too large,
 * or no usable size), log it once, and say so. Reads nothing but the row.
 */
function holdBackTerminal(
  deps: UploadWorkerDeps,
  state: UploadStateTracker,
  target: IndexEntry,
): boolean {
  if (target.dataPointId !== null) return false;
  const at = {
    scope: target.scope,
    path: target.path,
    identity: identityOf(target),
  };
  if (!isUsableUploadSize(target.sizeBytes)) {
    if (state.markUnsizable(at)) {
      deps.logger.warn(
        { ...at, sizeBytes: String(target.sizeBytes) },
        "Entry has no usable size; it stays local and is not uploaded",
      );
    }
    return true;
  }
  if (!exceedsUploadCap(target.sizeBytes)) return false;
  if (state.markTooLarge(at, target.sizeBytes)) {
    deps.logger.warn(
      {
        ...at,
        sizeBytes: target.sizeBytes,
        maxBodyBytes: MAX_UPLOAD_BODY_BYTES,
      },
      "Entry is too large to sync; it stays local and is not uploaded",
    );
  }
  return true;
}

/**
 * Run `attempt` with an AbortSignal that fires at the deadline. The result is
 * a rejection with `UploadDeadlineError` at the deadline even when `attempt`
 * never settles, so the worker can move on; the signal lets the work stop at
 * its next step instead of publishing late.
 */
async function withDeadline<T>(
  deadlineMs: number,
  attempt: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const error = new UploadDeadlineError(deadlineMs);
      controller.abort(error);
      reject(error);
    }, deadlineMs);
  });
  try {
    return await Promise.race([attempt(controller.signal), expired]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Process all unsynced entries (dataPointId === null).
 * Processes sequentially to avoid overwhelming storage backend.
 * Returns array of results (skips failures, logs errors).
 *
 * Coalesced scopes (see `isCoalescedScope`) publish only their newest
 * unsynced snapshot in the batch, after a quiet window; the older ones are
 * erased after it lands.
 */
export async function uploadAll(
  deps: UploadWorkerDeps,
  options?: UploadAllOptions,
): Promise<UploadResult[]> {
  const batchSize = options?.batchSize ?? 50;
  const clock = () => (options?.now ?? (() => new Date()))().getTime();
  // Unsynced index rows only, no bodies. Entries that cannot be attempted now
  // must not occupy the batch, or they hide every entry behind them, so the
  // batch is chosen below from everything listed, not from a limited page.
  // A host with keyset paging lists one window of at most `scanBudget` rows
  // per cycle, resuming where the last cycle stopped, so a huge backlog costs
  // a bounded amount per cycle and is still swept in full. Any other host is
  // listed whole.
  const state = deps.uploadState ?? createUploadStateTracker();
  const attempts = deps.uploadAttempts;
  // Leftover markers are attempts that never settled; count them before
  // choosing what to upload.
  await attempts?.recover();
  // Paging needs both methods: the page method alone has no fence, so a
  // growing tail could keep the sweep from ever wrapping. Such a host is
  // listed whole.
  const paged = deps.storage.maxUnsyncedId
    ? deps.storage.findUnsyncedPage
    : undefined;
  const scanBudget = options?.scanBudget ?? UPLOAD_SCAN_BUDGET;
  const scanAfter = paged ? state.scanCursor() : 0;
  // A sweep covers the rows present when it began: its upper id is fixed at
  // the start. Rows that arrive above it wait for the next sweep, so a tail
  // that keeps growing cannot stop the sweep from wrapping back to earlier
  // rows (a failed upload that is due again would never be revisited).
  if (paged && scanAfter === 0 && state.scanFence() === null) {
    const max = deps.storage.maxUnsyncedId?.() ?? Number.POSITIVE_INFINITY;
    state.setScanFence(max);
    // No unsynced row is above the fresh maximum, so state recorded for ids
    // beyond it belongs to rows that are gone (a remote deletion removes rows
    // without the sync manager). Only a new sweep may say this: an older
    // sweep's fence can sit below live state.
    if (Number.isFinite(max)) {
      state.reconcile([], {
        afterId: max,
        throughId: Number.POSITIVE_INFINITY,
      });
    }
  }
  const scanFence = paged ? (state.scanFence() ?? Number.POSITIVE_INFINITY) : 0;
  const listed = paged
    ? paged.call(deps.storage, { afterId: scanAfter, limit: scanBudget })
    : deps.storage.findUnsynced();
  const entries = paged ? listed.filter((e) => e.id <= scanFence) : listed;
  // The window is full only if it filled the budget and stayed inside the
  // fence; otherwise the sweep has listed everything up to its fence.
  const windowFull =
    paged !== undefined &&
    listed.length >= scanBudget &&
    entries.length === listed.length;
  // Tracked state is dropped for rows that are gone or were rewritten. After a
  // partial window only the id range actually listed counts, so backoff of
  // rows beyond it survives; a window that reached the end covers the rest.
  const scanned = paged
    ? {
        afterId: scanAfter,
        throughId: windowFull
          ? Number(entries[entries.length - 1]?.id)
          : scanFence,
      }
    : undefined;
  state.reconcile(entries, scanned);
  // Markers of rows that are gone or rewritten go the same way.
  await attempts?.reconcile(entries, scanned);
  const plans = coalescePlan(deps, entries, clock());
  const results: UploadResult[] = [];

  /** Erase superseded snapshots and forget their upload state. */
  const supersede = async (head: IndexEntry) => {
    const older = olderUnsynced(deps, head);
    await eraseSuperseded(deps, older);
    for (const entry of older) state.clear(entry.path);
  };

  // Choose the batch: the first `batchSize` entries that can be worked on
  // now. Too-large, unsizable, stopped and backing-off entries are skipped
  // here and stay in the index untouched.
  interface Work {
    entry: IndexEntry;
    plan: CoalescedScope | undefined;
  }
  const batch: Work[] = [];
  const planned = new Set<string>();
  const selectedAt = clock();
  // Last listed row the selection looked at; the next window resumes after it.
  let lastLookedAt = scanAfter;
  let selectionStopped = false;
  for (const entry of entries) {
    if (batch.length >= batchSize) {
      selectionStopped = true;
      break;
    }
    lastLookedAt = Number(entry.id);
    const plan = plans.get(entry.scope);
    if (plan) {
      if (planned.has(entry.scope)) continue;
      planned.add(entry.scope);
      if (plan.deferred) continue;
      if (plan.head.dataPointId === null) {
        if (!state.shouldAttempt(plan.head.path, selectedAt)) continue;
      }
    } else if (!state.shouldAttempt(entry.path, selectedAt)) continue;
    // Entries that can never upload are classified here, from the index row
    // alone, so they cost no batch slot even the first time they are seen.
    if (holdBackTerminal(deps, state, plan ? plan.head : entry)) continue;
    // An entry whose attempts killed the process is skipped, not retried: it
    // would starve every entry behind it after each restart.
    const candidate = plan ? plan.head : entry;
    const crashed = attempts
      ?.quarantined()
      .find(
        (record) =>
          record.key === uploadAttemptKey(deps.serverOwner, candidate),
      );
    if (crashed) {
      state.markCrashed(
        {
          scope: crashed.scope,
          path: crashed.path,
          identity: identityOf(candidate),
        },
        crashed.interrupted,
        selectedAt,
      );
      continue;
    }
    batch.push({ entry, plan });
  }

  if (paged) {
    // Stopped early: resume right after the last row looked at. Looked at all
    // of a full window: continue past it. Reached the end of the sweep's
    // fence: start over with a new fence.
    const resumes = selectionStopped || windowFull;
    state.setScanCursor(resumes ? lastLookedAt : 0);
    if (!resumes) state.setScanFence(null);
  }

  for (const { entry, plan } of batch) {
    if (plan && plan.head.dataPointId !== null) {
      // The latest version is already published: older unpublished
      // snapshots are superseded, never published.
      await supersede(plan.head);
      continue;
    }
    const target = plan ? plan.head : entry;
    // Earlier entries may have taken minutes: judge this one at its own time.
    if (!state.shouldAttempt(target.path, clock())) continue;
    // A first attempt at an entry is new data: it releases the scope's
    // stopped entries to try again.
    if (!state.has(target.path)) state.releaseStopped(target.scope);
    try {
      // Durable before any body is built: if this attempt kills the process,
      // the next boot finds the marker and counts it.
      await attempts?.begin(target);
      const result = await withDeadline(
        options?.attemptDeadlineMs ?? DEFAULT_UPLOAD_ATTEMPT_DEADLINE_MS,
        (signal) => uploadOne(deps, target, { signal }),
      );
      results.push(result);
      state.clear(target.path);
      if (plan) await supersede(plan.head);
    } catch (err) {
      // A dropped orphan is a self-heal, not a failure: the row is already
      // gone, there is nothing to retry, and surfacing it would keep the
      // scope showing a scary error (and fail settle-waits) for a file the
      // user deleted on purpose. Already logged in uploadOne; swallow here.
      if (
        err instanceof OrphanedEntryError ||
        err instanceof DeletedScopeEntryError
      ) {
        state.clear(target.path);
        continue;
      }
      const error = err as Error;
      state.recordFailure(
        {
          scope: target.scope,
          path: target.path,
          identity: identityOf(target),
        },
        error.message,
        clock(),
      );
      options?.onError?.(entry, error);
      deps.logger.error(
        { path: entry.path, scope: entry.scope, error: error.message },
        "Failed to upload entry",
      );
      if (!state.shouldAttempt(target.path, Number.MAX_SAFE_INTEGER)) {
        deps.logger.warn(
          { path: target.path, scope: target.scope },
          "Stopped retrying the upload of an entry after repeated failures",
        );
      }
    } finally {
      // Settled (success, or a failure caught above): not a crash.
      await attempts?.settle(target).catch((err: unknown) => {
        deps.logger.warn(
          {
            path: target.path,
            error: err instanceof Error ? err.message : String(err),
          },
          "Could not clear an upload attempt marker",
        );
      });
    }
  }

  return results;
}
