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
}

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

export interface UploadAllOptions {
  batchSize?: number;
  onError?: (entry: IndexEntry, error: Error) => void;
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
): Promise<UploadResult> {
  const {
    storage,
    storageAdapter,
    gateway,
    signer,
    masterKey,
    serverOwner,
    logger,
  } = deps;

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
        head: initialHead,
        readHead,
        checkHead,
        acknowledgedDeletionVersion:
          entry.afterTombstoneVersion == null
            ? undefined
            : BigInt(entry.afterTombstoneVersion),
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
 * Process all unsynced entries (dataPointId === null).
 * Processes sequentially to avoid overwhelming storage backend.
 * Returns array of results (skips failures, logs errors).
 */
export async function uploadAll(
  deps: UploadWorkerDeps,
  options?: UploadAllOptions,
): Promise<UploadResult[]> {
  const batchSize = options?.batchSize ?? 50;
  const entries = deps.storage.findUnsynced({ limit: batchSize });
  const results: UploadResult[] = [];

  for (const entry of entries) {
    try {
      const result = await uploadOne(deps, entry);
      results.push(result);
    } catch (err) {
      // A dropped orphan is a self-heal, not a failure: the row is already
      // gone, there is nothing to retry, and surfacing it would keep the
      // scope showing a scary error (and fail settle-waits) for a file the
      // user deleted on purpose. Already logged in uploadOne; swallow here.
      if (
        err instanceof OrphanedEntryError ||
        err instanceof DeletedScopeEntryError
      ) {
        continue;
      }
      const error = err as Error;
      options?.onError?.(entry, error);
      deps.logger.error(
        { path: entry.path, scope: entry.scope, error: error.message },
        "Failed to upload entry",
      );
    }
  }

  return results;
}
