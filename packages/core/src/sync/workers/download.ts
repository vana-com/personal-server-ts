import type { StorageAdapter } from "../../storage/adapters/interface.js";
import {
  DataFileEnvelopeSchema,
  decryptWithPassword,
  deriveScopeKey,
  type DataPointRecord,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { SyncCursor } from "../cursor.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import { buildDataBlocksAsync } from "../../storage/blocks/build.js";
import {
  classifySyncFailure,
  inferPayloadKind,
  type SyncFailureStage,
  type SyncPayloadKind,
} from "../issues.js";

/**
 * Minimal diagnostics hook — keeps core free of lite-specific imports.
 *
 * Note: the `id` params are the DPv2 data-point id (the stable identifier for a
 * synced item under the DataPoint model). The param name is kept generic-ish
 * for the lite diagnostics consumers that predate the file→DataPoint rename.
 */
export interface DownloadDiagnosticsHook {
  onDownloadStart(id: string): void;
  onDownloadEnd(id: string, scope: string): void;
  onDownloadError(id: string, detail: string): void;
  onDecryptStart(id: string, scope: string): void;
  onDecryptEnd(id: string, scope: string): void;
  onDecryptError(id: string, scope: string, detail: string): void;
  onIndexStart(id: string, scope: string): void;
  onIndexEnd(id: string, scope: string): void;
  onIndexError(id: string, scope: string, detail: string): void;
  onManifestBuildStart(id: string, scope: string): void;
  onManifestBuildEnd(id: string, scope: string): void;
  onManifestBuildError(id: string, scope: string, detail: string): void;
  onRepair(scope: string, detail: string): void;
}

export interface DownloadWorkerDeps {
  storage: DataStoragePort;
  storageAdapter: StorageAdapter;
  gateway: GatewayClient;
  cursor: SyncCursor;
  masterKey: Uint8Array;
  serverOwner: string;
  logger: Logger;
  /** Optional diagnostics hook — omit to disable instrumentation. */
  diagnostics?: DownloadDiagnosticsHook;
}

export interface DownloadResult {
  dataPointId: string;
  scope: string;
  collectedAt: string;
  path: string;
}

export interface DownloadAllOptions {
  /**
   * Ignore the stored incremental cursor and reconcile from the beginning of
   * the owner's data-point registry. This repairs browser caches whose cursor
   * advanced while local IndexedDB/OPFS lost or failed to index some records.
   */
  fullReconcile?: boolean;
}

interface SyncFailureMetadata {
  stage?: SyncFailureStage;
  scope?: string;
  payloadKind?: SyncPayloadKind;
  encryptedSizeBytes?: number;
}

type MissingBlockRepairResult =
  "already-ready" | "repaired" | "missing-envelope" | "not-repaired";

interface LocalMissingBlockRepairSummary {
  repaired: number;
  missingEnvelopeEntries: number;
}

/**
 * Context threaded into the block-sidecar helpers. Under the DataPoint model a
 * synced item is identified by its data-point id; schemaId (if known) feeds the
 * bounded-block manifest builder.
 */
interface RecordContext {
  dataPointId: string;
  schemaId: string | null;
}

/**
 * Download and process a single DPv2 data point from the storage backend:
 * 1. Check dedup: skip if dataPointId already in local index
 * 2. Reconstruct the blob URL from (scope, expectedVersion) — DataPointRecords
 *    carry no URL, so we rebuild the version-keyed `{scope}/{version}` key the
 *    upload worker wrote under and resolve it via storageAdapter.urlForKey
 * 3. Download the OpenPGP encrypted binary from storage
 * 4. Derive scope key from master key → hex-encode as OpenPGP password
 *    (scope comes straight off the record — no schema lookup needed)
 * 5. Decrypt with OpenPGP password-based decryption → plaintext JSON
 * 6. Parse as DataFileEnvelope (validate)
 * 7. Write to local filesystem + bounded block sidecars
 * 8. Insert into local index (with dataPointId + version)
 */
export async function downloadOne(
  deps: DownloadWorkerDeps,
  record: DataPointRecord,
): Promise<DownloadResult | null> {
  const { storage, storageAdapter, masterKey, logger, diagnostics } = deps;
  const ctx: RecordContext = { dataPointId: record.id, schemaId: null };

  // 1. Check dedup: skip if dataPointId already in local index
  const existing = storage.findByDataPointId(record.id);
  if (existing) {
    const repairResult = await repairMissingBlockSidecars(
      storage,
      logger,
      { dataPointId: record.id, schemaId: existing.schemaId },
      existing,
      diagnostics,
    );
    if (repairResult === "missing-envelope") {
      logger.warn(
        {
          dataPointId: record.id,
          scope: existing.scope,
          collectedAt: existing.collectedAt,
        },
        "Local index entry was missing its envelope; re-downloading data point",
      );
    } else {
      logger.debug(
        { dataPointId: record.id },
        "Data point already in index, skipping",
      );
      return null;
    }
  }

  // 2. Reconstruct the version-keyed storage URL.
  const storageKey = `${record.scope}/${record.expectedVersion}`;
  const url = storageAdapter.urlForKey(storageKey);

  // 3. Download OpenPGP encrypted binary from storage backend. A download
  // failure throws and blocks the cursor (correct: a transient error retries
  // next cycle rather than risk a silent gap).
  diagnostics?.onDownloadStart(record.id);
  let encrypted: Uint8Array;
  try {
    encrypted = await storageAdapter.download(url);
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onDownloadError(record.id, detail);
    throw err;
  }
  diagnostics?.onDownloadEnd(record.id, record.scope);

  // 4. Derive scope key → hex-encode as OpenPGP password (scope off the record)
  const scopeKey = deriveScopeKey(masterKey, record.scope);
  const scopeKeyHex = uint8ToHex(scopeKey);

  // 5. Decrypt with OpenPGP password-based decryption
  diagnostics?.onDecryptStart(record.id, record.scope);
  let plaintext: Uint8Array;
  try {
    plaintext = await decryptWithPassword(encrypted, scopeKeyHex);
  } catch (err) {
    const payloadKind = inferPayloadKind(encrypted);
    const encryptedSizeBytes = encrypted.byteLength;
    const detail = [
      (err as Error).message,
      `payloadKind=${payloadKind}`,
      `encryptedSizeBytes=${encryptedSizeBytes}`,
    ].join("; ");
    diagnostics?.onDecryptError(record.id, record.scope, detail);
    throw withSyncFailureMetadata(err, {
      scope: record.scope,
      payloadKind,
      encryptedSizeBytes,
    });
  }

  // 6. Parse as DataFileEnvelope (validate)
  let envelope: ReturnType<typeof DataFileEnvelopeSchema.parse>;
  try {
    const raw = JSON.parse(new TextDecoder().decode(plaintext));
    envelope = DataFileEnvelopeSchema.parse(raw);
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onDecryptError(record.id, record.scope, detail);
    throw err;
  }
  ctx.schemaId = envelope.schemaId ?? null;
  diagnostics?.onDecryptEnd(record.id, envelope.scope);

  const existingByVersion = storage.findEntry({
    scope: envelope.scope,
    at: envelope.collectedAt,
  });
  if (
    existingByVersion !== undefined &&
    existingByVersion.collectedAt === envelope.collectedAt
  ) {
    if (existingByVersion.dataPointId !== record.id) {
      await storage.updateDataPointId(existingByVersion.path, record.id);
    }
    const repairResult = await repairMissingBlockSidecars(
      storage,
      logger,
      {
        dataPointId: record.id,
        schemaId: existingByVersion.schemaId ?? ctx.schemaId,
      },
      existingByVersion,
      diagnostics,
    );
    if (repairResult !== "missing-envelope") {
      logger.debug(
        {
          dataPointId: record.id,
          scope: envelope.scope,
          collectedAt: envelope.collectedAt,
        },
        "Data version already exists locally, skipping",
      );
      return null;
    }
    logger.warn(
      {
        dataPointId: record.id,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
      },
      "Local version entry was missing its envelope; rewriting downloaded file",
    );
  }

  // 7. Write to local storage + bounded block sidecars
  diagnostics?.onIndexStart(record.id, envelope.scope);
  let relativePath: string;
  let sizeBytes: number;
  try {
    ({ relativePath, sizeBytes } = await storage.writeEnvelope(envelope));
    await writeBlockSidecars(
      storage,
      envelope,
      logger,
      ctx,
      relativePath,
      diagnostics,
    );
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onIndexError(record.id, envelope.scope, detail);
    throw err;
  }

  // 8. Insert into local index (with dataPointId + version)
  try {
    await storage.insertEntry({
      fileId: null,
      schemaId: ctx.schemaId,
      path: relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes,
      version: Number(record.expectedVersion),
      dataPointId: record.id,
    });
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onIndexError(record.id, envelope.scope, detail);
    throw err;
  }
  diagnostics?.onIndexEnd(record.id, envelope.scope);

  logger.info(
    { dataPointId: record.id, scope: envelope.scope, path: relativePath },
    "Downloaded and indexed data point",
  );

  return {
    dataPointId: record.id,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    path: relativePath,
  };
}

/**
 * Poll Gateway for the owner's data points since the stored cursor, download
 * each, and advance the cursor only when the page fully succeeds.
 */
export async function downloadAll(
  deps: DownloadWorkerDeps,
  options: DownloadAllOptions = {},
): Promise<DownloadResult[]> {
  const { gateway, cursor, serverOwner, logger } = deps;
  const syncRunId = createSyncRunId();

  const repairSummary = await repairLocalMissingBlockSidecars(deps);

  // 1. Read cursor (opaque pagination cursor persisted across runs)
  const lastCursor =
    options.fullReconcile || repairSummary.missingEnvelopeEntries > 0
      ? null
      : await cursor.read();
  if (options.fullReconcile) {
    logger.info(
      "Running full registry reconciliation to repair any missing local scope records",
    );
  }
  if (repairSummary.missingEnvelopeEntries > 0) {
    logger.warn(
      { missingEnvelopeEntries: repairSummary.missingEnvelopeEntries },
      "Resetting this sync listing to repair stale local index entries",
    );
  }

  // 2. Poll gateway for the owner's data points.
  const { dataPoints, cursor: nextCursor } =
    await gateway.listDataPointsByOwner(serverOwner, lastCursor);

  const results: DownloadResult[] = [];
  let failed = false;

  // 3. Process each data point record
  for (const dataPoint of dataPoints) {
    try {
      const result = await downloadOne(deps, dataPoint);
      if (result) {
        results.push(result);
      }
    } catch (err) {
      const metadata = getSyncFailureMetadata(err);
      const classified = classifySyncFailure({
        error: err,
        fileId: dataPoint.id,
        syncRunId,
        stage: metadata.stage,
        scope: metadata.scope ?? dataPoint.scope,
        payloadKind: metadata.payloadKind,
        encryptedSizeBytes: metadata.encryptedSizeBytes,
      });
      if (!classified.issue.retryable) {
        logger.warn(
          {
            dataPointId: dataPoint.id,
            scope: classified.issue.scope,
            stage: classified.issue.stage,
            payloadKind: classified.issue.payloadKind,
            encryptedSizeBytes: classified.issue.encryptedSizeBytes,
            errorClass: classified.issue.errorClass,
            message: classified.issue.message,
          },
          "Quarantined corrupt synced data point",
        );
        continue;
      }
      logger.error(
        {
          dataPointId: dataPoint.id,
          scope: dataPoint.scope,
          error: (err as Error).message,
        },
        "Failed to download data point",
      );
      failed = true;
    }
  }

  // 4. Advance cursor only when every record in the page was handled.
  if (nextCursor !== null && !failed) {
    await cursor.write(nextCursor);
  } else if (failed) {
    logger.warn(
      { nextCursor },
      "Download cursor not advanced because one or more data points failed",
    );
  }

  return results;
}

export async function repairLocalMissingBlockSidecars(
  deps: Pick<DownloadWorkerDeps, "storage" | "logger" | "diagnostics">,
): Promise<LocalMissingBlockRepairSummary> {
  const { storage, logger, diagnostics } = deps;
  if (!storage.writeBlockManifest || !storage.hasScopeBlocks) {
    return { repaired: 0, missingEnvelopeEntries: 0 };
  }

  let repaired = 0;
  let missingEnvelopeEntries = 0;
  let offset = 0;
  const limit = 100;

  while (true) {
    const page = storage.listScopes({ limit, offset });
    let deletedEntryInPage = false;
    for (const scopeSummary of page.scopes) {
      const entry = storage.findEntry({
        scope: scopeSummary.scope,
        at: scopeSummary.latestCollectedAt,
      });
      if (!entry) continue;

      const repairResult = await repairMissingBlockSidecars(
        storage,
        logger,
        {
          dataPointId: entry.dataPointId ?? entry.path,
          schemaId: entry.schemaId,
        },
        entry,
        diagnostics,
      );
      if (repairResult === "repaired") repaired += 1;
      if (repairResult === "missing-envelope") {
        missingEnvelopeEntries += 1;
        deletedEntryInPage = true;
      }
    }

    if (!deletedEntryInPage) {
      offset += page.scopes.length;
    }
    if (offset >= page.total || page.scopes.length === 0) break;
  }

  if (repaired > 0) {
    logger.info(
      { repaired },
      "Repaired missing bounded block sidecars for local indexed data",
    );
  }
  if (missingEnvelopeEntries > 0) {
    logger.warn(
      { missingEnvelopeEntries },
      "Removed stale local index entries missing local envelopes",
    );
  }
  return { repaired, missingEnvelopeEntries };
}

function createSyncRunId(): string {
  return typeof crypto !== "undefined" &&
    typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `download-${Date.now().toString(36)}`;
}

function uint8ToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function withSyncFailureMetadata(
  error: unknown,
  metadata: SyncFailureMetadata,
): unknown {
  if (error instanceof Error) {
    Object.assign(error, { syncFailureMetadata: metadata });
    return error;
  }
  return { error, syncFailureMetadata: metadata };
}

function getSyncFailureMetadata(error: unknown): SyncFailureMetadata {
  if (typeof error !== "object" || error === null) return {};
  const metadata = (error as { syncFailureMetadata?: unknown })
    .syncFailureMetadata;
  if (typeof metadata !== "object" || metadata === null) return {};
  return metadata as SyncFailureMetadata;
}

async function writeBlockSidecars(
  storage: DataStoragePort,
  envelope: {
    scope: string;
    collectedAt: string;
    data: unknown;
    version?: string;
  },
  logger: Logger,
  ctx: RecordContext,
  relativePath: string,
  diagnostics?: DownloadDiagnosticsHook,
): Promise<void> {
  if (!storage.writeBlockManifest) return;

  diagnostics?.onManifestBuildStart(ctx.dataPointId, envelope.scope);
  try {
    const built = await buildDataBlocksAsync({
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      schemaId: ctx.schemaId ?? undefined,
      content: envelope,
    });
    await storage.writeBlockManifest(
      envelope.scope,
      envelope.collectedAt,
      built.manifest,
      built.blocks,
    );
    diagnostics?.onManifestBuildEnd(ctx.dataPointId, envelope.scope);
  } catch (error) {
    const classified = classifySyncFailure({
      error,
      fileId: ctx.dataPointId,
      syncRunId: "download",
      stage: "block_build",
      schemaId: ctx.schemaId ?? undefined,
      scope: envelope.scope,
    });
    diagnostics?.onManifestBuildError(
      ctx.dataPointId,
      envelope.scope,
      classified.issue.message,
    );
    logger.warn(
      {
        dataPointId: ctx.dataPointId,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        path: relativePath,
        stage: classified.issue.stage,
        errorClass: classified.issue.errorClass,
        message: classified.issue.message,
      },
      "Bounded block sidecar write failed after raw envelope write",
    );
  }
}

async function repairMissingBlockSidecars(
  storage: DataStoragePort,
  logger: Logger,
  ctx: RecordContext,
  entry: {
    scope: string;
    collectedAt: string;
    fileId: string | null;
    schemaId: string | null;
    path: string;
  },
  diagnostics?: DownloadDiagnosticsHook,
): Promise<MissingBlockRepairResult> {
  if (!storage.writeBlockManifest || !storage.hasScopeBlocks) {
    return "not-repaired";
  }

  let hasBlocks = false;
  try {
    hasBlocks = await storage.hasScopeBlocks(entry.scope, entry.collectedAt);
  } catch (error) {
    logger.warn(
      {
        dataPointId: ctx.dataPointId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair skipped after readiness check failed",
    );
    return "not-repaired";
  }
  if (hasBlocks) return "already-ready";

  diagnostics?.onRepair(
    entry.scope,
    "indexed entry missing block manifest; rebuilding from local envelope",
  );

  let envelope: Awaited<ReturnType<DataStoragePort["readEnvelope"]>>;
  try {
    envelope = await storage.readEnvelope(entry.scope, entry.collectedAt);
  } catch (error) {
    logger.warn(
      {
        dataPointId: ctx.dataPointId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair skipped because local envelope is unavailable",
    );
    // Remove the stale index entry whose payload is gone. We can only target
    // it by gateway fileId; DataPoint-only entries (fileId === null) are left
    // in place (no path-keyed delete on the port) and self-heal on re-download.
    if (entry.fileId) {
      diagnostics?.onRepair(
        entry.scope,
        "index exists without local payload; removing stale local index entry",
      );
      const removed = await storage.deleteByFileId(entry.fileId);
      logger.warn(
        {
          dataPointId: ctx.dataPointId,
          scope: entry.scope,
          collectedAt: entry.collectedAt,
          removed,
        },
        "Removed stale local index entry missing local envelope",
      );
      return removed ? "missing-envelope" : "not-repaired";
    }
    return "not-repaired";
  }

  await writeBlockSidecars(
    storage,
    envelope,
    logger,
    {
      dataPointId: ctx.dataPointId,
      schemaId: entry.schemaId ?? ctx.schemaId,
    },
    entry.path,
    diagnostics,
  );

  try {
    return (await storage.hasScopeBlocks(entry.scope, entry.collectedAt))
      ? "repaired"
      : "not-repaired";
  } catch (error) {
    logger.warn(
      {
        dataPointId: ctx.dataPointId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair completed but readiness could not be verified",
    );
    return "not-repaired";
  }
}
