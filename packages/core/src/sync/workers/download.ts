import type { StorageAdapter } from "../../storage/adapters/interface.js";
import {
  DataFileEnvelopeSchema,
  decryptWithPassword,
  deriveScopeKey,
  type FileRecord,
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

/** Minimal diagnostics hook — keeps core free of lite-specific imports. */
export interface DownloadDiagnosticsHook {
  onDownloadStart(fileId: string): void;
  onDownloadEnd(fileId: string, scope: string): void;
  onDownloadError(fileId: string, detail: string): void;
  onDecryptStart(fileId: string, scope: string): void;
  onDecryptEnd(fileId: string, scope: string): void;
  onDecryptError(fileId: string, scope: string, detail: string): void;
  onIndexStart(fileId: string, scope: string): void;
  onIndexEnd(fileId: string, scope: string): void;
  onIndexError(fileId: string, scope: string, detail: string): void;
  onManifestBuildStart(fileId: string, scope: string): void;
  onManifestBuildEnd(fileId: string, scope: string): void;
  onManifestBuildError(fileId: string, scope: string, detail: string): void;
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
  fileId: string;
  scope: string;
  collectedAt: string;
  path: string;
}

interface SyncFailureMetadata {
  stage?: SyncFailureStage;
  scope?: string;
  payloadKind?: SyncPayloadKind;
  encryptedSizeBytes?: number;
}

/**
 * Download and process a single file record from the storage backend:
 * 1. Check dedup: skip if fileId already in local index
 * 2. Download OpenPGP encrypted binary from storage backend
 * 3. Resolve schemaId → scope via Gateway getSchema
 * 4. Derive scope key from master key → hex-encode as OpenPGP password
 * 5. Decrypt with OpenPGP password-based decryption → plaintext JSON
 * 6. Parse as DataFileEnvelope (validate)
 * 7. Write to local filesystem via hierarchy manager
 * 8. Insert into local index (with fileId)
 */
export async function downloadOne(
  deps: DownloadWorkerDeps,
  record: FileRecord,
): Promise<DownloadResult | null> {
  const { storage, storageAdapter, gateway, masterKey, logger, diagnostics } =
    deps;

  // 1. Check dedup: skip if fileId already in local index
  const existing = storage.findByFileId(record.fileId);
  if (existing) {
    await repairMissingBlockSidecars(
      storage,
      logger,
      record,
      existing,
      diagnostics,
    );
    logger.debug({ fileId: record.fileId }, "File already in index, skipping");
    return null;
  }

  // 2. Download OpenPGP encrypted binary from storage backend.
  // A download failure (404 or transient) throws and blocks the cursor — and that is correct here:
  // the delete cascade de-registers a file BEFORE deleting its blob, so any genuinely-deleted file
  // has deletedAt set and is excluded from this default (excludeDeleted) listing. Thus a 404 only
  // happens for an in-flight cross-device delete, which self-heals on the next cycle once the
  // de-register propagates and the file drops out of the list; a transient error blocks-and-retries
  // without losing data. We deliberately do NOT skip-on-404 here: the storage layer can't reliably
  // distinguish "gone" from "transiently unavailable", so skipping would risk a silent data gap
  // during an outage. (Cross-device removal of already-downloaded copies is slice 3b.)
  diagnostics?.onDownloadStart(record.fileId);
  let encrypted: Uint8Array;
  try {
    encrypted = await storageAdapter.download(record.url);
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onDownloadError(record.fileId, detail);
    throw err;
  }

  // 3. Resolve schemaId → scope via Gateway getSchema
  const schema = await gateway.getSchema(record.schemaId);
  if (!schema) {
    diagnostics?.onDownloadError(
      record.fileId,
      `No schema found for schemaId: ${record.schemaId}`,
    );
    throw new Error(`No schema found for schemaId: ${record.schemaId}`);
  }

  diagnostics?.onDownloadEnd(record.fileId, schema.scope);

  // 4. Derive scope key → hex-encode as OpenPGP password
  const scopeKey = deriveScopeKey(masterKey, schema.scope);
  const scopeKeyHex = uint8ToHex(scopeKey);

  // 5. Decrypt with OpenPGP password-based decryption
  diagnostics?.onDecryptStart(record.fileId, schema.scope);
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
    diagnostics?.onDecryptError(record.fileId, schema.scope, detail);
    throw withSyncFailureMetadata(err, {
      scope: schema.scope,
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
    diagnostics?.onDecryptError(record.fileId, schema.scope, detail);
    throw err;
  }
  diagnostics?.onDecryptEnd(record.fileId, envelope.scope);

  const existingByVersion = storage.findEntry({
    scope: envelope.scope,
    at: envelope.collectedAt,
  });
  if (
    existingByVersion !== undefined &&
    existingByVersion.collectedAt === envelope.collectedAt
  ) {
    if (existingByVersion.fileId !== record.fileId) {
      await storage.updateFileId(existingByVersion.path, record.fileId);
    }
    await repairMissingBlockSidecars(
      storage,
      logger,
      record,
      {
        ...existingByVersion,
        fileId: record.fileId,
        schemaId: existingByVersion.schemaId ?? record.schemaId,
      },
      diagnostics,
    );
    logger.debug(
      {
        fileId: record.fileId,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
      },
      "File version already exists locally, skipping",
    );
    return null;
  }

  // 7. Write to local storage via the runtime storage port
  diagnostics?.onIndexStart(record.fileId, envelope.scope);
  let relativePath: string;
  let sizeBytes: number;
  try {
    ({ relativePath, sizeBytes } = await storage.writeEnvelope(envelope));
    await writeBlockSidecars(
      storage,
      envelope,
      logger,
      record,
      relativePath,
      diagnostics,
    );
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onIndexError(record.fileId, envelope.scope, detail);
    throw err;
  }

  // 8. Insert into local index (with fileId)
  try {
    await storage.insertEntry({
      fileId: record.fileId,
      schemaId: record.schemaId,
      path: relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes,
    });
  } catch (err) {
    const detail = (err as Error).message;
    diagnostics?.onIndexError(record.fileId, envelope.scope, detail);
    throw err;
  }
  diagnostics?.onIndexEnd(record.fileId, envelope.scope);

  logger.info(
    { fileId: record.fileId, scope: envelope.scope, path: relativePath },
    "Downloaded and indexed file",
  );

  return {
    fileId: record.fileId,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    path: relativePath,
  };
}

/**
 * Poll Gateway for new file records since lastProcessedTimestamp,
 * download each, and advance the cursor only when the page fully succeeds.
 */
export async function downloadAll(
  deps: DownloadWorkerDeps,
): Promise<DownloadResult[]> {
  const { gateway, cursor, serverOwner, logger } = deps;
  const syncRunId = createSyncRunId();

  await repairLocalMissingBlockSidecars(deps);

  // 1. Read cursor
  const lastProcessedTimestamp = await cursor.read();

  // 2. Poll gateway for new file records, including soft-deleted ones so we can reconcile deletions
  // of files this device already holds (cross-device "deleted on desktop → gone on web too").
  const { files, cursor: nextCursor } = await gateway.listFilesSince(
    serverOwner,
    lastProcessedTimestamp,
    { includeDeleted: true },
  );

  const results: DownloadResult[] = [];
  let failed = false;

  // 3. Process each file record
  for (const file of files) {
    try {
      // Deletion reconciliation: a record marked deletedAt means the owner deleted it elsewhere.
      // Drop any local copy instead of downloading. Idempotent — no local copy is a no-op.
      if (file.deletedAt) {
        const removed = await deps.storage.deleteByFileId(file.fileId);
        if (removed) {
          logger.info(
            { fileId: file.fileId },
            "Reconciled remote deletion: removed local copy",
          );
        }
        continue;
      }
      const result = await downloadOne(deps, file);
      if (result) {
        results.push(result);
      }
    } catch (err) {
      const metadata = getSyncFailureMetadata(err);
      const classified = classifySyncFailure({
        error: err,
        fileId: file.fileId,
        schemaId: file.schemaId,
        syncRunId,
        stage: metadata.stage,
        scope: metadata.scope,
        payloadKind: metadata.payloadKind,
        encryptedSizeBytes: metadata.encryptedSizeBytes,
      });
      if (!classified.issue.retryable) {
        logger.warn(
          {
            fileId: file.fileId,
            schemaId: file.schemaId,
            scope: classified.issue.scope,
            stage: classified.issue.stage,
            payloadKind: classified.issue.payloadKind,
            encryptedSizeBytes: classified.issue.encryptedSizeBytes,
            errorClass: classified.issue.errorClass,
            message: classified.issue.message,
          },
          "Quarantined corrupt synced file",
        );
        continue;
      }
      logger.error(
        {
          fileId: file.fileId,
          schemaId: file.schemaId,
          error: (err as Error).message,
        },
        "Failed to download file",
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
      "Download cursor not advanced because one or more files failed",
    );
  }

  return results;
}

export async function repairLocalMissingBlockSidecars(
  deps: Pick<DownloadWorkerDeps, "storage" | "logger" | "diagnostics">,
): Promise<number> {
  const { storage, logger, diagnostics } = deps;
  if (!storage.writeBlockManifest || !storage.hasScopeBlocks) return 0;

  let repaired = 0;
  let offset = 0;
  const limit = 100;

  while (true) {
    const page = storage.listScopes({ limit, offset });
    for (const scopeSummary of page.scopes) {
      const entry = storage.findEntry({
        scope: scopeSummary.scope,
        at: scopeSummary.latestCollectedAt,
      });
      if (!entry) continue;

      const repairedScope = await repairMissingBlockSidecars(
        storage,
        logger,
        {
          fileId: entry.fileId ?? entry.path,
          owner: "",
          url: "",
          schemaId: entry.schemaId ?? "",
          createdAt: entry.createdAt,
        },
        entry,
        diagnostics,
      );
      if (repairedScope) repaired += 1;
    }

    offset += page.scopes.length;
    if (offset >= page.total || page.scopes.length === 0) break;
  }

  if (repaired > 0) {
    logger.info(
      { repaired },
      "Repaired missing bounded block sidecars for local indexed data",
    );
  }
  return repaired;
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
  record: FileRecord,
  relativePath: string,
  diagnostics?: DownloadDiagnosticsHook,
): Promise<void> {
  if (!storage.writeBlockManifest) return;

  diagnostics?.onManifestBuildStart(record.fileId, envelope.scope);
  try {
    const built = await buildDataBlocksAsync({
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      schemaId: record.schemaId,
      content: envelope,
    });
    await storage.writeBlockManifest(
      envelope.scope,
      envelope.collectedAt,
      built.manifest,
      built.blocks,
    );
    diagnostics?.onManifestBuildEnd(record.fileId, envelope.scope);
  } catch (error) {
    const classified = classifySyncFailure({
      error,
      fileId: record.fileId,
      syncRunId: "download",
      stage: "block_build",
      schemaId: record.schemaId,
      scope: envelope.scope,
    });
    diagnostics?.onManifestBuildError(
      record.fileId,
      envelope.scope,
      classified.issue.message,
    );
    logger.warn(
      {
        fileId: record.fileId,
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
  record: FileRecord,
  entry: {
    scope: string;
    collectedAt: string;
    fileId: string | null;
    schemaId: string | null;
    path: string;
  },
  diagnostics?: DownloadDiagnosticsHook,
): Promise<boolean> {
  if (!storage.writeBlockManifest || !storage.hasScopeBlocks) return false;

  let hasBlocks = false;
  try {
    hasBlocks = await storage.hasScopeBlocks(entry.scope, entry.collectedAt);
  } catch (error) {
    logger.warn(
      {
        fileId: entry.fileId ?? record.fileId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair skipped after readiness check failed",
    );
    return false;
  }
  if (hasBlocks) return false;

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
        fileId: entry.fileId ?? record.fileId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair skipped because local envelope is unavailable",
    );
    return false;
  }

  await writeBlockSidecars(
    storage,
    envelope,
    logger,
    {
      ...record,
      fileId: entry.fileId ?? record.fileId,
      schemaId: entry.schemaId ?? record.schemaId,
    },
    entry.path,
    diagnostics,
  );

  try {
    return await storage.hasScopeBlocks(entry.scope, entry.collectedAt);
  } catch (error) {
    logger.warn(
      {
        fileId: entry.fileId ?? record.fileId,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        error: (error as Error).message,
      },
      "Bounded block sidecar repair completed but readiness could not be verified",
    );
    return false;
  }
}
