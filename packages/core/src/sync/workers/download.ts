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

export interface DownloadWorkerDeps {
  storage: DataStoragePort;
  storageAdapter: StorageAdapter;
  gateway: GatewayClient;
  cursor: SyncCursor;
  masterKey: Uint8Array;
  serverOwner: string;
  logger: Logger;
}

export interface DownloadResult {
  fileId: string;
  scope: string;
  collectedAt: string;
  path: string;
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
  const { storage, storageAdapter, gateway, masterKey, logger } = deps;

  // 1. Check dedup: skip if fileId already in local index
  const existing = storage.findByFileId(record.fileId);
  if (existing) {
    logger.debug({ fileId: record.fileId }, "File already in index, skipping");
    return null;
  }

  // 2. Download OpenPGP encrypted binary from storage backend
  const encrypted = await storageAdapter.download(record.url);

  // 3. Resolve schemaId → scope via Gateway getSchema
  const schema = await gateway.getSchema(record.schemaId);
  if (!schema) {
    throw new Error(`No schema found for schemaId: ${record.schemaId}`);
  }

  // 4. Derive scope key → hex-encode as OpenPGP password
  const scopeKey = deriveScopeKey(masterKey, schema.scope);
  const scopeKeyHex = uint8ToHex(scopeKey);

  // 5. Decrypt with OpenPGP password-based decryption
  const plaintext = await decryptWithPassword(encrypted, scopeKeyHex);

  // 6. Parse as DataFileEnvelope (validate)
  const raw = JSON.parse(new TextDecoder().decode(plaintext));
  const envelope = DataFileEnvelopeSchema.parse(raw);

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
  const { relativePath, sizeBytes } = await storage.writeEnvelope(envelope);

  // 8. Insert into local index (with fileId)
  storage.insertEntry({
    fileId: record.fileId,
    schemaId: record.schemaId,
    path: relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes,
  });

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

  // 1. Read cursor
  const lastProcessedTimestamp = await cursor.read();

  // 2. Poll gateway for new file records
  const { files, cursor: nextCursor } = await gateway.listFilesSince(
    serverOwner,
    lastProcessedTimestamp,
  );

  const results: DownloadResult[] = [];
  let failed = false;

  // 3. Process each file record
  for (const file of files) {
    try {
      const result = await downloadOne(deps, file);
      if (result) {
        results.push(result);
      }
    } catch (err) {
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

function uint8ToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
