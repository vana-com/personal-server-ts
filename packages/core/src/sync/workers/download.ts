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
  dataPointId: string;
  scope: string;
  collectedAt: string;
  path: string;
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
 * 7. Write to local filesystem via the runtime storage port
 * 8. Insert into local index (with dataPointId + version)
 */
export async function downloadOne(
  deps: DownloadWorkerDeps,
  record: DataPointRecord,
): Promise<DownloadResult | null> {
  const { storage, storageAdapter, masterKey, logger } = deps;

  // 1. Check dedup: skip if dataPointId already in local index
  const existing = storage.findByDataPointId(record.id);
  if (existing) {
    logger.debug(
      { dataPointId: record.id },
      "Data point already in index, skipping",
    );
    return null;
  }

  // 2. Reconstruct the version-keyed storage URL.
  const storageKey = `${record.scope}/${record.expectedVersion}`;
  const url = storageAdapter.urlForKey(storageKey);

  // 3. Download OpenPGP encrypted binary from storage backend
  const encrypted = await storageAdapter.download(url);

  // 4. Derive scope key → hex-encode as OpenPGP password
  const scopeKey = deriveScopeKey(masterKey, record.scope);
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
    if (existingByVersion.dataPointId !== record.id) {
      await storage.updateDataPointId(existingByVersion.path, record.id);
    }
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

  // 7. Write to local storage via the runtime storage port
  const { relativePath, sizeBytes } = await storage.writeEnvelope(envelope);

  // 8. Insert into local index (with dataPointId + version)
  await storage.insertEntry({
    fileId: null,
    schemaId: envelope.schemaId ?? null,
    path: relativePath,
    scope: envelope.scope,
    collectedAt: envelope.collectedAt,
    sizeBytes,
    version: Number(record.expectedVersion),
    dataPointId: record.id,
  });

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
 * Poll Gateway for new data points owned by this server since the stored
 * cursor, download each, and advance the cursor only when the page fully
 * succeeds.
 */
export async function downloadAll(
  deps: DownloadWorkerDeps,
): Promise<DownloadResult[]> {
  const { gateway, cursor, serverOwner, logger } = deps;

  // 1. Read cursor (opaque pagination cursor persisted across runs)
  const lastCursor = await cursor.read();

  // 2. Poll gateway for new data points
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

function uint8ToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
