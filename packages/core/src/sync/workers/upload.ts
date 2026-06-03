import { keccak256, stringToHex } from "viem";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import {
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { DataStoragePort } from "../../ports/index.js";

export interface UploadWorkerDeps {
  storage: DataStoragePort;
  storageAdapter: StorageAdapter;
  gateway: GatewayClient;
  signer: ServerSigner;
  masterKey: Uint8Array;
  serverOwner: string;
  logger: Logger;
}

export interface UploadResult {
  path: string;
  fileId: string;
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
 * Upload a single unsynced index entry:
 * 1. Read local data file from disk
 * 2. Resolve schemaId for the scope
 * 3. Derive scope key from master key → hex-encode as OpenPGP password
 * 4. Encrypt envelope with OpenPGP password-based encryption → ciphertext
 * 5. Register DPv2 data point on-chain (AddData) if not already, persist dataPointId
 * 6. Upload ciphertext to storage backend
 * 7. Sign file registration (EIP-712) and call Gateway registerFile
 * 8. Update local index with fileId
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
  const envelope = await storage.readEnvelope(entry.scope, entry.collectedAt);

  // 2. Resolve schemaId from the local index when available, or fall back
  // to the Gateway for legacy entries created before schema IDs were indexed.
  let schemaId = entry.schemaId;
  if (!schemaId) {
    const schema = await gateway.getSchemaForScope(entry.scope);
    if (!schema) {
      throw new Error(`No schema found for scope: ${entry.scope}`);
    }
    schemaId = schema.id;
  }

  // 3. Derive scope key → hex-encode as OpenPGP password
  const scopeKey = deriveScopeKey(masterKey, entry.scope);
  const scopeKeyHex = uint8ToHex(scopeKey);

  // 4. Encrypt with OpenPGP password-based encryption
  const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
  const encrypted = await encryptWithPassword(plaintext, scopeKeyHex);

  // 5. DPv2 data-point registration (idempotent — skipped when the prior run
  // already persisted a dataPointId on this entry).
  //
  // Commitments:
  //   dataHash     = keccak256 of the ciphertext that gets uploaded to storage.
  //                  Binds the on-chain version to the exact bytes we'll serve.
  //   metadataHash = keccak256 of canonical-JSON({scope, collectedAt, schemaId,
  //                  sizeBytes}). Commits to the off-chain metadata that
  //                  describes this version without leaking the payload.
  const dataHash = keccak256(encrypted);
  const metadataHash = keccak256(
    stringToHex(
      JSON.stringify({
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        schemaId,
        sizeBytes: encrypted.byteLength,
      }),
    ),
  );

  let dataPointId = entry.dataPointId;
  if (!dataPointId) {
    const addDataSignature = await signer.signAddData({
      ownerAddress: serverOwner as `0x${string}`,
      scope: entry.scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(entry.version),
    });

    const dataPointResult = await gateway.registerDataPoint({
      ownerAddress: serverOwner,
      scope: entry.scope,
      dataHash,
      metadataHash,
      expectedVersion: String(entry.version),
      signature: addDataSignature,
    });

    dataPointId = dataPointResult.dataPointId ?? null;
    if (!dataPointId) {
      throw new Error(
        `Gateway registerDataPoint did not return a dataPointId for ${entry.path} (scope=${entry.scope}, version=${entry.version})`,
      );
    }

    await storage.updateDataPointId(entry.path, dataPointId);

    logger.info(
      {
        path: entry.path,
        scope: entry.scope,
        version: entry.version,
        dataPointId,
      },
      "Registered DPv2 data point",
    );
  }

  // 6. Upload to storage backend
  const storageKey = `${entry.scope}/${entry.collectedAt}`;
  const url = await storageAdapter.upload(storageKey, encrypted);

  // 7. Sign file registration via EIP-712, then register on-chain via Gateway
  const signature = await signer.signFileRegistration({
    ownerAddress: serverOwner as `0x${string}`,
    url,
    schemaId: schemaId as `0x${string}`,
  });

  const registration = await gateway.registerFile({
    ownerAddress: serverOwner,
    url,
    schemaId,
    signature,
  });

  const fileId = registration.fileId;
  if (!fileId) {
    throw new Error(
      `Gateway registerFile did not return a fileId for ${entry.path}`,
    );
  }

  // 8. Update local index with fileId
  await storage.updateFileId(entry.path, fileId);

  logger.info(
    { path: entry.path, fileId, url, dataPointId },
    "Uploaded and registered file",
  );

  return { path: entry.path, fileId, url, dataPointId };
}

/**
 * Process all unsynced entries (fileId === null).
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

function uint8ToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}
