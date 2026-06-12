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
 * Upload a single unsynced index entry:
 * 1. Read local data file from disk
 * 2. Resolve schemaId for the scope
 * 3. Derive scope key from master key → hex-encode as OpenPGP password
 * 4. Encrypt envelope with OpenPGP password-based encryption → ciphertext
 * 5. Compute dataHash / metadataHash commitments
 * 6. Upload ciphertext to storage backend, version-keyed `{scope}/{version}`
 * 7. Register DPv2 data point on-chain (AddData) if not already
 * 8. Persist the gateway-assigned dataPointId (marks the entry synced)
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
  //   dataHash     = keccak256 of the plaintext envelope JSON. Commits to the
  //                  canonical content, not the ciphertext — OpenPGP
  //                  password-based encryption embeds random salts so
  //                  re-encrypting the same plaintext yields different bytes;
  //                  hashing the plaintext keeps the on-chain commitment
  //                  reproducible across replicas serving the same version.
  //   metadataHash = keccak256 of canonical-JSON({scope, collectedAt, schemaId,
  //                  sizeBytes}). Commits to the off-chain metadata that
  //                  describes this version without leaking the payload.
  const dataHash = keccak256(plaintext);
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

  // 6. Upload ciphertext to storage backend FIRST, version-keyed so the
  // download worker can reconstruct the URL from a DataPointRecord's
  // (scope, expectedVersion) — DataPointRecords carry no URL. We upload
  // before registering so the on-chain data point (the synced marker) is
  // never stamped ahead of a blob that failed to land.
  const storageKey = `${entry.scope}/${entry.version}`;
  const url = await storageAdapter.upload(storageKey, encrypted);

  // 7. DPv2 data-point registration (idempotent — skipped when a prior run
  // already persisted a dataPointId on this entry). registerDataPoint stamps
  // the synced marker that excludes this entry from findUnsynced next time.
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

    // 8. Stamp the dataPointId on the local index entry — marks it synced.
    await storage.updateDataPointId(entry.path, dataPointId);
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
