import type { StorageAdapter } from "../../storage/adapters/interface.js";
import {
  deriveScopeKey,
  encryptWithPassword,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "pino";
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
}

export interface UploadAllOptions {
  batchSize?: number;
  onError?: (entry: IndexEntry, error: Error) => void;
}

/**
 * Upload a single unsynced index entry:
 * 1. Read local data file from disk
 * 2. Look up schema for the scope → get schemaId
 * 3. Derive scope key from master key → hex-encode as OpenPGP password
 * 4. Encrypt with OpenPGP password-based encryption → binary
 * 5. Upload OpenPGP binary to storage backend
 * 6. Sign file registration via EIP-712
 * 7. Register file record on-chain via Gateway (with schemaId)
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

  // 5. Upload to storage backend
  const storageKey = `${entry.scope}/${entry.collectedAt}`;
  const url = await storageAdapter.upload(storageKey, encrypted);

  // 6. Sign file registration via EIP-712
  const signature = await signer.signFileRegistration({
    ownerAddress: serverOwner as `0x${string}`,
    url,
    schemaId: schemaId as `0x${string}`,
  });

  // 7. Register file on-chain via Gateway
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
    { path: entry.path, fileId, url },
    "Uploaded and registered file",
  );

  return { path: entry.path, fileId, url };
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
