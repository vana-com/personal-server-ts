import { encodeAbiParameters, keccak256, stringToHex } from "viem";
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
  const envelope = await storage.readEnvelope(entry.scope, entry.collectedAt);

  // 2. Derive scope key → hex-encode as OpenPGP password
  const scopeKey = deriveScopeKey(masterKey, entry.scope);
  const scopeKeyHex = uint8ToHex(scopeKey);

  // 3. Encrypt with OpenPGP password-based encryption
  const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
  const encrypted = await encryptWithPassword(plaintext, scopeKeyHex);

  // 4. Compute the on-chain commitments.
  //   dataHash     = keccak256 of the plaintext envelope JSON. Commits to the
  //                  canonical content, not the ciphertext — OpenPGP
  //                  password-based encryption embeds random salts so
  //                  re-encrypting the same plaintext yields different bytes;
  //                  hashing the plaintext keeps the on-chain commitment
  //                  reproducible across replicas serving the same version.
  //   metadataHash = keccak256 of canonical-JSON({scope, collectedAt,
  //                  sizeBytes}). Commits to the off-chain metadata that
  //                  describes this version without leaking the payload. DPv2
  //                  is scope-addressed with no schema concept — the gateway
  //                  neither records nor registers schemas — so no schemaId is
  //                  looked up or committed.
  const dataHash = keccak256(plaintext);
  const metadataHash = keccak256(
    stringToHex(
      JSON.stringify({
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        sizeBytes: encrypted.byteLength,
      }),
    ),
  );

  // 5. Upload ciphertext to storage backend FIRST, version-keyed so the
  // download worker can reconstruct the URL from a DataPointRecord's
  // (scope, expectedVersion) — DataPointRecords carry no URL. We upload
  // before registering so the on-chain data point (the synced marker) is
  // never stamped ahead of a blob that failed to land.
  const storageKey = `${entry.scope}/${entry.version}`;
  let url = await storageAdapter.upload(storageKey, encrypted);

  // 6. DPv2 data-point registration (idempotent — skipped when a prior run
  // already persisted a dataPointId on this entry). registerDataPoint stamps
  // the synced marker that excludes this entry from findUnsynced next time.
  let dataPointId: string;
  if (entry.dataPointId) {
    dataPointId = entry.dataPointId;
  } else {
    const registerAt = async (version: bigint): Promise<string> => {
      const addDataSignature = await signer.signAddData({
        ownerAddress: serverOwner as `0x${string}`,
        scope: entry.scope,
        dataHash,
        metadataHash,
        expectedVersion: version,
      });

      const dataPointResult = await gateway.registerDataPoint({
        ownerAddress: serverOwner,
        scope: entry.scope,
        dataHash,
        metadataHash,
        expectedVersion: String(version),
        signature: addDataSignature,
      });

      const id = dataPointResult.dataPointId ?? null;
      if (!id) {
        throw new Error(
          `Gateway registerDataPoint did not return a dataPointId for ${entry.path} (scope=${entry.scope}, version=${version})`,
        );
      }
      return id;
    };

    try {
      dataPointId = await registerAt(BigInt(entry.version));
    } catch (err) {
      if (!isStaleVersionConflict(err)) throw err;
      // The registry's version for this (owner, scope) is ahead of the local
      // index: pre-DPv2 rows were backfilled to version 1, and other replicas
      // (PS Lite in the browser) advance the same per-scope sequence. The
      // gateway 409s precisely so the client can re-sign against the live
      // version — retrying the same version every cycle head-blocks the
      // scope's whole upload queue.
      const record = await gateway.getDataPoint(
        computeDataPointId(serverOwner, entry.scope),
      );

      if (record && record.dataHash.toLowerCase() === dataHash.toLowerCase()) {
        // Identical content is already registered (this entry, or a replica's
        // copy of it) — adopt the registered data point rather than minting a
        // new version of the same bytes.
        dataPointId = record.id;
        // Align the local row with the adopted registry version — downstream
        // consumers sign from the row's version (e.g. x402 RecordDataAccess),
        // so a stale local version would emit records the registry rejects.
        const adoptedVersion = Number(record.expectedVersion);
        if (adoptedVersion !== entry.version) {
          // Cross-replica adopt: "the registrant already uploaded the blob
          // under the registered version key" is an assumption, not a fact —
          // a replica that crashed between register and upload leaves a
          // registry row whose bytes 404 for every consumer (readers
          // reconstruct the URL from the record's (scope, expectedVersion);
          // records carry no URL). Verify, and heal from our identical
          // plaintext (dataHash matched, so our ciphertext decrypts to the
          // registered content).
          const adoptedKey = `${entry.scope}/${adoptedVersion}`;
          const adoptedBlobExists = await storageAdapter.exists(
            storageAdapter.urlForKey(adoptedKey),
          );
          if (!adoptedBlobExists) {
            logger.warn(
              { scope: entry.scope, version: adoptedVersion, dataPointId },
              "Adopted registry version has no blob in storage; re-uploading from local content",
            );
            url = await storageAdapter.upload(adoptedKey, encrypted);
          }
          await storage.updateEntryVersion(entry.path, adoptedVersion);
        }
      } else {
        // Rebase onto the gateway's live next-valid version. Two independent
        // signals for what that is:
        //   • the registry row — a replica racing AHEAD advances it past the
        //     version this error was raised against;
        //   • the 409 message itself — authoritative when the registry
        //     regressed BEHIND the local index (a moksha/DataRegistry reset,
        //     or duplicate re-snapshots pushing the local counter ahead), and
        //     the only signal at all when the reset left no row for
        //     getDataPoint to return (BUI-715).
        // Take the max so the scope converges from either direction; when
        // neither signal is available there is nothing to rebase onto, so
        // surface the conflict rather than guess.
        const recordNext = record ? Number(record.expectedVersion) + 1 : 0;
        const errorNext = parseGatewayNextVersion((err as Error).message) ?? 0;
        const target = Math.max(recordNext, errorNext);
        if (target <= 0) throw err;
        const rebased = BigInt(target);
        // The blob key embeds the version (replicas reconstruct URLs from the
        // registry record), so the rebased version needs its own blob; the one
        // written under the stale key above is orphaned, which storage
        // tolerates.
        url = await storageAdapter.upload(
          `${entry.scope}/${rebased}`,
          encrypted,
        );
        // A concurrent replica can still win the race to `rebased`; the next
        // sync cycle re-reads the registry and rebases again, so this stays
        // convergent without looping here.
        dataPointId = await registerAt(rebased);
        await storage.updateEntryVersion(entry.path, Number(rebased));
      }
    }

    // 7. Stamp the dataPointId on the local index entry — marks it synced.
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

// The gateway rejects a registration whose expectedVersion is not strictly
// greater than its stored value with a 409; the SDK client surfaces it as
// `Gateway error: 409 <detail>`. Anything else is not a version conflict.
function isStaleVersionConflict(err: unknown): err is Error {
  return err instanceof Error && /Gateway error: 409\b/.test(err.message);
}

// Extract the gateway's authoritative next-valid version from a 409 body so a
// rebase can target it directly instead of only inferring from a registry row
// (which is absent after a reset that dropped the scope's row entirely).
// Handles the current "Gap in version sequence … next valid version is N"
// phrasing (and its "effective max (M" form) as well as the older "Stale
// expectedVersion … must be strictly greater than the stored value N" one.
// Returns null when no version can be parsed.
export function parseGatewayNextVersion(message: string): number | null {
  const nextValid = message.match(/next valid version is (\d+)/i);
  if (nextValid) return Number(nextValid[1]);
  const effectiveMax = message.match(/effective max \((\d+)/i);
  if (effectiveMax) return Number(effectiveMax[1]) + 1;
  const storedValue = message.match(
    /strictly greater than the stored value (\d+)/i,
  );
  if (storedValue) return Number(storedValue[1]) + 1;
  return null;
}

/**
 * Deterministic DPv2 data-point id — `keccak256(abi.encode(owner, scope))`,
 * the same primary key DataRegistryV2 and the gateway use. Lets the upload
 * worker look up the registry's live row for a scope without a list call.
 */
export function computeDataPointId(
  ownerAddress: string,
  scope: string,
): `0x${string}` {
  // ABI-encoding an address is checksum-insensitive (same bytes either way),
  // but viem rejects mixed-case strings that fail checksum validation —
  // normalize so config-sourced owner strings can't trip it.
  return keccak256(
    encodeAbiParameters(
      [
        { name: "ownerAddress", type: "address" },
        { name: "scope", type: "string" },
      ],
      [ownerAddress.toLowerCase() as `0x${string}`, scope],
    ),
  );
}
