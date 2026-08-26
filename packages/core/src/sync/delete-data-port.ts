import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import type {
  DataPointFeedPort,
  DeleteBlobVersionsOutcome,
  DeleteDataPort,
  TombstoneOutcome,
} from "../ports/index.js";
import type { ServerSigner } from "../signing/signer.js";
import { computeDataPointId } from "./data-point-id.js";
import { parseGatewayNextVersion } from "./workers/upload.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";

export interface GatewayDeleteDataPortOptions {
  /** Gateway base URL, e.g. https://dp-rpc.vana.org */
  gatewayUrl: string;
  /** Deletion-aware registry lookup (current version + deleted state). */
  dataPointFeed: DataPointFeedPort;
  /** Data owner the tombstone is registered on behalf of. */
  serverOwner: `0x${string}`;
  /**
   * The same signer the upload worker uses for AddData: the personal server
   * account, which the registry trusts for this owner. Reused as-is so a
   * tombstone is signed exactly like a normal registration.
   */
  signer: Pick<ServerSigner, "signAddData">;
  storage: {
    /** vana-storage base URL, e.g. https://storage.vana.org */
    endpoint: string;
    /** Protocol chain id; blob paths are chain-scoped. */
    chainId: number;
    /**
     * EIP-191 signer for the Web3Signed storage auth. The same account the
     * storage provider uploads with (the server account), so the DELETE is
     * authorised the way PUT is.
     */
    signMessage(message: string): Promise<`0x${string}`>;
  };
  /** Test seam; defaults to the global fetch. */
  fetch?: typeof fetch;
}

/**
 * Remote deletion against the DPv2 gateway + vana-storage.
 *
 * Gateway (durable fact):
 *   DELETE {gateway}/v1/data/{dataPointId}
 *   Authorization: Web3Signed {signature}
 *   { ownerAddress, scope, expectedVersion, signature }
 * where signature = EIP-712 AddData over
 *   { ownerAddress, scope, dataHash: TOMBSTONE_DATA_HASH,
 *     metadataHash: TOMBSTONE_METADATA_HASH, expectedVersion: current + 1 }
 *
 * Storage (one exact blob per version, never the scope prefix):
 *   DELETE {storage}/v1/chains/{chainId}/blobs/{owner}/{scope}/{version}
 *   authorization: Web3Signed (aud = storage endpoint, uri = that path)
 * The path is the one the SDK's vana-storage provider uploads to: lowercased
 * owner, every key segment URI-encoded; vana-storage resolves a three-segment
 * path as a single-object delete and answers 404 when the object is absent.
 */
export function createGatewayDeleteDataPort(
  options: GatewayDeleteDataPortOptions,
): DeleteDataPort {
  const gatewayBase = options.gatewayUrl.replace(/\/+$/, "");
  const storageBase = options.storage.endpoint.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  // The storage provider lowercases the owner in blob paths; match it or the
  // exact DELETE keys would not be the ones PUT wrote.
  const owner = options.serverOwner.toLowerCase() as `0x${string}`;

  async function sendTombstone(
    scope: string,
    dataPointId: string,
    version: bigint,
  ): Promise<Response> {
    const signature = await options.signer.signAddData({
      ownerAddress: options.serverOwner,
      scope,
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      expectedVersion: version,
    });
    return fetchImpl(`${gatewayBase}/v1/data/${dataPointId}`, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Web3Signed ${signature}`,
      },
      body: JSON.stringify({
        ownerAddress: options.serverOwner,
        scope,
        expectedVersion: String(version),
        signature,
      }),
    });
  }

  return {
    async tombstone(scope: string): Promise<TombstoneOutcome> {
      const dataPointId = computeDataPointId(options.serverOwner, scope);
      const current = await options.dataPointFeed.getDataPoint({
        ownerAddress: options.serverOwner,
        scope,
      });
      if (current === null) {
        return { status: "not-registered", dataPointId };
      }
      if (current.deletedAt !== null) {
        return {
          status: "already-deleted",
          dataPointId,
          version: current.expectedVersion,
          deletedAt: current.deletedAt,
        };
      }

      let version = BigInt(current.expectedVersion) + 1n;
      let res = await sendTombstone(scope, dataPointId, version);
      if (res.status === 409) {
        // Another replica advanced the scope between our read and our
        // write. The 409 body carries `currentExpectedVersion` (and the
        // legacy message phrasing names the next valid version); re-sign
        // once against it.
        const body = await res.json().catch(() => null);
        const conflict = unwrap(body);
        // Gateway 409 body: `nextExpectedVersion` is the version to sign
        // next; `currentExpectedVersion` is the version the gateway holds,
        // so it needs +1. Prefer the explicit next, fall back to current+1,
        // then to the legacy message phrasing.
        const nextExplicit =
          integerField(conflict, "nextExpectedVersion") ??
          integerField(body, "nextExpectedVersion");
        const currentExpected =
          integerField(conflict, "currentExpectedVersion") ??
          integerField(body, "currentExpectedVersion");
        const legacyNext = parseGatewayNextVersion(
          detailFromBody(body, res.statusText),
        );
        const next =
          nextExplicit !== null
            ? nextExplicit
            : currentExpected !== null
              ? currentExpected + 1n
              : legacyNext !== null
                ? BigInt(legacyNext)
                : null;
        if (next === null) {
          throw new Error(
            `Gateway error: 409 ${detailFromBody(body, res.statusText)}`,
          );
        }
        version = next;
        res = await sendTombstone(scope, dataPointId, version);
      }
      if (res.status === 404) {
        // The registry lost the row between our read and our write (or the
        // feed answered from a replica ahead of the writer): nothing to
        // tombstone.
        return { status: "not-registered", dataPointId };
      }
      if (res.status === 410) {
        // Raced with a concurrent deletion: the point is already gone.
        const body = await res.json().catch(() => null);
        return {
          status: "already-deleted",
          dataPointId,
          version: String(version),
          deletedAt: stringField(unwrap(body), "deletedAt"),
        };
      }
      if (!res.ok) {
        throw new Error(
          `Gateway error: ${res.status} ${await errorDetail(res)}`,
        );
      }
      const body = await res.json().catch(() => null);
      const row = unwrap(body);
      return {
        status: "tombstoned",
        dataPointId: stringField(row, "dataPointId") ?? dataPointId,
        version: stringField(row, "expectedVersion") ?? String(version),
        deletedAt: stringField(row, "deletedAt"),
      };
    },

    async deleteBlobVersions(
      scope: string,
      versions: string[],
    ): Promise<DeleteBlobVersionsOutcome> {
      const outcome: DeleteBlobVersionsOutcome = {
        deleted: [],
        missing: [],
        failed: [],
      };
      // Sequential on purpose: vana-storage rate-limits DELETE per owner
      // and the caller already bounds the batch size per pass.
      for (const version of versions) {
        const path = `/v1/chains/${options.storage.chainId}/blobs/${owner}/${encodeURIComponent(scope)}/${encodeURIComponent(version)}`;
        try {
          const authorization = await buildWeb3SignedHeader({
            signMessage: (message: string) =>
              options.storage.signMessage(message),
            aud: storageBase,
            method: "DELETE",
            uri: path,
          });
          const res = await fetchImpl(`${storageBase}${path}`, {
            method: "DELETE",
            headers: { authorization },
          });
          if (res.status === 404) {
            // Idempotent: an absent object is a completed delete.
            outcome.missing.push(version);
          } else if (res.ok) {
            outcome.deleted.push(version);
          } else {
            outcome.failed.push({
              version,
              error: `vana-storage delete failed: ${res.status} ${res.statusText}`,
            });
          }
        } catch (err) {
          outcome.failed.push({
            version,
            error: err instanceof Error ? err.message : String(err),
          });
        }
      }
      return outcome;
    },
  };
}

async function errorDetail(res: Response): Promise<string> {
  const body = await res.json().catch(() => null);
  return detailFromBody(body, res.statusText);
}

function detailFromBody(body: unknown, fallback: string): string {
  if (typeof body === "object" && body !== null) {
    const record = body as Record<string, unknown>;
    if (typeof record.error === "string") return record.error;
    if (typeof record.message === "string") return record.message;
    if (typeof record.error === "object" && record.error !== null) {
      const nested = record.error as Record<string, unknown>;
      if (typeof nested.message === "string") return nested.message;
    }
  }
  return fallback;
}

// Versions are unbounded integers on the wire (decimal strings); parse them
// as bigint so a value past Number.MAX_SAFE_INTEGER cannot round.
function integerField(record: unknown, key: string): bigint | null {
  if (typeof record !== "object" || record === null) return null;
  const value = (record as Record<string, unknown>)[key];
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return BigInt(value);
  }
  if (typeof value === "string" && /^\d+$/.test(value)) return BigInt(value);
  return null;
}

function unwrap(body: unknown): Record<string, unknown> | null {
  if (typeof body !== "object" || body === null) return null;
  const record = body as Record<string, unknown>;
  if (typeof record.data === "object" && record.data !== null) {
    return record.data as Record<string, unknown>;
  }
  return record;
}

function stringField(
  record: Record<string, unknown> | null,
  key: string,
): string | null {
  const value = record?.[key];
  return typeof value === "string" ? value : null;
}
