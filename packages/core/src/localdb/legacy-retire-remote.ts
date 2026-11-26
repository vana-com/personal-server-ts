import { GatewayRefusalError } from "../sync/delete-data-port.js";
import { isGatewayRefusalCode } from "../sync/gateway-refusal.js";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import type { GatewayDeleteDataPortOptions } from "../sync/delete-data-port.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
} from "../sync/tombstone.js";
import {
  LegacyTombstoneUnacknowledged,
  type LegacyRetirePipelinePorts,
} from "./legacy-retire-pipeline.js";

/** Retirement transport: exact requests, with no ordinary delete hooks or retries. */
export function createLegacyRetireRemote(
  options: GatewayDeleteDataPortOptions,
): Pick<LegacyRetirePipelinePorts, "tombstone" | "eraseBlob"> {
  const fetcher = options.fetch ?? globalThis.fetch;
  return {
    async tombstone(scope, head, authority, signal) {
      authority();
      const current = await options.dataPointFeed.getDataPoint({
        ownerAddress: options.serverOwner,
        scope,
        signal,
      });
      if (
        !current ||
        current.deletedAt !== null ||
        current.expectedVersion !== head.fence.expectedVersion ||
        current.dataHash.toLowerCase() !== head.fence.dataHash.toLowerCase() ||
        current.metadataHash.toLowerCase() !==
          head.fence.metadataHash.toLowerCase()
      )
        return "not-sent";
      authority();
      const version = BigInt(head.fence.expectedVersion) + 1n;
      const signature = await options.signer.signAddData({
        ownerAddress: options.serverOwner,
        scope,
        dataHash: TOMBSTONE_DATA_HASH,
        metadataHash: TOMBSTONE_METADATA_HASH,
        expectedVersion: version,
      });
      authority();
      const response = await fetcher(
        `${options.gatewayUrl.replace(/\/+$/, "")}/v1/data/${computeDataPointId(options.serverOwner, scope)}`,
        {
          method: "DELETE",
          signal,
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
        },
      );
      const body = (await response.json().catch(() => null)) as {
        code?: unknown;
        data?: { expectedVersion?: string };
        expectedVersion?: string;
      } | null;
      if (!response.ok && body && isGatewayRefusalCode(body.code))
        throw new GatewayRefusalError(
          response.status,
          body.code,
          "legacy retirement refused",
        );
      if (!response.ok) throw new Error("legacy tombstone request failed");
      if ((body?.data ?? body)?.expectedVersion !== String(version))
        throw new LegacyTombstoneUnacknowledged(
          "legacy tombstone was not acknowledged at pin + 1",
        );
    },
    async eraseBlob(scope, version, authority, signal) {
      const base = options.storage.endpoint.replace(/\/+$/, "");
      const path = `/v1/chains/${options.storage.chainId}/blobs/${options.serverOwner.toLowerCase()}/${encodeURIComponent(scope)}/${encodeURIComponent(version)}`;
      authority();
      const authorization = await buildWeb3SignedHeader({
        signMessage: options.storage.signMessage,
        aud: options.storage.audience ?? base,
        method: "DELETE",
        uri: path,
      });
      authority();
      const response = await fetcher(`${base}${path}`, {
        method: "DELETE",
        headers: { authorization },
        signal,
      });
      return response.ok || response.status === 404;
    },
  };
}
