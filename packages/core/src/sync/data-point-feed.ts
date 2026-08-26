import type {
  DataPointFeedListOptions,
  DataPointFeedListResult,
  DataPointFeedPort,
  DataPointFeedRecord,
} from "../ports/index.js";
import { computeDataPointId } from "./data-point-id.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "./tombstone.js";

export interface GatewayDataPointFeedOptions {
  /** Gateway base URL, e.g. https://dp-rpc.vana.org */
  gatewayUrl: string;
  /** Test seam; defaults to the global fetch. */
  fetch?: typeof fetch;
  /** Test seam for the fallback `deletedAt` when a 410 body carries none. */
  now?: () => Date;
}

/**
 * Deletion-aware gateway feed over the same REST endpoints the SDK client
 * uses, plus the `includeDeleted=true` query the SDK does not expose:
 *
 *   GET {gateway}/v1/data?user={owner}&includeDeleted=true[&cursor=..][&since=..][&limit=..]
 *   GET {gateway}/v1/data/{dataPointId}?includeDeleted=true
 *
 * Rows come back with `deletedAt` (null while live). A gateway that answers
 * the single lookup of a tombstoned point with 410 instead of a row is
 * normalised into a deleted record so callers never have to catch a 410.
 */
export function createGatewayDataPointFeed(
  options: GatewayDataPointFeedOptions,
): DataPointFeedPort {
  const base = options.gatewayUrl.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const now = options.now ?? (() => new Date());

  return {
    async listDataPointsByOwner(
      owner: string,
      cursor: string | null,
      listOptions?: DataPointFeedListOptions,
    ): Promise<DataPointFeedListResult> {
      const params = new URLSearchParams({ user: owner });
      if (cursor !== null) params.set("cursor", cursor);
      if (listOptions?.since) params.set("since", listOptions.since);
      if (listOptions?.limit !== undefined) {
        params.set("limit", String(listOptions.limit));
      }
      if (listOptions?.includeDeleted) params.set("includeDeleted", "true");

      const res = await fetchImpl(`${base}/v1/data?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`Gateway error: ${res.status} ${res.statusText}`);
      }
      const envelope = (await res.json()) as {
        data?: { dataPoints?: unknown[] };
        pagination?: { hasMore?: boolean; nextCursor?: string | null };
      };
      const nextCursor =
        envelope.pagination?.hasMore === false
          ? null
          : (envelope.pagination?.nextCursor ?? null);
      const rows = envelope.data?.dataPoints ?? [];
      return {
        dataPoints: rows.map((row) => normalizeRecord(row)),
        cursor: nextCursor,
      };
    },

    async getDataPoint(input) {
      const dataPointId = computeDataPointId(input.ownerAddress, input.scope);
      const res = await fetchImpl(
        `${base}/v1/data/${dataPointId}?includeDeleted=true`,
      );
      if (res.status === 404) return null;
      if (res.status === 410) {
        // Tombstoned. Prefer the row the gateway echoes in the 410 body;
        // otherwise synthesise the minimum a caller needs to treat the point
        // as deleted "at or before now".
        const body = await res.json().catch(() => null);
        const echoed = unwrap(body);
        const deletedAt =
          stringField(echoed, "deletedAt") ?? now().toISOString();
        return {
          id: dataPointId,
          ownerAddress: input.ownerAddress,
          scope: input.scope,
          dataHash: stringField(echoed, "dataHash") ?? TOMBSTONE_DATA_HASH,
          metadataHash:
            stringField(echoed, "metadataHash") ?? TOMBSTONE_METADATA_HASH,
          expectedVersion: stringField(echoed, "expectedVersion") ?? "0",
          addedAt: stringField(echoed, "addedAt") ?? deletedAt,
          deletedAt,
        };
      }
      if (!res.ok) {
        throw new Error(`Gateway error: ${res.status} ${res.statusText}`);
      }
      const body = await res.json();
      return normalizeRecord(unwrap(body));
    },
  };
}

// The gateway wraps single-resource responses as `{ data: {...} }` (the SDK's
// unwrapEnvelope); tolerate a bare object too.
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
): string | undefined {
  const value = record?.[key];
  return typeof value === "string" ? value : undefined;
}

function normalizeRecord(row: unknown): DataPointFeedRecord {
  const record = (row ?? {}) as Record<string, unknown>;
  const deletedAt = record.deletedAt;
  return {
    ...(record as unknown as DataPointFeedRecord),
    deletedAt: typeof deletedAt === "string" ? deletedAt : null,
  };
}

/**
 * Adapter from the SDK `GatewayClient` listing to the feed shape. Used when a
 * host wires no dedicated feed: deletions are only visible if the gateway
 * happens to include `deletedAt` without being asked, so this is a
 * degraded mode. Prefer `createGatewayDataPointFeed`.
 */
export function feedFromGatewayClient(gateway: {
  listDataPointsByOwner(
    owner: string,
    cursor: string | null,
    options?: DataPointFeedListOptions,
  ): Promise<{ dataPoints: unknown[]; cursor: string | null }>;
  getDataPoint(dataPointId: string): Promise<unknown | null>;
}): DataPointFeedPort {
  return {
    async listDataPointsByOwner(owner, cursor, listOptions) {
      const { includeDeleted: _includeDeleted, ...sdkOptions } =
        listOptions ?? {};
      const result =
        Object.keys(sdkOptions).length > 0
          ? await gateway.listDataPointsByOwner(owner, cursor, sdkOptions)
          : await gateway.listDataPointsByOwner(owner, cursor);
      return {
        dataPoints: result.dataPoints.map((row) => normalizeRecord(row)),
        cursor: result.cursor,
      };
    },
    async getDataPoint(input) {
      const row = await gateway.getDataPoint(
        computeDataPointId(input.ownerAddress, input.scope),
      );
      return row === null ? null : normalizeRecord(row);
    },
  };
}
