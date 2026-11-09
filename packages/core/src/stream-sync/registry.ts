/**
 * Gateway adapter for the stream-sync registry calls (§2.3).
 *
 * Reads are strict: a status other than 200 or 404 throws, so a synthesized
 * row never stands in for the authoritative read. Writes are exclusive
 * `POST /v1/data`: 2xx commits (a replay of the identical row also answers
 * 2xx), 409 is a conflict, 5xx and network failures are ambiguous, and any
 * other status is a refusal.
 */

import {
  parseScope,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  type RegistryPostResult,
  type SignedRegistryPost,
  type StreamSyncRegistry,
} from "./ports.js";

export interface GatewayStreamSyncRegistryOptions {
  readonly gatewayUrl: string;
  readonly ownerAddress: string;
  readonly fetch?: typeof fetch;
  /** Page size for the control listing. */
  readonly listPageSize?: number;
}

interface RegistryRow {
  readonly scope?: unknown;
  readonly expectedVersion?: unknown;
  readonly dataHash?: unknown;
  readonly metadataHash?: unknown;
  readonly deletedAt?: unknown;
}

function toControlRead(row: RegistryRow): ControlRead {
  const version = Number(row.expectedVersion);
  if (
    !Number.isSafeInteger(version) ||
    version < 1 ||
    typeof row.dataHash !== "string" ||
    typeof row.metadataHash !== "string"
  ) {
    throw new Error("registry row has no valid version or hashes");
  }
  return {
    found: true,
    version,
    dataHash: row.dataHash,
    metadataHash: row.metadataHash,
    deleted: typeof row.deletedAt === "string" && row.deletedAt !== "",
  };
}

function unwrap(body: unknown): RegistryRow {
  if (typeof body !== "object" || body === null) return {};
  const record = body as { data?: unknown };
  if (typeof record.data === "object" && record.data !== null) {
    return record.data as RegistryRow;
  }
  return record as RegistryRow;
}

export function createGatewayStreamSyncRegistry(
  options: GatewayStreamSyncRegistryOptions,
): StreamSyncRegistry {
  const base = options.gatewayUrl.replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const pageSize = options.listPageSize ?? 500;

  /** Page through every owner row and keep the scopes `keep` accepts. */
  async function listRows(keep: (scope: string) => boolean) {
    const out: { scope: string; read: ControlRead }[] = [];
    let cursor: string | null = null;
    do {
      const params = new URLSearchParams({
        user: options.ownerAddress,
        includeDeleted: "true",
        limit: String(pageSize),
      });
      if (cursor !== null) params.set("cursor", cursor);
      const res = await fetchImpl(`${base}/v1/data?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`registry listing failed: ${res.status}`);
      }
      const envelope = (await res.json()) as {
        data?: { dataPoints?: RegistryRow[] };
        pagination?: { hasMore?: boolean; nextCursor?: string | null };
      };
      for (const row of envelope.data?.dataPoints ?? []) {
        if (typeof row.scope !== "string" || !keep(row.scope)) continue;
        out.push({ scope: row.scope, read: toControlRead(row) });
      }
      cursor =
        envelope.pagination?.hasMore === false
          ? null
          : (envelope.pagination?.nextCursor ?? null);
    } while (cursor !== null);
    return out;
  }

  return {
    async read(scope) {
      const id = computeDataPointId(options.ownerAddress, scope);
      const res = await fetchImpl(`${base}/v1/data/${id}?includeDeleted=true`);
      if (res.status === 404) return { found: false };
      if (res.status !== 200) {
        throw new Error(`registry read of ${scope} failed: ${res.status}`);
      }
      return toControlRead(unwrap(await res.json()));
    },

    async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
      let res: Response;
      try {
        res = await fetchImpl(`${base}/v1/data`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Web3Signed ${request.signature}`,
          },
          body: JSON.stringify({
            ownerAddress: request.ownerAddress,
            scope: request.scope,
            dataHash: request.dataHash,
            metadataHash: request.metadataHash,
            expectedVersion: request.expectedVersion,
            exclusive: true,
          }),
        });
      } catch (cause) {
        throw new AmbiguousRegistryReplyError(
          `registry POST of ${request.scope} got no reply: ${(cause as Error).message}`,
        );
      }
      if (res.status >= 200 && res.status < 300) return { kind: "committed" };
      if (res.status === 409) {
        const body = (await res.json().catch(() => null)) as {
          latestVersion?: unknown;
        } | null;
        const latest = body?.latestVersion;
        return {
          kind: "conflict",
          latestVersion:
            typeof latest === "string" || typeof latest === "number"
              ? String(latest)
              : null,
        };
      }
      if (res.status >= 500 || res.status === 429) {
        throw new AmbiguousRegistryReplyError(
          `registry POST of ${request.scope} answered ${res.status}`,
        );
      }
      const text = await res.text().catch(() => "");
      throw new RegistryRefusedError(
        `registry refused POST of ${request.scope}: ${res.status} ${text.slice(0, 200)}`,
        res.status,
      );
    },

    listControlRows: () =>
      listRows((scope) => parseScope(scope)?.kind === "control"),

    listStreamRows: (connector) =>
      listRows((scope) => {
        const parsed = parseScope(scope);
        return parsed?.kind === "stream" && parsed.connector === connector;
      }),
  };
}
