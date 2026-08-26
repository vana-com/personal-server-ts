/**
 * Gateway client for the lineage endpoints. A thin fetch wrapper (not the SDK
 * GatewayClient) because the three calls need things the SDK client does not
 * expose yet: `includeDeleted=true` on the data point lookup, a server-signed
 * request on the lineage read, and the `lineage` field on registration.
 */

import { LineageUnavailableError } from "../errors/catalog.js";
import type { RequestSigner } from "../signing/request-signer.js";
import type { LineageDataPointRecord } from "./lineage.js";

export type LineageNode =
  | {
      dataPointId: string;
      scope: string;
      version: string;
      deletedAt: string | null;
    }
  | { dataPointId: string; redacted: true };

/** `data` of a gateway lineage response (see docs/derivative-data-api.md). */
export interface LineageView {
  dataPointId: string;
  ownerAddress: string;
  scope: string;
  version: string;
  deletedAt: string | null;
  sources: LineageNode[];
  derivatives: LineageNode[];
}

export type LineageGatewayResult =
  | { ok: true; data: LineageView; proof: unknown }
  | { ok: false; status: number; body: unknown };

export interface GetLineageInput {
  dataPointId: string;
  /** Decimal version string; absent = the current version. */
  version?: string;
  /**
   * Ask for the view a specific grant sees (nodes outside the grant's scopes
   * come back redacted), attested as such. The gateway only honors it for the
   * owner or one of the owner's registered servers.
   */
  grantId?: string;
}

export interface RegisterDataPointWithLineageParams {
  ownerAddress: string;
  scope: string;
  dataHash: string;
  metadataHash: string;
  expectedVersion: string;
  signature: string;
  lineage: readonly string[];
}

export interface RegisterDataPointWithLineageResult {
  dataPointId?: string;
  expectedVersion?: string;
}

export interface LineageGatewayPort {
  /** GET /v1/data/:id?includeDeleted=true; null on 404. */
  getDataPoint(dataPointId: string): Promise<LineageDataPointRecord | null>;
  /** GET /v1/data/:id/lineage, signed with the server key. */
  getLineage(input: GetLineageInput): Promise<LineageGatewayResult>;
  /**
   * POST /v1/data with `lineage`. Same body and error contract as the SDK's
   * registerDataPoint (a non-2xx throws `Gateway error: <status> <detail>`)
   * so the upload worker's stale-version handling applies unchanged.
   */
  registerDataPoint(
    params: RegisterDataPointWithLineageParams,
  ): Promise<RegisterDataPointWithLineageResult>;
}

export interface GatewayLineageClientOptions {
  gatewayUrl: string;
  /** Signs lineage reads as this server; absent = getLineage is unavailable. */
  requestSigner?: RequestSigner;
  fetch?: typeof fetch;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isLineageNode(value: unknown): value is LineageNode {
  if (!isRecord(value) || typeof value.dataPointId !== "string") return false;
  if (value.redacted === true) return true;
  return (
    typeof value.scope === "string" &&
    typeof value.version === "string" &&
    (value.deletedAt === null || typeof value.deletedAt === "string")
  );
}

function parseLineageView(value: unknown): LineageView | null {
  if (
    !isRecord(value) ||
    typeof value.dataPointId !== "string" ||
    typeof value.ownerAddress !== "string" ||
    typeof value.scope !== "string" ||
    typeof value.version !== "string" ||
    !(value.deletedAt === null || typeof value.deletedAt === "string") ||
    !Array.isArray(value.sources) ||
    !value.sources.every(isLineageNode) ||
    !Array.isArray(value.derivatives) ||
    !value.derivatives.every(isLineageNode)
  ) {
    return null;
  }
  return value as unknown as LineageView;
}

export function createGatewayLineageClient(
  options: GatewayLineageClientOptions,
): LineageGatewayPort {
  const base = options.gatewayUrl.replace(/\/+$/, "");
  const origin = new URL(base).origin;
  const doFetch = options.fetch ?? fetch;

  async function readJson(res: Response): Promise<unknown> {
    try {
      return await res.json();
    } catch {
      return null;
    }
  }

  return {
    async getDataPoint(dataPointId) {
      const res = await doFetch(
        `${base}/v1/data/${encodeURIComponent(dataPointId)}?includeDeleted=true`,
      );
      if (res.status === 404) return null;
      if (!res.ok) {
        throw new Error(`Gateway error: ${res.status} ${res.statusText}`);
      }
      const body = await readJson(res);
      const data = isRecord(body) ? body.data : undefined;
      if (
        !isRecord(data) ||
        typeof data.id !== "string" ||
        typeof data.ownerAddress !== "string" ||
        typeof data.scope !== "string" ||
        typeof data.expectedVersion !== "string"
      ) {
        throw new Error("Gateway error: malformed data point response");
      }
      return {
        dataPointId: data.id,
        ownerAddress: data.ownerAddress,
        scope: data.scope,
        version: data.expectedVersion,
        deletedAt: typeof data.deletedAt === "string" ? data.deletedAt : null,
      };
    },

    async getLineage(input) {
      if (!options.requestSigner) {
        throw new LineageUnavailableError({ reason: "no request signer" });
      }
      const path = `/v1/data/${encodeURIComponent(input.dataPointId)}/lineage`;
      const params = new URLSearchParams();
      if (input.version !== undefined) params.set("version", input.version);
      if (input.grantId !== undefined) params.set("grantId", input.grantId);
      const query = params.toString();
      // The signed uri is the path only (the gateway verifies against the
      // request path without its query string), matching how Personal Server
      // reads are signed.
      const authorization = await options.requestSigner.signRequest({
        aud: origin,
        method: "GET",
        uri: path,
      });
      const res = await doFetch(`${base}${path}${query ? `?${query}` : ""}`, {
        headers: { Authorization: authorization },
      });
      const body = await readJson(res);
      if (!res.ok) return { ok: false, status: res.status, body };
      const data = parseLineageView(isRecord(body) ? body.data : undefined);
      if (!data) {
        return {
          ok: false,
          status: res.status,
          body: { error: "malformed lineage response", received: body },
        };
      }
      return {
        ok: true,
        data,
        proof: isRecord(body) ? (body.proof ?? null) : null,
      };
    },

    async registerDataPoint(params) {
      const res = await doFetch(`${base}/v1/data`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Web3Signed ${params.signature}`,
        },
        body: JSON.stringify({
          ownerAddress: params.ownerAddress,
          scope: params.scope,
          dataHash: params.dataHash,
          metadataHash: params.metadataHash,
          expectedVersion: params.expectedVersion,
          lineage: [...params.lineage],
        }),
      });
      if (!res.ok) {
        const body = await readJson(res);
        const detail =
          (isRecord(body) && typeof body.error === "string" && body.error) ||
          res.statusText;
        throw new Error(`Gateway error: ${res.status} ${detail}`);
      }
      const body = await readJson(res);
      const record = isRecord(body) ? body : {};
      return {
        dataPointId:
          typeof record.dataPointId === "string"
            ? record.dataPointId
            : typeof record.id === "string"
              ? record.id
              : undefined,
        expectedVersion:
          typeof record.expectedVersion === "string"
            ? record.expectedVersion
            : undefined,
      };
    },
  };
}
