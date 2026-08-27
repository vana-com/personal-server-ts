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
  /**
   * A node the caller's grant does not cover. It carries NO identifier:
   * dataPointId is keccak256(owner, scope) and a grantee knows the owner,
   * so an id would let it dictionary-test scope names. Only position and
   * count survive, which is all a consent UI needs to show the shape.
   */
  | { redacted: true };

/** `data` of a gateway lineage response (see docs/derivative-data-api.md). */
export interface LineageView {
  dataPointId: string;
  ownerAddress: string;
  scope: string;
  version: string;
  deletedAt: string | null;
  sources: LineageNode[];
  derivatives: LineageNode[];
  /** Present (true) only when the gateway capped `derivatives`. */
  derivativesTruncated?: true;
  /**
   * The grant this view was attested for. Absent on the owner's full view;
   * set (lowercase) on a redacted grant view. The client refuses a view
   * whose grantId does not match the one it asked for.
   */
  grantId?: string;
}

export type LineageGatewayResult =
  | { ok: true; data: LineageView; proof: GatewayProof }
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
  /** LineageAttestation signature over (owner, scope, version, dataHash, lineage). */
  lineageSignature: string;
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
  if (!isRecord(value)) return false;
  if (value.redacted === true) {
    // A redacted node must be exactly { redacted: true }. A gateway that
    // attaches an id, scope or version to a redacted node is leaking, and the
    // view is refused rather than passed on with the leak intact.
    return Object.keys(value).length === 1;
  }
  if (typeof value.dataPointId !== "string") return false;
  return (
    typeof value.scope === "string" &&
    typeof value.version === "string" &&
    (value.deletedAt === null || typeof value.deletedAt === "string")
  );
}

/** The gateway attestation shape (ProofData); a 200 without it is not a view. */
export interface GatewayProof {
  userSignature: string;
  gatewaySignature: string;
  timestamp: number;
  status: string;
  estimatedConfirmation: string | null;
  chainBlockHeight: number | null;
}

function isGatewayProof(value: unknown): value is GatewayProof {
  return (
    isRecord(value) &&
    typeof value.userSignature === "string" &&
    typeof value.gatewaySignature === "string" &&
    typeof value.timestamp === "number" &&
    typeof value.status === "string" &&
    (value.estimatedConfirmation === null ||
      typeof value.estimatedConfirmation === "string") &&
    (value.chainBlockHeight === null ||
      typeof value.chainBlockHeight === "number")
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
    !value.derivatives.every(isLineageNode) ||
    !(value.grantId === undefined || typeof value.grantId === "string") ||
    !(
      value.derivativesTruncated === undefined ||
      value.derivativesTruncated === true
    )
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
      // Bind the record to what was asked for: a stale or misrouted 200 must
      // not validate a different source than the one the caller named.
      if (data.id.toLowerCase() !== dataPointId.toLowerCase()) {
        throw new Error(
          `Gateway error: data point response is for ${data.id}, requested ${dataPointId}`,
        );
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
      // The view selectors are signed, never free query parameters: the
      // version is a path segment (inside the signed uri) and the grant view
      // is the scheme's own `grantId` claim, so a captured signature cannot
      // be replayed for another version or grant view.
      const uri =
        `/v1/data/${input.dataPointId.toLowerCase()}/lineage` +
        (input.version !== undefined ? `/${input.version}` : "");
      const authorization = await options.requestSigner.signRequest({
        aud: origin,
        method: "GET",
        uri,
        grantId: input.grantId?.toLowerCase(),
      });
      const res = await doFetch(`${base}${uri}`, {
        headers: { Authorization: authorization },
      });
      const body = await readJson(res);
      if (!res.ok) return { ok: false, status: res.status, body };
      // The API promises an attested view: a 200 whose data or proof does
      // not have the documented shape is reported as a gateway error, never
      // passed on as a view.
      const data = parseLineageView(isRecord(body) ? body.data : undefined);
      const proof = isRecord(body) ? body.proof : undefined;
      if (!data || !isGatewayProof(proof)) {
        return {
          ok: false,
          status: res.status,
          body: { error: "malformed lineage response", received: body },
        };
      }
      // The attested view must be the one that was requested. A response for
      // another data point, or for a version other than the signed path
      // segment, is a gateway error, never served to an authorized caller.
      const requestedId = input.dataPointId.toLowerCase();
      // The grant view is part of the identity of the response: a builder
      // asking under its grant must get a view attested for that grant, and
      // a full owner view (no grantId) must never be handed to a builder.
      const requestedGrant = input.grantId?.toLowerCase();
      const servedGrant = data.grantId?.toLowerCase();
      const viewMismatch =
        data.dataPointId.toLowerCase() !== requestedId ||
        (input.version !== undefined && data.version !== input.version) ||
        requestedGrant !== servedGrant;
      if (viewMismatch) {
        return {
          ok: false,
          status: res.status,
          body: {
            error: "lineage response does not match the requested view",
            requested: {
              dataPointId: requestedId,
              version: input.version,
              grantId: requestedGrant,
            },
            received: {
              dataPointId: data.dataPointId,
              version: data.version,
              grantId: servedGrant,
            },
          },
        };
      }
      return { ok: true, data, proof };
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
          lineageSignature: params.lineageSignature,
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
