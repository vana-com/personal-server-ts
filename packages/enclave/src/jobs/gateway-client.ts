import type {
  ClaimRequest,
  ClaimResponse,
  CompleteRequest,
  FailRequest,
  FencedResponse,
  HeartbeatRequest,
  TeeNodeHeartbeat,
} from "./types.js";

const AUTHORIZATION_HEADER = "Authorization";
const CONTENT_TYPE_HEADER = "Content-Type";
const NODE_ID_HEADER = "X-Node-Id";
const BEARER_PREFIX = "Bearer ";
const JSON_CONTENT_TYPE = "application/json";
const CLAIM_TIMEOUT_GRACE_SECONDS = 5;
const REQUEST_TIMEOUT_MS = 10_000;
const MILLISECONDS_PER_SECOND = 1_000;
const NO_CONTENT = 204;
const FORBIDDEN = 403;
const CONFLICT = 409;

export interface GatewayClient {
  claim(wait: number, body: ClaimRequest): Promise<ClaimResponse | null>;
  heartbeat(jobId: string, body: HeartbeatRequest): Promise<FencedResponse>;
  complete(jobId: string, body: CompleteRequest): Promise<FencedResponse>;
  fail(jobId: string, body: FailRequest): Promise<FencedResponse>;
  nodeHeartbeat(
    nodeId: string,
    body: TeeNodeHeartbeat,
  ): Promise<{ state: string }>;
}

export interface GatewayClientOptions {
  baseUrl: string;
  nodeId: string;
  nodeSecret: string;
  fetch?: typeof fetch;
}

export class LeaseLostError extends Error {
  constructor() {
    super("Job lease was lost");
    this.name = "LeaseLostError";
  }
}

export class NodeNotAdmittedError extends Error {
  constructor() {
    super("TEE node is not admitted");
    this.name = "NodeNotAdmittedError";
  }
}

export class GatewayHttpError extends Error {
  constructor(public readonly status: number) {
    super(`Gateway request failed with status ${status}`);
    this.name = "GatewayHttpError";
  }
}

export function createGatewayClient(
  options: GatewayClientOptions,
): GatewayClient {
  const requestFetch = options.fetch ?? fetch;
  const baseUrl = options.baseUrl.replace(/\/$/, "");
  const headers = {
    [AUTHORIZATION_HEADER]: `${BEARER_PREFIX}${options.nodeSecret}`,
    [CONTENT_TYPE_HEADER]: JSON_CONTENT_TYPE,
    [NODE_ID_HEADER]: options.nodeId,
  };

  async function request<T>(
    path: string,
    body: unknown,
    timeoutMs: number,
  ): Promise<T> {
    const response = await requestFetch(`${baseUrl}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      throw httpError(response);
    }

    return (await response.json()) as T;
  }

  return {
    async claim(wait, body): Promise<ClaimResponse | null> {
      const response = await requestFetch(
        `${baseUrl}/v1/jobs/claim?wait=${wait}`,
        {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(
            (wait + CLAIM_TIMEOUT_GRACE_SECONDS) * MILLISECONDS_PER_SECOND,
          ),
        },
      );
      if (response.status === NO_CONTENT) {
        return null;
      }
      if (!response.ok) {
        throw httpError(response);
      }

      let claim: unknown;
      try {
        claim = await response.json();
      } catch {
        throw new GatewayHttpError(response.status);
      }
      if (!isClaimResponse(claim)) {
        throw new GatewayHttpError(response.status);
      }

      return claim;
    },
    heartbeat(jobId, body): Promise<FencedResponse> {
      return request(
        `/v1/jobs/${encodeURIComponent(jobId)}/heartbeat`,
        body,
        REQUEST_TIMEOUT_MS,
      );
    },
    complete(jobId, body): Promise<FencedResponse> {
      return request(
        `/v1/jobs/${encodeURIComponent(jobId)}/complete`,
        body,
        REQUEST_TIMEOUT_MS,
      );
    },
    fail(jobId, body): Promise<FencedResponse> {
      return request(
        `/v1/jobs/${encodeURIComponent(jobId)}/fail`,
        body,
        REQUEST_TIMEOUT_MS,
      );
    },
    nodeHeartbeat(nodeId, body): Promise<{ state: string }> {
      return request(
        `/v1/tee-nodes/${encodeURIComponent(nodeId)}/heartbeat`,
        body,
        REQUEST_TIMEOUT_MS,
      );
    },
  };
}

function httpError(response: Response): Error {
  if (response.status === FORBIDDEN) {
    return new NodeNotAdmittedError();
  }
  if (response.status === CONFLICT) {
    return new LeaseLostError();
  }

  return new GatewayHttpError(response.status);
}

function isClaimResponse(value: unknown): value is ClaimResponse {
  if (!isRecord(value) || !isRecord(value.job) || !isRecord(value.identity)) {
    return false;
  }

  return (
    typeof value.job.jobId === "string" &&
    (value.job.chainId === undefined ||
      (typeof value.job.chainId === "number" &&
        Number.isFinite(value.job.chainId))) &&
    typeof value.job.fencingToken === "number" &&
    typeof value.job.requestCiphertext === "string" &&
    typeof value.identity.userPsId === "string" &&
    typeof value.identity.epoch === "number" &&
    typeof value.identity.enclaveAddress === "string" &&
    typeof value.identity.enclavePublicKey === "string" &&
    isRecord(value.identity.sealedEnvelope)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
