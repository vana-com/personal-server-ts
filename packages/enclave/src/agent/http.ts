import { timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { isAddress, isHex, type Address, type Hex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { buildEvidence } from "./evidence.js";
import { AgentError } from "./errors.js";
import { readHealth } from "./health.js";
import { sealDelivery } from "./seal.js";
import type { IdentityRequestBody, SealRequestBody } from "./types.js";

const AUTHORIZATION_HEADER = "authorization";
const BEARER_PREFIX = "Bearer ";
const CONTENT_TYPE_HEADER = "content-type";
const JSON_CONTENT_TYPE = "application/json";
const BODY_LIMIT_BYTES = 64 * 1024;
const HEALTH_ROUTE = "/agent/v1/health";
const IDENTITY_ROUTE = "/agent/v1/identity";
const SEAL_ROUTE = "/agent/v1/secrets/seal";
const DRAIN_ROUTE = "/agent/v1/drain";
const GET = "GET";
const POST = "POST";
const OK = 200;
const BAD_REQUEST = 400;
const UNAUTHORIZED = 401;
const NOT_FOUND = 404;
const BODY_TOO_LARGE = 413;
const INTERNAL_ERROR = 500;
const UNAUTHORIZED_MESSAGE = "authorization required";
const NOT_FOUND_MESSAGE = "route not found";
const BODY_TOO_LARGE_MESSAGE = "request body is too large";
const BAD_REQUEST_MESSAGE = "request body is invalid";
const INTERNAL_MESSAGE = "internal server error";
const UNKNOWN_ERROR = "unknown";

export interface AgentServerOptions {
  client: DstackClient;
  secret: string;
  jobs?: AgentJobsControl;
}

export interface AgentJobsControl {
  nodeId: string;
  activeCount(): number;
  draining(): boolean;
  drain(): Promise<void>;
}

class BodyTooLarge extends Error {}
class BadRequest extends Error {}

export function createAgentServer(options: AgentServerOptions): Server {
  return createServer((request, response) => {
    const path = requestPath(request);
    response.once("finish", () => {
      console.error({
        method: request.method,
        path,
        status: response.statusCode,
      });
    });
    void handleRequest(options, request, response, path);
  });
}

async function handleRequest(
  options: AgentServerOptions,
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
): Promise<void> {
  if (!isAuthorized(request, options.secret)) {
    sendError(response, UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
    return;
  }

  try {
    if (request.method === GET && path === HEALTH_ROUTE) {
      sendJson(
        response,
        OK,
        await readHealth(
          options.client,
          options.jobs?.nodeId ?? null,
          options.jobs?.activeCount() ?? 0,
          options.jobs?.draining() ?? false,
        ),
      );
      return;
    }

    if (request.method === POST && path === DRAIN_ROUTE) {
      await options.jobs?.drain();
      sendJson(response, OK, { draining: true });
      return;
    }

    if (request.method === POST && path === IDENTITY_ROUTE) {
      const body = identityBody(await readJson(request));
      sendJson(response, OK, await buildEvidence(options.client, body));
      return;
    }

    if (request.method === POST && path === SEAL_ROUTE) {
      const body = sealBody(await readJson(request));
      sendJson(response, OK, await sealDelivery(options.client, body));
      return;
    }

    sendError(response, NOT_FOUND, "NOT_FOUND", NOT_FOUND_MESSAGE);
  } catch (error) {
    if (error instanceof BodyTooLarge) {
      sendError(
        response,
        BODY_TOO_LARGE,
        "BODY_TOO_LARGE",
        BODY_TOO_LARGE_MESSAGE,
      );
      return;
    }

    if (error instanceof AgentError) {
      // AgentError messages are fixed internal strings and never include input.
      sendError(response, error.status, error.code, error.message);
      return;
    }

    if (error instanceof SyntaxError || error instanceof BadRequest) {
      sendError(response, BAD_REQUEST, "BAD_REQUEST", BAD_REQUEST_MESSAGE);
      return;
    }

    console.error({
      path,
      error:
        error instanceof Error
          ? `${error.name}: ${error.message}`
          : UNKNOWN_ERROR,
    });
    sendError(response, INTERNAL_ERROR, "INTERNAL", INTERNAL_MESSAGE);
  }
}

function isAuthorized(request: IncomingMessage, secret: string): boolean {
  const header = request.headers[AUTHORIZATION_HEADER];
  if (typeof header !== "string" || !header.startsWith(BEARER_PREFIX)) {
    return false;
  }

  const supplied = Buffer.from(header.slice(BEARER_PREFIX.length), "utf8");
  const expected = Buffer.from(secret, "utf8");
  if (supplied.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(supplied, expected);
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > BODY_LIMIT_BYTES) {
      throw new BodyTooLarge();
    }
    chunks.push(bytes);
  }

  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

function identityBody(value: unknown): IdentityRequestBody {
  const body = record(value);
  if (
    !isAddressValue(body.ownerAddress) ||
    !isPositiveInteger(body.chainId) ||
    !isPositiveInteger(body.epoch)
  ) {
    throw new BadRequest();
  }

  return {
    ownerAddress: body.ownerAddress,
    chainId: body.chainId,
    epoch: body.epoch,
  };
}

function sealBody(value: unknown): SealRequestBody {
  const body = record(value);
  if (
    !isAddressValue(body.ownerAddress) ||
    !isPositiveInteger(body.chainId) ||
    !isPositiveInteger(body.epoch) ||
    !isAddressValue(body.enclaveAddress) ||
    !isHex(body.ciphertext, { strict: true }) ||
    (body.minEpoch !== undefined && !isPositiveInteger(body.minEpoch))
  ) {
    throw new BadRequest();
  }

  return {
    ownerAddress: body.ownerAddress as Address,
    chainId: body.chainId,
    epoch: body.epoch,
    enclaveAddress: body.enclaveAddress as Address,
    ciphertext: body.ciphertext as Hex,
    ...(body.minEpoch === undefined ? {} : { minEpoch: body.minEpoch }),
  };
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BadRequest();
  }

  return value as Record<string, unknown>;
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value > 0;
}

function isAddressValue(value: unknown): value is Address {
  return typeof value === "string" && isAddress(value);
}

function requestPath(request: IncomingMessage): string {
  return new URL(request.url ?? "/", "http://agent.invalid").pathname;
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
): void {
  response.statusCode = status;
  response.setHeader(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
  response.end(JSON.stringify(body));
}

function sendError(
  response: ServerResponse,
  status: number,
  code: string,
  message: string,
): void {
  sendJson(response, status, { code, error: message });
}
