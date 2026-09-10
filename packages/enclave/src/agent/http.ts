import { timingSafeEqual } from "node:crypto";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/node";
import { ScopeSchema } from "@opendatalabs/vana-sdk/protocol/scopes";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { isAddress, isHex, type Address, type Hex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import type { FleetConfigValidity } from "../fleet/security-config.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveAccount } from "../identity/wallet.js";
import { normalizeJobId } from "../jobs/types.js";
import type { SandboxLookup, SandboxStatus } from "../sandbox/registry.js";
import {
  ACCESS_RECORD_ACTION,
  buildAccessRecord,
  canonicalJson,
  MAX_ACCESS_RECORDS,
  type AccessRecordInput,
  type SignedAccessRecord,
} from "./access-records.js";
import { buildEvidence } from "./evidence.js";
import { AgentError } from "./errors.js";
import { readHealth } from "./health.js";
import { sealDelivery } from "./seal.js";
import type {
  IdentityRequestBody,
  PrewarmRequestBody,
  ResultSigningRequestBody,
  SandboxJobLookup,
  SealRequestBody,
} from "./types.js";

const AUTHORIZATION_HEADER = "authorization";
const BEARER_PREFIX = "Bearer ";
const CONTENT_TYPE_HEADER = "content-type";
const JSON_CONTENT_TYPE = "application/json";
const BODY_LIMIT_BYTES = 64 * 1024;
const HEALTH_ROUTE = "/agent/v1/health";
const IDENTITY_ROUTE = "/agent/v1/identity";
const SEAL_ROUTE = "/agent/v1/secrets/seal";
const DRAIN_ROUTE = "/agent/v1/drain";
const RESULT_SIGNING_ROUTE = "/agent/v1/job-results/sign";
const ACCESS_RECORDS_ROUTE = "/agent/v1/access-records";
const SANDBOXES_ROUTE = "/agent/v1/sandboxes";
const PREWARM_ROUTE = "/agent/v1/sandboxes/prewarm";
const GET = "GET";
const POST = "POST";
const PUT = "PUT";
const OK = 200;
const ACCEPTED = 202;
const BAD_REQUEST = 400;
const UNAUTHORIZED = 401;
const FORBIDDEN = 403;
const NOT_FOUND = 404;
const BODY_TOO_LARGE = 413;
const INTERNAL_ERROR = 500;
const UNAUTHORIZED_MESSAGE = "authorization required";
const NOT_FOUND_MESSAGE = "route not found";
const BODY_TOO_LARGE_MESSAGE = "request body is too large";
const BAD_REQUEST_MESSAGE = "request body is invalid";
const INTERNAL_MESSAGE = "internal server error";
const UNKNOWN_ERROR = "unknown";
const BODY_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const RESULT_SIGNING_MESSAGE = "Signed job result upload";
const ACCESS_RECORDS_MESSAGE = "Signed access records";
const ACCESS_RECORDS_REFUSED = "access records refused";
const STALE_PLACEMENT_CODE = "STALE_PLACEMENT";
const STALE_PLACEMENT_MESSAGE = "stale placement";
const OUTCOMES = new Set(["served", "denied"]);
const SOURCES = new Set(["mcp", "api"]);
const DEFAULT_LOG_TAIL = 100;
const MAX_LOG_TAIL = 500;
const TEXT_CONTENT_TYPE = "text/plain; charset=utf-8";
const SANDBOX_LOGS_PATH_PATTERN =
  /^\/agent\/v1\/sandboxes\/([a-zA-Z0-9_.-]+)\/logs$/;

export interface AgentServerOptions {
  client: DstackClient;
  secret: string;
  jobs?: AgentJobsControl;
  /** Signed-bundle window, surfaced on health so the pool loop can refuse
   * to start a member whose configuration is about to expire. */
  config?: FleetConfigValidity;
}

export interface AgentJobsControl {
  nodeId: string;
  storageApiUrl: string;
  activeCount(): number;
  draining(): boolean;
  drain(): Promise<void>;
  sandboxDebug: boolean;
  fleetEnabled?: boolean;
  nodeIncarnation?: string;
  listSandboxes(): Promise<SandboxStatus[]>;
  sandboxLogs(containerId: string, tail: number): Promise<string | undefined>;
  lookupSandboxJob(accessToken: string, jobId: string): SandboxJobLookup;
  lookupSandbox(accessToken: string): SandboxLookup;
  postAccessRecords(records: SignedAccessRecord[]): Promise<void>;
  prewarm(body: PrewarmRequestBody): void;
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
  if (request.method === POST && path === RESULT_SIGNING_ROUTE) {
    await handleResultSigning(options, request, response);
    return;
  }

  if (request.method === POST && path === ACCESS_RECORDS_ROUTE) {
    await handleAccessRecords(options, request, response);
    return;
  }

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
          options.config,
        ),
      );
      return;
    }

    if (request.method === POST && path === DRAIN_ROUTE) {
      await options.jobs?.drain();
      sendJson(response, OK, { draining: true });
      return;
    }

    if (request.method === GET && path === SANDBOXES_ROUTE) {
      if (!options.jobs?.sandboxDebug) {
        sendError(response, NOT_FOUND, "NOT_FOUND", NOT_FOUND_MESSAGE);
        return;
      }
      sendJson(response, OK, await options.jobs.listSandboxes());
      return;
    }

    const logsContainerId = sandboxLogsContainerId(path);
    if (request.method === GET && logsContainerId) {
      if (!options.jobs?.sandboxDebug) {
        sendError(response, NOT_FOUND, "NOT_FOUND", NOT_FOUND_MESSAGE);
        return;
      }
      const logs = await options.jobs.sandboxLogs(
        logsContainerId,
        logTail(request),
      );
      if (logs === undefined) {
        sendError(response, NOT_FOUND, "NOT_FOUND", NOT_FOUND_MESSAGE);
        return;
      }
      sendText(response, OK, logs);
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

    if (request.method === POST && path === PREWARM_ROUTE && options.jobs) {
      if (options.jobs.fleetEnabled) {
        sendError(
          response,
          FORBIDDEN,
          "FLEET_ASSIGNMENT_REQUIRED",
          "Fleet controller assignment required",
        );
        return;
      }
      const body = prewarmRequestBody(await readJson(request));
      sendJson(response, ACCEPTED, { accepted: true });
      options.jobs.prewarm(body);
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

async function handleResultSigning(
  options: AgentServerOptions,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const token = bearerToken(request);
  if (!token || !options.jobs) {
    sendError(response, UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
    return;
  }

  try {
    const body = resultSigningBody(await readJson(request));
    const lookup = options.jobs.lookupSandboxJob(token, body.jobId);
    if (lookup.kind === "unauthorized") {
      sendError(response, UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
      return;
    }
    if (lookup.kind === "inactive") {
      sendError(response, FORBIDDEN, "SIGNING_REFUSED", "signing refused");
      return;
    }

    const { job } = lookup;
    if (
      body.chainId !== job.chainId ||
      (body.owner !== undefined && !sameAddress(body.owner, job.owner)) ||
      userPsId(job.chainId, job.owner) !== job.userPsId
    ) {
      sendError(response, FORBIDDEN, "SIGNING_REFUSED", "signing refused");
      return;
    }

    const account = await deriveEnclaveAccount(
      options.client,
      job.userPsId,
      job.epoch,
    );
    if (!sameAddress(account.address, job.serverAddress)) {
      sendError(response, FORBIDDEN, "SIGNING_REFUSED", "signing refused");
      return;
    }

    const owner = job.owner.toLowerCase();
    const encodedJobId = encodeURIComponent(job.jobId);
    const uri = `/v1/job-results/${job.chainId}/${owner}/${encodedJobId}`;
    const key = `jobresults/${job.chainId}/${encodedJobId}`;
    const authorization = await buildWeb3SignedHeader({
      signMessage: (message) => account.signMessage(message),
      aud: new URL(options.jobs.storageApiUrl).origin,
      method: PUT,
      uri,
      bodyHash: body.bodyHash,
    });

    // Derivation/signing are asynchronous; placement or attempt authorization
    // may have expired since the initial lookup. Never release a late token.
    const confirmed = options.jobs.lookupSandboxJob(token, body.jobId);
    if (
      confirmed.kind !== "active" ||
      confirmed.job.jobId !== job.jobId ||
      confirmed.job.epoch !== job.epoch ||
      confirmed.job.userPsId !== job.userPsId ||
      confirmed.job.chainId !== job.chainId ||
      !sameAddress(confirmed.job.owner, job.owner) ||
      !sameAddress(confirmed.job.serverAddress, job.serverAddress) ||
      JSON.stringify(confirmed.job.assignment) !==
        JSON.stringify(job.assignment)
    ) {
      sendError(response, FORBIDDEN, "SIGNING_REFUSED", "signing refused");
      return;
    }

    console.error(
      { jobId: job.jobId, key, size: body.byteLength },
      RESULT_SIGNING_MESSAGE,
    );
    sendJson(response, OK, { authorization });
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
    if (error instanceof SyntaxError || error instanceof BadRequest) {
      sendError(response, BAD_REQUEST, "BAD_REQUEST", BAD_REQUEST_MESSAGE);
      return;
    }

    console.error({
      path: RESULT_SIGNING_ROUTE,
      error:
        error instanceof Error
          ? `${error.name}: ${error.message}`
          : UNKNOWN_ERROR,
    });
    sendError(response, INTERNAL_ERROR, "INTERNAL", INTERNAL_MESSAGE);
  }
}

/**
 * Sign and relay one batch of access records. Authenticated by the sandbox's
 * own access token, like result signing — the sandbox PS holds no agent
 * secret. Records the sandbox cannot vouch for (identity, node) are stamped
 * here, never taken from the body.
 */
async function handleAccessRecords(
  options: AgentServerOptions,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  const token = bearerToken(request);
  if (!token || !options.jobs) {
    sendError(response, UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
    return;
  }

  try {
    const inputs = accessRecordsBody(await readJson(request));
    const lookup = options.jobs.lookupSandbox(token);
    if (lookup.kind === "unauthorized") {
      sendError(response, UNAUTHORIZED, "UNAUTHORIZED", UNAUTHORIZED_MESSAGE);
      return;
    }

    // The owner moved to another placement generation; a sandbox left over
    // from the previous one may not record against them.
    if (lookup.kind === "stale") {
      sendError(
        response,
        FORBIDDEN,
        STALE_PLACEMENT_CODE,
        STALE_PLACEMENT_MESSAGE,
      );
      return;
    }

    const { identity } = lookup;

    const account = await deriveEnclaveAccount(
      options.client,
      identity.userPsId,
      identity.epoch,
    );
    const signed: SignedAccessRecord[] = [];
    for (const input of inputs) {
      const record = buildAccessRecord(input, identity, options.jobs.nodeId);
      const signature = await account.signMessage(canonicalJson(record));
      signed.push({ payload: record, signature });
    }

    await options.jobs.postAccessRecords(signed);

    console.error(
      { count: signed.length, userPsId: identity.userPsId },
      ACCESS_RECORDS_MESSAGE,
    );
    sendJson(response, ACCEPTED, { accepted: signed.length });
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
    if (error instanceof SyntaxError || error instanceof BadRequest) {
      sendError(response, BAD_REQUEST, "BAD_REQUEST", BAD_REQUEST_MESSAGE);
      return;
    }

    console.error({
      path: ACCESS_RECORDS_ROUTE,
      error:
        error instanceof Error
          ? `${error.name}: ${error.message}`
          : UNKNOWN_ERROR,
    });
    sendError(response, INTERNAL_ERROR, "INTERNAL", ACCESS_RECORDS_REFUSED);
  }
}

function isAuthorized(request: IncomingMessage, secret: string): boolean {
  const token = bearerToken(request);
  if (token === undefined) {
    return false;
  }

  const supplied = Buffer.from(token, "utf8");
  const expected = Buffer.from(secret, "utf8");
  if (supplied.length !== expected.length) {
    return false;
  }

  return timingSafeEqual(supplied, expected);
}

function bearerToken(request: IncomingMessage): string | undefined {
  const header = request.headers[AUTHORIZATION_HEADER];

  return typeof header === "string" && header.startsWith(BEARER_PREFIX)
    ? header.slice(BEARER_PREFIX.length)
    : undefined;
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

export function identityBody(value: unknown): IdentityRequestBody {
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

function prewarmRequestBody(value: unknown): PrewarmRequestBody {
  const body = record(value);
  const sealedEnvelope = record(body.sealedEnvelope);
  const wrappedContentKey = record(sealedEnvelope.wrappedContentKey);
  const scope = ScopeSchema.safeParse(body.scope);
  if (
    !isHex(body.userPsId, { strict: true }) ||
    body.userPsId.length !== 66 ||
    !isPositiveInteger(body.epoch) ||
    !isAddressValue(body.enclaveAddress) ||
    !isHex(body.enclavePublicKey, { strict: true }) ||
    body.enclavePublicKey.length !== 132 ||
    sealedEnvelope.v !== 1 ||
    !isBase64(sealedEnvelope.iv) ||
    !isBase64(sealedEnvelope.ciphertext) ||
    !isBase64(sealedEnvelope.tag) ||
    !isBase64(wrappedContentKey.iv) ||
    !isBase64(wrappedContentKey.ciphertext) ||
    !isBase64(wrappedContentKey.tag) ||
    !scope.success
  ) {
    throw new BadRequest();
  }

  return {
    userPsId: body.userPsId,
    epoch: body.epoch,
    enclaveAddress: body.enclaveAddress,
    enclavePublicKey: body.enclavePublicKey,
    sealedEnvelope: {
      v: 1,
      iv: sealedEnvelope.iv,
      ciphertext: sealedEnvelope.ciphertext,
      tag: sealedEnvelope.tag,
      wrappedContentKey: {
        iv: wrappedContentKey.iv,
        ciphertext: wrappedContentKey.ciphertext,
        tag: wrappedContentKey.tag,
      },
    },
    scope: scope.data,
  };
}

export function sealBody(value: unknown): SealRequestBody {
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

function resultSigningBody(value: unknown): ResultSigningRequestBody {
  const body = record(value);
  const jobId = normalizeJobId(body.jobId);
  if (
    jobId === undefined ||
    !isPositiveInteger(body.chainId) ||
    (body.owner !== undefined && !isAddressValue(body.owner)) ||
    !isPositiveSafeInteger(body.byteLength) ||
    typeof body.bodyHash !== "string" ||
    !BODY_HASH_PATTERN.test(body.bodyHash)
  ) {
    throw new BadRequest();
  }

  return {
    jobId,
    chainId: body.chainId,
    ...(body.owner === undefined ? {} : { owner: body.owner }),
    byteLength: body.byteLength,
    bodyHash: body.bodyHash,
  };
}

export function accessRecordsBody(value: unknown): AccessRecordInput[] {
  const body = record(value);
  if (
    !Array.isArray(body.records) ||
    body.records.length === 0 ||
    body.records.length > MAX_ACCESS_RECORDS
  ) {
    throw new BadRequest();
  }

  return body.records.map(accessRecord);
}

function accessRecord(value: unknown): AccessRecordInput {
  const body = record(value);
  const denied = body.outcome === "denied";
  if (
    body.action !== ACCESS_RECORD_ACTION ||
    !isPositiveInteger(body.chainId) ||
    !isNonEmptyString(body.grantId) ||
    !isAddressValue(body.granteeAddress) ||
    !isNonEmptyString(body.logId) ||
    !isIsoTimestamp(body.occurredAt) ||
    !OUTCOMES.has(body.outcome as string) ||
    !isNonEmptyString(body.scope) ||
    !SOURCES.has(body.source as string) ||
    (body.tool !== undefined && !isNonEmptyString(body.tool)) ||
    (denied
      ? !isNonEmptyString(body.denyReason)
      : body.denyReason !== undefined)
  ) {
    throw new BadRequest();
  }

  return {
    action: ACCESS_RECORD_ACTION,
    chainId: body.chainId,
    ...(denied ? { denyReason: body.denyReason as string } : {}),
    grantId: body.grantId as string,
    granteeAddress: body.granteeAddress,
    logId: body.logId as string,
    occurredAt: body.occurredAt as string,
    outcome: body.outcome as AccessRecordInput["outcome"],
    scope: body.scope as string,
    source: body.source as AccessRecordInput["source"],
    ...(body.tool === undefined ? {} : { tool: body.tool as string }),
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isIsoTimestamp(value: unknown): value is string {
  return isNonEmptyString(value) && !Number.isNaN(Date.parse(value));
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

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isAddressValue(value: unknown): value is Address {
  return typeof value === "string" && isAddress(value);
}

function isBase64(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  try {
    return Buffer.from(value, "base64").toString("base64") === value;
  } catch {
    return false;
  }
}

function sameAddress(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function requestPath(request: IncomingMessage): string {
  return new URL(request.url ?? "/", "http://agent.invalid").pathname;
}

function sandboxLogsContainerId(path: string): string | undefined {
  return SANDBOX_LOGS_PATH_PATTERN.exec(path)?.[1];
}

function logTail(request: IncomingMessage): number {
  const value = new URL(
    request.url ?? "/",
    "http://agent.invalid",
  ).searchParams.get("tail");
  if (value === null) {
    return DEFAULT_LOG_TAIL;
  }
  const tail = Number(value);
  if (!Number.isSafeInteger(tail) || tail <= 0) {
    throw new BadRequest();
  }

  return Math.min(tail, MAX_LOG_TAIL);
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

function sendText(
  response: ServerResponse,
  status: number,
  body: string,
): void {
  response.statusCode = status;
  response.setHeader(CONTENT_TYPE_HEADER, TEXT_CONTENT_TYPE);
  response.end(body);
}

function sendError(
  response: ServerResponse,
  status: number,
  code: string,
  message: string,
): void {
  sendJson(response, status, { code, error: message });
}
