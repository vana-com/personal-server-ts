import { createHash, randomUUID } from "node:crypto";
import {
  assertScopeNotDeleted,
  redactEnvelopeForGrantee,
} from "@opendatalabs/personal-server-ts-core/api";
import { readDataContract } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  DataDeletedError,
  GrantRevokedError,
  InvalidSignatureError,
  ProtocolError,
  SignedArtifactInvalidError,
  SignedArtifactMissingError,
  UnregisteredBuilderError,
} from "@opendatalabs/personal-server-ts-core/errors";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type {
  DataStoragePort,
  ProtocolGatewayPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import {
  verifyDataReadPolicy,
  verifySignedArtifacts,
} from "@opendatalabs/personal-server-ts-core/policy";
import type { ScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import {
  verifyWeb3Signed,
  type DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";
import {
  canonicalJobRequestBytes,
  sealJobResult,
} from "@opendatalabs/vana-sdk/crypto/envelope/job";
import {
  JOB_PROTOCOL_VERSION,
  type JobRequestEnvelope,
  type JobResult,
} from "@opendatalabs/vana-sdk/protocol/jobs";
import type { ECIESProvider } from "@opendatalabs/vana-sdk/crypto/ecies/interface";
import type { Logger } from "pino";
import { isAddressEqual, type Address, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import type { JobExecuteResponse, JobFailureCode } from "./types.js";

const RAW_READ = "raw_read";
const EXECUTE_PATH = "/v1/jobs/execute";
const POST = "POST";
const JSON_CONTENT_TYPE = "application/json";
const UNKNOWN_METADATA = "unknown";
const MILLISECONDS_PER_SECOND = 1_000;
const JOB_EXECUTION_FAILED_LOG = "Enclave job execution failed";
const RESULT_SIGNING_PATH = "/agent/v1/job-results/sign";
const RESULT_OBJECT_PREFIX = "jobresults";
const PUT = "PUT";
const JOB_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface JobWorkerDeps {
  serverOwner: Address;
  serverAddress: Address;
  serverPublicKey: Hex;
  authAudience: string;
  gateway: ProtocolGatewayPort;
  gatewayConfig: DataPortabilityGatewayConfig;
  storage: DataStoragePort;
  ecies: ECIESProvider;
  now?: () => Date;
  logger: Logger;
  accessLogWriter: AccessLogWriter;
  scopeDeletions?: ScopeDeletionTracker;
  resultUpload: {
    storageEndpoint: string;
    agentEndpoint: string;
    accessToken: string;
    chainId: number;
    fetch?: typeof fetch;
  };
}

export class JobFailure extends Error {
  constructor(
    public readonly code: JobFailureCode,
    message: string,
    public readonly retryable: boolean,
  ) {
    super(message);
    this.name = "JobFailure";
  }
}

export async function executeJob(
  envelope: JobRequestEnvelope,
  deps: JobWorkerDeps,
): Promise<JobExecuteResponse> {
  try {
    return await executeJobUnsafe(envelope, deps);
  } catch (error) {
    if (error instanceof JobFailure) {
      throw error;
    }

    deps.logger.warn(
      { jobId: envelope.request.jobId, error: errorSummary(error) },
      JOB_EXECUTION_FAILED_LOG,
    );
    throw new JobFailure("INTERNAL", "job execution failed", true);
  }
}

async function executeJobUnsafe(
  envelope: JobRequestEnvelope,
  deps: JobWorkerDeps,
): Promise<JobExecuteResponse> {
  const { request } = envelope;
  if (request.v !== JOB_PROTOCOL_VERSION) {
    throw new JobFailure("INTERNAL", "protocol version not supported", false);
  }
  if (request.operation !== RAW_READ) {
    throw new JobFailure("INTERNAL", "operation not supported", false);
  }
  const jobId = normalizeJobId(request.jobId);

  const now = deps.now?.() ?? new Date();
  if (!validDeadline(request.deadline, now)) {
    throw new JobFailure("DEADLINE_PASSED", "job deadline passed", false);
  }

  const auth = await verifyJobAuth(envelope, deps.authAudience, now);
  if (!sameAddress(auth.signer, request.builder)) {
    throw new JobFailure(
      "BUILDER_MISMATCH",
      "builder identity mismatch",
      false,
    );
  }
  if (!sameAddress(request.owner, deps.serverOwner)) {
    throw new JobFailure("OWNER_MISMATCH", "job owner mismatch", false);
  }

  let grant;
  try {
    grant = await verifyDataReadPolicy(
      {
        signer: request.builder,
        grantId: request.grantId,
        requestedScope: request.scope,
        serverOwner: deps.serverOwner,
      },
      { authSessionVerifier: deps.gateway, grantVerifier: deps.gateway },
    );
  } catch (error) {
    throw mapPolicyFailure(error);
  }

  const builder = await deps.gateway.getBuilder(request.builder);
  if (!builder) {
    throw new JobFailure(
      "BUILDER_MISMATCH",
      "builder is not registered",
      false,
    );
  }
  try {
    await verifySignedArtifacts({
      grant,
      builder,
      gatewayConfig: deps.gatewayConfig,
      ownerAddress: deps.serverOwner,
    });
  } catch (error) {
    throw mapArtifactFailure(error);
  }

  let builderKeyAddress: Address;
  try {
    builderKeyAddress = publicKeyToAddress(builder.publicKey as Hex);
  } catch {
    throw new JobFailure(
      "SIGNED_ARTIFACT_INVALID",
      "builder public key is invalid",
      false,
    );
  }
  if (
    !sameAddress(builderKeyAddress, request.builder) ||
    builder.publicKey.toLowerCase() !== request.builderPublicKey.toLowerCase()
  ) {
    throw new JobFailure("BUILDER_MISMATCH", "builder key mismatch", false);
  }

  const registration = await deps.gateway.getServer(deps.serverAddress);
  if (
    !registration ||
    registration.revokedAt !== null ||
    !sameAddress(registration.ownerAddress, deps.serverOwner) ||
    registration.publicKey.toLowerCase() !== deps.serverPublicKey.toLowerCase()
  ) {
    throw new JobFailure(
      "SERVER_NOT_REGISTERED",
      "server registration is invalid",
      false,
    );
  }

  const entry = deps.storage.findEntry({ scope: request.scope });
  try {
    await assertScopeNotDeleted(
      { scopeDeletions: deps.scopeDeletions, serverOwner: deps.serverOwner },
      request.scope,
      entry,
    );
  } catch (error) {
    if (error instanceof DataDeletedError) {
      throw new JobFailure("SCOPE_NOT_FOUND", "scope not found", false);
    }

    throw error;
  }
  const read = await readDataContract({
    storage: deps.storage,
    scopeParam: request.scope,
  });
  if (!read.ok || !entry) {
    throw new JobFailure("SCOPE_NOT_FOUND", "scope not found", false);
  }

  const localVersion = await deps.storage.findLatestVersionByScope(
    request.scope,
  );
  if (
    request.pinnedVersion !== null &&
    String(localVersion) !== request.pinnedVersion
  ) {
    throw new JobFailure("VERSION_MISMATCH", "scope version mismatch", true);
  }

  const redacted = redactEnvelopeForGrantee(read.envelope);
  const result: JobResult = {
    v: JOB_PROTOCOL_VERSION,
    jobId,
    scope: request.scope,
    version: localVersion === 0 ? null : String(localVersion),
    contentType: JSON_CONTENT_TYPE,
    body: new TextEncoder().encode(JSON.stringify(redacted)),
  };
  const sealed = await sealJobResult(
    result,
    request.builderPublicKey,
    deps.ecies,
  );
  const sealedBytes = sealed.bytes;
  const digest = createHash("sha256").update(sealedBytes).digest("hex");
  const resultHash = `0x${digest}` as Hex;
  const resultSize = sealedBytes.byteLength;
  const encodedJobId = encodeURIComponent(jobId);
  const owner = deps.serverOwner.toLowerCase();
  const resultObjectKey = `${RESULT_OBJECT_PREFIX}/${deps.resultUpload.chainId}/${encodedJobId}`;
  const uploadPath = `/v1/job-results/${deps.resultUpload.chainId}/${owner}/${encodedJobId}`;
  const requestFetch = deps.resultUpload.fetch ?? fetch;
  const authorization = await requestUploadSignature(requestFetch, {
    agentEndpoint: deps.resultUpload.agentEndpoint,
    accessToken: deps.resultUpload.accessToken,
    jobId,
    chainId: deps.resultUpload.chainId,
    owner: deps.serverOwner,
    byteLength: resultSize,
    bodyHash: `sha256:${digest}`,
  });
  await uploadResult(requestFetch, {
    storageEndpoint: deps.resultUpload.storageEndpoint,
    path: uploadPath,
    authorization,
    body: sealedBytes,
  });

  await deps.accessLogWriter.write({
    logId: randomUUID(),
    grantId: request.grantId,
    builder: request.builder,
    action: "read",
    scope: request.scope,
    timestamp: now.toISOString(),
    ipAddress: UNKNOWN_METADATA,
    userAgent: UNKNOWN_METADATA,
  });
  deps.logger.info(
    { jobId: request.jobId, scope: request.scope, version: localVersion },
    "Enclave job read served",
  );

  return {
    resultObjectKey,
    resultHash,
    resultSize,
  };
}

interface UploadSignatureRequest {
  agentEndpoint: string;
  accessToken: string;
  jobId: string;
  chainId: number;
  owner: Address;
  byteLength: number;
  bodyHash: string;
}

async function requestUploadSignature(
  requestFetch: typeof fetch,
  request: UploadSignatureRequest,
): Promise<string> {
  let response: Response;
  try {
    response = await requestFetch(
      `${request.agentEndpoint.replace(/\/$/, "")}${RESULT_SIGNING_PATH}`,
      {
        method: POST,
        headers: {
          Authorization: `Bearer ${request.accessToken}`,
          "Content-Type": JSON_CONTENT_TYPE,
        },
        body: JSON.stringify({
          jobId: request.jobId,
          chainId: request.chainId,
          owner: request.owner,
          byteLength: request.byteLength,
          bodyHash: request.bodyHash,
        }),
      },
    );
  } catch {
    throw new JobFailure(
      "RESULT_UPLOAD_FAILED",
      "result signing service is unavailable",
      true,
    );
  }
  if (!response.ok) {
    if (response.status >= 500) {
      throw new JobFailure(
        "RESULT_UPLOAD_FAILED",
        "result signing service is unavailable",
        true,
      );
    }
    throw new JobFailure(
      "RESULT_SIGNING_REFUSED",
      "result upload signing was refused",
      false,
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  if (
    !body ||
    typeof body !== "object" ||
    !("authorization" in body) ||
    typeof body.authorization !== "string" ||
    !body.authorization.startsWith("Web3Signed ")
  ) {
    throw new JobFailure(
      "RESULT_SIGNING_REFUSED",
      "result upload signing response is invalid",
      false,
    );
  }

  return body.authorization;
}

interface ResultUploadRequest {
  storageEndpoint: string;
  path: string;
  authorization: string;
  body: Uint8Array;
}

async function uploadResult(
  requestFetch: typeof fetch,
  request: ResultUploadRequest,
): Promise<void> {
  let response: Response;
  try {
    const storageOrigin = new URL(request.storageEndpoint).origin;
    response = await requestFetch(`${storageOrigin}${request.path}`, {
      method: PUT,
      headers: {
        Authorization: request.authorization,
        "Content-Type": "application/octet-stream",
      },
      body: Buffer.from(
        request.body.buffer as ArrayBuffer,
        request.body.byteOffset,
        request.body.byteLength,
      ),
    });
  } catch {
    throw new JobFailure("RESULT_UPLOAD_FAILED", "result upload failed", true);
  }
  if (response.status === 413) {
    throw new JobFailure(
      "RESULT_TOO_LARGE",
      "sealed result exceeds the 100 MB storage limit",
      false,
    );
  }
  if (!response.ok) {
    throw new JobFailure(
      "RESULT_UPLOAD_FAILED",
      "result upload failed",
      response.status >= 500,
    );
  }
}

async function verifyJobAuth(
  envelope: JobRequestEnvelope,
  authAudience: string,
  now: Date,
): Promise<{ signer: Address }> {
  try {
    // aud = Gateway origin; contract section 1 step 1 amendment.
    return await verifyWeb3Signed({
      headerValue: envelope.auth,
      expectedOrigin: authAudience,
      expectedMethod: POST,
      expectedPath: EXECUTE_PATH,
      bodyBytes: canonicalJobRequestBytes(envelope.request),
      now: Math.floor(now.getTime() / MILLISECONDS_PER_SECOND),
    });
  } catch {
    throw new JobFailure("AUTH_INVALID", "job authorization is invalid", false);
  }
}

function normalizeJobId(jobId: string): string {
  if (!JOB_ID_PATTERN.test(jobId)) {
    throw new JobFailure("INTERNAL", "job id is invalid", false);
  }

  return jobId.toLowerCase();
}

function mapPolicyFailure(error: unknown): JobFailure {
  if (error instanceof GrantRevokedError) {
    return new JobFailure("GRANT_REVOKED", "grant is revoked", false);
  }
  if (
    error instanceof InvalidSignatureError ||
    error instanceof UnregisteredBuilderError
  ) {
    return new JobFailure(
      "BUILDER_MISMATCH",
      "builder is not authorized",
      false,
    );
  }
  if (error instanceof ProtocolError) {
    return new JobFailure("GRANT_INVALID", "grant is invalid", false);
  }

  return new JobFailure("INTERNAL", "policy verification failed", true);
}

function mapArtifactFailure(error: unknown): JobFailure {
  if (error instanceof SignedArtifactMissingError) {
    return new JobFailure(
      "SIGNED_ARTIFACT_MISSING",
      "signed artifact is missing",
      false,
    );
  }
  if (error instanceof GrantRevokedError) {
    return new JobFailure("GRANT_REVOKED", "grant is revoked", false);
  }
  if (error instanceof SignedArtifactInvalidError) {
    return new JobFailure(
      "SIGNED_ARTIFACT_INVALID",
      "signed artifact is invalid",
      false,
    );
  }
  if (error instanceof ProtocolError) {
    return new JobFailure(
      "SIGNED_ARTIFACT_INVALID",
      "signed artifact is invalid",
      false,
    );
  }

  return new JobFailure("INTERNAL", "artifact verification failed", true);
}

function errorSummary(error: unknown): string {
  return error instanceof Error
    ? `${error.name}: ${error.message}`
    : String(error);
}

function validDeadline(deadline: string, now: Date): boolean {
  const timestamp = Date.parse(deadline);

  return Number.isFinite(timestamp) && timestamp > now.getTime();
}

function sameAddress(left: string, right: string): boolean {
  try {
    return isAddressEqual(left as Address, right as Address);
  } catch {
    return false;
  }
}
