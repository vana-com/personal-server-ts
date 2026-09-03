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
  parseWeb3SignedHeader,
  verifyWeb3Signed,
  type DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";
import type { Logger } from "pino";
import { isAddressEqual, type Address, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  JOB_PROTOCOL_VERSION,
  MAX_INLINE_RESULT_BYTES,
  type JobExecuteResponse,
  type JobFailureCode,
  type JobRequestEnvelope,
  type JobResult,
} from "./types.js";

const RAW_READ = "raw_read";
const EXECUTE_PATH = "/v1/jobs/execute";
const POST = "POST";
const JSON_CONTENT_TYPE = "application/json";
const UNKNOWN_METADATA = "unknown";
const MILLISECONDS_PER_SECOND = 1_000;

export interface JobEcies {
  encrypt(
    publicKey: Uint8Array | Hex,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
}

export interface JobWorkerDeps {
  serverOwner: Address;
  serverAddress: Address;
  serverPublicKey: Hex;
  gateway: ProtocolGatewayPort;
  gatewayConfig: DataPortabilityGatewayConfig;
  storage: DataStoragePort;
  ecies: JobEcies;
  now?: () => Date;
  logger: Logger;
  accessLogWriter: AccessLogWriter;
  scopeDeletions?: ScopeDeletionTracker;
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

  const now = deps.now?.() ?? new Date();
  if (!validDeadline(request.deadline, now)) {
    throw new JobFailure("DEADLINE_PASSED", "job deadline passed", false);
  }

  const auth = await verifyJobAuth(envelope, now);
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
    !sameAddress(registration.ownerAddress, deps.serverOwner)
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
    jobId: request.jobId,
    scope: request.scope,
    version: localVersion === 0 ? null : String(localVersion),
    contentType: JSON_CONTENT_TYPE,
    body: Buffer.from(JSON.stringify(redacted)).toString("base64"),
  };
  const encrypted = await deps.ecies.encrypt(
    request.builderPublicKey,
    Buffer.from(JSON.stringify(result)),
  );
  if (encrypted.byteLength > MAX_INLINE_RESULT_BYTES) {
    throw new JobFailure(
      "RESULT_TOO_LARGE",
      "encrypted result is too large",
      false,
    );
  }

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
    resultCiphertext: Buffer.from(encrypted).toString("base64"),
    resultHash: `0x${createHash("sha256").update(encrypted).digest("hex")}`,
    resultSize: encrypted.byteLength,
  };
}

async function verifyJobAuth(
  envelope: JobRequestEnvelope,
  now: Date,
): Promise<{ signer: Address }> {
  try {
    const parsed = parseWeb3SignedHeader(envelope.auth);

    return await verifyWeb3Signed({
      headerValue: envelope.auth,
      expectedOrigin: parsed.payload.aud,
      expectedMethod: POST,
      expectedPath: EXECUTE_PATH,
      bodyBytes: Buffer.from(JSON.stringify(envelope.request)),
      now: Math.floor(now.getTime() / MILLISECONDS_PER_SECOND),
    });
  } catch {
    throw new JobFailure("AUTH_INVALID", "job authorization is invalid", false);
  }
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

  return new JobFailure("GRANT_INVALID", "grant is invalid", false);
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

  return new JobFailure(
    "SIGNED_ARTIFACT_INVALID",
    "signed artifact is invalid",
    false,
  );
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
