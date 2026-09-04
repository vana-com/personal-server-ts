import type {
  ECIESEncrypted,
  ECIESProvider,
} from "@opendatalabs/vana-sdk/crypto/ecies/interface";
import { getAddress, toHex, type Address, type Hex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { decryptEcies } from "../agent/ecies.js";
import { deriveEnclaveKey } from "../identity/wallet.js";
import { isNonTransientDockerSandboxError } from "../sandbox/docker-runtime.js";
import { SandboxSyncBlockedError } from "../sandbox/probes.js";
import type { SandboxRegistry } from "../sandbox/registry.js";
import type { SandboxSpec } from "../sandbox/runtime.js";
import type { SandboxContracts } from "../agent/bootstrap.js";
import { unseal } from "../sealing/envelope.js";
import { NODE_FAULT, type JobLogger, type JobRunResult } from "./claim-loop.js";
import { LeaseLostError, type GatewayClient } from "./gateway-client.js";
import {
  JobEnvelopeError,
  openJobRequest,
  type ClaimResponse,
  type JobExecuteError,
  type JobExecuteResponse,
  type JobRequestEnvelope,
} from "./types.js";

const EXECUTE_PATH = "/enclave/v1/jobs/execute";
const AUTHORIZATION_HEADER = "Authorization";
const CONTENT_TYPE_HEADER = "Content-Type";
const BEARER_PREFIX = "Bearer ";
const JSON_CONTENT_TYPE = "application/json";
const POST = "POST";
const OK = 200;
const EXECUTE_TIMEOUT_MS = 120_000;
const HEARTBEAT_DIVISOR = 3;
const MILLISECONDS_PER_SECOND = 1_000;
const MIN_TIMER_DELAY_MS = 0;
const INVALID_REQUEST_REASON = "REQUEST_INVALID";
const DEADLINE_REASON = "DEADLINE_PASSED";
const CHAIN_MISMATCH_REASON = "CHAIN_MISMATCH";
const SANDBOX_SYNC_BLOCKED_REASON = "SANDBOX_SYNC_BLOCKED";
const SYNC_ENABLED = "true";
const SYNC_DISABLED = "false";
const ENCRYPT_UNAVAILABLE = "ECIES encryption is unavailable";
const NORMALIZE_UNAVAILABLE = "ECIES key normalization is unavailable";
const INVALID_CIPHERTEXT = "Invalid job request ciphertext";
const LEASE_EXPIRED_MESSAGE = "Job lease expired without confirmation";
const NODE_DERIVATION_MISMATCH_MESSAGE =
  "Derived enclave key does not match the claimed identity";
const JOB_STAGE_FAILURE_MESSAGE = "Enclave job stage failed";
const SANDBOX_NODE_FAULT_MESSAGE = "Sandbox node fault; draining agent";
const DECRYPT_STAGE = "decrypt";
const UNSEAL_STAGE = "unseal";
const SANDBOX_ACQUIRE_STAGE = "sandbox-acquire";
const WORK_DELAY_STAGE = "work-delay";
const EXECUTE_STAGE = "execute";
const COMPLETE_STAGE = "complete";
const CHAIN_VALIDATION_STAGE = "chain-validation";
const UNKNOWN_ERROR = "unknown";
const MAX_ERROR_CAUSES = 5;
const RESULT_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const JOB_FAILURE_CODES = new Set<string>([
  "AUTH_INVALID",
  "BUILDER_MISMATCH",
  "OWNER_MISMATCH",
  "GRANT_REVOKED",
  "GRANT_INVALID",
  "SIGNED_ARTIFACT_MISSING",
  "SIGNED_ARTIFACT_INVALID",
  "SERVER_NOT_REGISTERED",
  "SCOPE_NOT_FOUND",
  "VERSION_MISMATCH",
  "DEADLINE_PASSED",
  "RESULT_SIGNING_REFUSED",
  "RESULT_UPLOAD_FAILED",
  "RESULT_TOO_LARGE",
  "INTERNAL",
]);
const TERMINAL_SYNC_BLOCK_REASONS = new Set([
  "unregistered",
  "registration_check_failed",
]);

type ClaimedJob = ClaimResponse["job"];
type ClaimedIdentity = ClaimResponse["identity"];
type SyncMode = "enabled" | "disabled";

export interface RunJobDeps {
  client: DstackClient;
  gateway: GatewayClient;
  registry: SandboxRegistry;
  image: string;
  gatewayUrl: string;
  storageApiUrl?: string;
  agentUrl: string;
  chainId: number;
  contracts: SandboxContracts;
  gatewayBypassSecret?: string;
  leaseSeconds: number;
  sync: SyncMode;
  logger: JobLogger;
  workDelayMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export class SandboxChainMismatchError extends Error {
  constructor(
    public readonly expectedChainId: number,
    public readonly receivedChainId: number,
  ) {
    super(
      `Gateway job chain ${receivedChainId} does not match sandbox chain ${expectedChainId}`,
    );
    this.name = "SandboxChainMismatchError";
  }
}

export async function runJob(
  job: ClaimedJob,
  identity: ClaimedIdentity,
  deps: RunJobDeps,
): Promise<JobRunResult> {
  const jobChainId = job.chainId ?? deps.chainId;
  if (jobChainId !== deps.chainId) {
    const error = new SandboxChainMismatchError(deps.chainId, jobChainId);
    logStageFailure(deps.logger, job.jobId, CHAIN_VALIDATION_STAGE, error);
    await failJob(job, CHAIN_MISMATCH_REASON, deps.gateway);
    return;
  }
  const lease = startLease(job, deps);
  const now = deps.now ?? Date.now;
  const runStartedAt = now();
  const requestFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? delay;
  const registryKey = `${identity.userPsId}:${identity.epoch}`;
  let acquired = false;

  try {
    let decrypted: DecryptResult;
    try {
      decrypted = await decryptRequest(job, identity, deps.client);
    } catch (error) {
      logStageFailure(deps.logger, job.jobId, DECRYPT_STAGE, error);
      return;
    }
    if (decrypted.kind === "node-fault") {
      deps.logger.warn({ jobId: job.jobId }, NODE_DERIVATION_MISMATCH_MESSAGE);
      return;
    }
    if (lease.lost()) {
      logLeaseLost(deps.logger, job.jobId, DECRYPT_STAGE, runStartedAt, now());
      return;
    }
    if (decrypted.kind === "invalid") {
      await failJob(job, INVALID_REQUEST_REASON, deps.gateway);
      return;
    }
    const { envelope } = decrypted;
    if (!requestMatches(envelope, job, now())) {
      await failJob(job, failureReason(envelope, now()), deps.gateway);
      return;
    }

    let signature: Uint8Array;
    try {
      signature = await unseal(
        deps.client,
        identity.userPsId,
        identity.epoch,
        identity.sealedEnvelope,
      );
    } catch (error) {
      logStageFailure(deps.logger, job.jobId, UNSEAL_STAGE, error);
      return;
    }

    let sandbox;
    const acquireStartedAt = now();
    const acquireEvents = new Set<string>();
    logAcquisitionEvent(
      deps.logger,
      job.jobId,
      "start",
      acquireStartedAt,
      now(),
    );
    try {
      sandbox = await deps.registry.acquire(
        registryKey,
        (accessToken) => {
          const spec = sandboxSpec(
            identity,
            deps,
            accessToken,
            signature,
            (event) => {
              acquireEvents.add(event);
              logAcquisitionEvent(
                deps.logger,
                job.jobId,
                event,
                acquireStartedAt,
                now(),
              );
            },
          );
          signature.fill(0);

          return spec;
        },
        lease.signal,
      );
      acquired = true;
      for (const event of ["healthy", "synced"] as const) {
        if (!acquireEvents.has(event)) {
          logAcquisitionEvent(
            deps.logger,
            job.jobId,
            event,
            acquireStartedAt,
            now(),
          );
        }
      }
    } catch (error) {
      if (lease.lost()) {
        logLeaseLost(
          deps.logger,
          job.jobId,
          SANDBOX_ACQUIRE_STAGE,
          acquireStartedAt,
          now(),
        );
        return;
      }
      if (
        error instanceof SandboxSyncBlockedError &&
        TERMINAL_SYNC_BLOCK_REASONS.has(error.reason)
      ) {
        logStageFailure(deps.logger, job.jobId, SANDBOX_ACQUIRE_STAGE, error);
        await failJob(job, SANDBOX_SYNC_BLOCKED_REASON, deps.gateway);
        return;
      }
      if (isNonTransientDockerSandboxError(error)) {
        logNodeFault(deps.logger, job.jobId, error);
        return NODE_FAULT;
      }
      logStageFailure(deps.logger, job.jobId, SANDBOX_ACQUIRE_STAGE, error);
      return;
    } finally {
      signature.fill(0);
    }
    if (lease.lost()) {
      logLeaseLost(
        deps.logger,
        job.jobId,
        SANDBOX_ACQUIRE_STAGE,
        acquireStartedAt,
        now(),
      );
      return;
    }

    if (deps.workDelayMs) {
      const delayStartedAt = now();
      await sleep(deps.workDelayMs);
      if (lease.lost()) {
        logLeaseLost(
          deps.logger,
          job.jobId,
          WORK_DELAY_STAGE,
          delayStartedAt,
          now(),
        );
        return;
      }
    }

    const remainingMs = Date.parse(envelope.request.deadline) - now();
    if (remainingMs <= 0) {
      await failJob(job, DEADLINE_REASON, deps.gateway);
      return;
    }

    const executeStartedAt = now();
    const result = await executeSandbox(
      {
        origin: sandbox.handle.origin,
        accessToken: sandbox.accessToken,
        envelope,
        timeoutMs: Math.min(remainingMs, EXECUTE_TIMEOUT_MS),
        requestFetch,
        leaseSignal: lease.signal,
      },
      deps.registry.bindJob(registryKey, {
        jobId: job.jobId,
        chainId: jobChainId,
        owner: job.owner,
        userPsId: identity.userPsId,
        epoch: identity.epoch,
        serverAddress: identity.enclaveAddress,
      }),
    );
    await lease.settled();
    if (lease.lost()) {
      logLeaseLost(
        deps.logger,
        job.jobId,
        EXECUTE_STAGE,
        executeStartedAt,
        now(),
      );
      return;
    }
    if (result.kind === "retry") {
      return;
    }
    if (result.kind === "fail") {
      await failJob(job, result.reason, deps.gateway);
      return;
    }

    const completeStartedAt = now();
    try {
      await deps.gateway.complete(job.jobId, {
        fencingToken: job.fencingToken,
        resultObjectKey: result.response.resultObjectKey,
        resultHash: result.response.resultHash,
        resultSize: result.response.resultSize,
      });
    } catch (error) {
      if (error instanceof LeaseLostError) {
        logLeaseLost(
          deps.logger,
          job.jobId,
          COMPLETE_STAGE,
          completeStartedAt,
          now(),
        );
        return;
      }

      logStageFailure(deps.logger, job.jobId, COMPLETE_STAGE, error);
      return;
    }
  } finally {
    lease.stop();
    await lease.settled();
    if (acquired) {
      deps.registry.release(registryKey);
    }
  }
}

interface LeaseState {
  signal: AbortSignal;
  lost(): boolean;
  settled(): Promise<void>;
  stop(): void;
}

function startLease(job: ClaimedJob, deps: RunJobDeps): LeaseState {
  const controller = new AbortController();
  const now = deps.now ?? Date.now;
  let leaseLost = false;
  let leaseDeadline = parseLeaseDeadline(job.claimExpiresAt, now());
  let pending = Promise.resolve();
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const intervalMs =
    (deps.leaseSeconds * MILLISECONDS_PER_SECOND) / HEARTBEAT_DIVISOR;
  const timer = setInterval(() => {
    pending = pending.then(async () => {
      if (leaseLost) {
        return;
      }

      try {
        const response = await deps.gateway.heartbeat(job.jobId, {
          fencingToken: job.fencingToken,
          leaseSeconds: deps.leaseSeconds,
        });
        if (response.claimExpiresAt) {
          leaseDeadline = parseLeaseDeadline(response.claimExpiresAt, now());
          armDeadline();
        }
      } catch (error) {
        if (error instanceof LeaseLostError) {
          loseLease();
          return;
        }
        if (now() >= leaseDeadline) {
          expireLease();
        }
      }
    });
  }, intervalMs);
  timer.unref();
  armDeadline();

  function armDeadline(): void {
    if (deadlineTimer) {
      clearTimeout(deadlineTimer);
    }

    const delayMs = Math.max(MIN_TIMER_DELAY_MS, leaseDeadline - now());
    deadlineTimer = setTimeout(expireLease, delayMs);
    deadlineTimer.unref();
  }

  function expireLease(): void {
    if (leaseLost) {
      return;
    }
    if (now() < leaseDeadline) {
      armDeadline();
      return;
    }

    loseLease();
    deps.logger.warn({ jobId: job.jobId }, LEASE_EXPIRED_MESSAGE);
  }

  function loseLease(): void {
    if (leaseLost) {
      return;
    }

    leaseLost = true;
    controller.abort();
  }

  return {
    signal: controller.signal,
    lost: () => leaseLost,
    settled: () => pending,
    stop(): void {
      clearInterval(timer);
      if (deadlineTimer) {
        clearTimeout(deadlineTimer);
      }
    },
  };
}

function parseLeaseDeadline(value: string, fallback: number): number {
  const deadline = Date.parse(value);

  return Number.isFinite(deadline) ? deadline : fallback;
}

async function decryptRequest(
  job: ClaimedJob,
  identity: ClaimedIdentity,
  client: DstackClient,
): Promise<DecryptResult> {
  const derived = await deriveEnclaveKey(
    client,
    identity.userPsId,
    identity.epoch,
  );

  try {
    if (getAddress(derived.address) !== getAddress(identity.enclaveAddress)) {
      return { kind: "node-fault" };
    }

    return {
      kind: "envelope",
      envelope: await openJobRequest(
        job.requestCiphertext,
        derived.key,
        DECRYPT_ONLY_ECIES,
      ),
    };
  } catch (error) {
    if (error instanceof JobEnvelopeError) {
      return { kind: "invalid" };
    }
    throw error;
  } finally {
    derived.key.fill(0);
  }
}

type DecryptResult =
  | { kind: "envelope"; envelope: JobRequestEnvelope }
  | { kind: "invalid" }
  | { kind: "node-fault" };

function logStageFailure(
  logger: JobLogger,
  jobId: string,
  stage: string,
  error: unknown,
): void {
  const [root, ...causes] = errorChain(error);

  logger.warn(
    {
      jobId,
      stage,
      error: root,
      causes,
    },
    JOB_STAGE_FAILURE_MESSAGE,
  );
}

function logNodeFault(logger: JobLogger, jobId: string, error: unknown): void {
  const [root, ...causes] = errorChain(error);

  logger.error(
    {
      jobId,
      stage: SANDBOX_ACQUIRE_STAGE,
      error: root,
      causes,
    },
    SANDBOX_NODE_FAULT_MESSAGE,
  );
}

function logAcquisitionEvent(
  logger: JobLogger,
  jobId: string,
  event: "start" | "healthy" | "synced",
  startedAt: number,
  currentTime: number,
): void {
  logger.info(
    {
      jobId,
      stage: SANDBOX_ACQUIRE_STAGE,
      event,
      elapsedMs: Math.max(0, currentTime - startedAt),
    },
    "Sandbox acquisition progress",
  );
}

function logLeaseLost(
  logger: JobLogger,
  jobId: string,
  stage: string,
  startedAt: number,
  currentTime: number,
): void {
  logger.warn(
    {
      jobId,
      stage,
      elapsedMs: Math.max(0, currentTime - startedAt),
    },
    "Job lease lost",
  );
}

interface LoggedError {
  name: string;
  message: string;
}

function errorChain(error: unknown): LoggedError[] {
  const chain: LoggedError[] = [];
  const seen = new Set<Error>();
  let current = error;

  while (chain.length <= MAX_ERROR_CAUSES && current instanceof Error) {
    if (seen.has(current)) {
      break;
    }

    seen.add(current);
    chain.push({ name: current.name, message: current.message });
    current = current.cause;
  }

  return chain.length > 0
    ? chain
    : [{ name: UNKNOWN_ERROR, message: UNKNOWN_ERROR }];
}

function requestMatches(
  envelope: JobRequestEnvelope,
  job: ClaimedJob,
  nowMs: number,
): boolean {
  const { request } = envelope;

  return (
    request.jobId === job.jobId &&
    sameAddress(request.owner, job.owner) &&
    request.grantId.toLowerCase() === job.grantId.toLowerCase() &&
    request.scope === job.scope &&
    Date.parse(request.deadline) > nowMs
  );
}

function failureReason(envelope: JobRequestEnvelope, nowMs: number): string {
  if (Date.parse(envelope.request.deadline) <= nowMs) {
    return DEADLINE_REASON;
  }

  return INVALID_REQUEST_REASON;
}

function sandboxSpec(
  identity: ClaimedIdentity,
  deps: RunJobDeps,
  accessToken: string,
  signature: Uint8Array,
  onProgress: NonNullable<SandboxSpec["onProgress"]>,
): SandboxSpec {
  return {
    userPsId: identity.userPsId,
    epoch: identity.epoch,
    image: deps.image,
    onProgress,
    env: {
      VANA_MASTER_KEY_SIGNATURE: toHex(signature),
      PS_ACCESS_TOKEN: accessToken,
      PS_SERVER_ADDRESS: identity.enclaveAddress,
      PS_SERVER_PUBLIC_KEY: identity.enclavePublicKey,
      SYNC_ENABLED: deps.sync === "enabled" ? SYNC_ENABLED : SYNC_DISABLED,
      GATEWAY_URL: deps.gatewayUrl,
      ENCLAVE_AGENT_URL: deps.agentUrl,
      CHAIN_ID: String(deps.chainId),
      DATA_REGISTRY_CONTRACT: deps.contracts.dataRegistry,
      DATA_PORTABILITY_SERVER_CONTRACT: deps.contracts.dataPortabilityServer,
      DATA_PORTABILITY_GRANTEES_CONTRACT:
        deps.contracts.dataPortabilityGrantees,
      DATA_PORTABILITY_PERMISSIONS_CONTRACT:
        deps.contracts.dataPortabilityPermissions,
      ...(deps.storageApiUrl ? { STORAGE_API_URL: deps.storageApiUrl } : {}),
      ...(deps.gatewayBypassSecret
        ? { VERCEL_PROTECTION_BYPASS: deps.gatewayBypassSecret }
        : {}),
    },
  };
}

type ExecuteResult =
  | { kind: "complete"; response: JobExecuteResponse }
  | { kind: "fail"; reason: string }
  | { kind: "retry" };

interface ExecuteOptions {
  origin: string;
  accessToken: string;
  envelope: JobRequestEnvelope;
  timeoutMs: number;
  requestFetch: typeof fetch;
  leaseSignal: AbortSignal;
}

async function executeSandbox(
  options: ExecuteOptions,
  unbindJob: () => void,
): Promise<ExecuteResult> {
  try {
    const response = await options.requestFetch(
      `${options.origin}${EXECUTE_PATH}`,
      {
        method: POST,
        headers: {
          [AUTHORIZATION_HEADER]: `${BEARER_PREFIX}${options.accessToken}`,
          [CONTENT_TYPE_HEADER]: JSON_CONTENT_TYPE,
        },
        body: JSON.stringify(options.envelope),
        signal: AbortSignal.any([
          options.leaseSignal,
          AbortSignal.timeout(options.timeoutMs),
        ]),
      },
    );
    const body = (await response.json()) as unknown;
    if (response.status === OK && isExecuteResponse(body)) {
      return { kind: "complete", response: body };
    }
    if (!isExecuteError(body) || body.error.retryable) {
      return { kind: "retry" };
    }

    return { kind: "fail", reason: body.error.code };
  } catch {
    return { kind: "retry" };
  } finally {
    unbindJob();
  }
}

async function failJob(
  job: ClaimedJob,
  reason: string,
  gateway: GatewayClient,
): Promise<void> {
  try {
    await gateway.fail(job.jobId, {
      fencingToken: job.fencingToken,
      reason,
    });
  } catch (error) {
    if (error instanceof LeaseLostError) {
      return;
    }
  }
}

function isExecuteResponse(value: unknown): value is JobExecuteResponse {
  if (!isRecord(value)) {
    return false;
  }

  return (
    typeof value.resultObjectKey === "string" &&
    value.resultObjectKey.length > 0 &&
    isResultHash(value.resultHash) &&
    typeof value.resultSize === "number" &&
    Number.isInteger(value.resultSize) &&
    value.resultSize >= 0
  );
}

function isExecuteError(value: unknown): value is JobExecuteError {
  if (!isRecord(value) || !isRecord(value.error)) {
    return false;
  }

  return (
    isFailureCode(value.error.code) &&
    typeof value.error.message === "string" &&
    typeof value.error.retryable === "boolean"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isResultHash(value: unknown): value is Hex {
  return typeof value === "string" && RESULT_HASH_PATTERN.test(value);
}

function isFailureCode(
  value: unknown,
): value is JobExecuteError["error"]["code"] {
  return typeof value === "string" && JOB_FAILURE_CODES.has(value);
}

function sameAddress(left: Address, right: Address): boolean {
  try {
    return getAddress(left) === getAddress(right);
  } catch {
    return false;
  }
}

// Decrypt-only SDK adapter; encryption stays unavailable on the agent path.
const DECRYPT_ONLY_ECIES: ECIESProvider = {
  async decrypt(
    privateKey: Uint8Array,
    encrypted: ECIESEncrypted,
  ): Promise<Uint8Array> {
    try {
      return decryptEcies(
        privateKey,
        Buffer.concat([
          encrypted.iv,
          encrypted.ephemPublicKey,
          encrypted.ciphertext,
          encrypted.mac,
        ]),
      );
    } catch {
      throw new JobEnvelopeError(INVALID_CIPHERTEXT);
    }
  },
  async encrypt(): Promise<ECIESEncrypted> {
    throw new Error(ENCRYPT_UNAVAILABLE);
  },
  normalizeToUncompressed(): Uint8Array {
    throw new Error(NORMALIZE_UNAVAILABLE);
  },
};

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
