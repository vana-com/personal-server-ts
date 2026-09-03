import type {
  ECIESEncrypted,
  ECIESProvider,
} from "@opendatalabs/vana-sdk/crypto/ecies/interface";
import { getAddress, toHex, type Address, type Hex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { decryptEcies } from "../agent/ecies.js";
import { deriveEnclaveKey } from "../identity/wallet.js";
import type { SandboxRegistry } from "../sandbox/registry.js";
import type { SandboxSpec } from "../sandbox/runtime.js";
import { unseal } from "../sealing/envelope.js";
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
const INVALID_REQUEST_REASON = "REQUEST_INVALID";
const DEADLINE_REASON = "DEADLINE_PASSED";
const SYNC_ENABLED = "true";
const SYNC_DISABLED = "false";
const ENCRYPT_UNAVAILABLE = "ECIES encryption is unavailable";
const NORMALIZE_UNAVAILABLE = "ECIES key normalization is unavailable";
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
  "RESULT_TOO_LARGE",
  "INTERNAL",
]);

type ClaimedJob = ClaimResponse["job"];
type ClaimedIdentity = ClaimResponse["identity"];
type SyncMode = "enabled" | "disabled";

export interface RunJobDeps {
  client: DstackClient;
  gateway: GatewayClient;
  registry: SandboxRegistry;
  image: string;
  leaseSeconds: number;
  sync: SyncMode;
  workDelayMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export async function runJob(
  job: ClaimedJob,
  identity: ClaimedIdentity,
  deps: RunJobDeps,
): Promise<void> {
  const lease = startLease(job, deps);
  const now = deps.now ?? Date.now;
  const requestFetch = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? delay;
  const registryKey = `${identity.userPsId}:${identity.epoch}`;
  let acquired = false;

  try {
    let envelope: JobRequestEnvelope | undefined;
    try {
      envelope = await decryptRequest(job, identity, deps.client);
    } catch {
      return;
    }
    if (!envelope || lease.lost()) {
      if (!lease.lost()) {
        await failJob(job, INVALID_REQUEST_REASON, deps.gateway);
      }
      return;
    }
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
    } catch {
      return;
    }

    let sandbox;
    try {
      sandbox = await deps.registry.acquire(registryKey, (accessToken) => {
        const spec = sandboxSpec(identity, deps, accessToken, signature);
        signature.fill(0);

        return spec;
      });
      acquired = true;
    } catch {
      return;
    } finally {
      signature.fill(0);
    }
    if (lease.lost()) {
      return;
    }

    if (deps.workDelayMs) {
      await sleep(deps.workDelayMs);
    }
    if (lease.lost()) {
      return;
    }

    const remainingMs = Date.parse(envelope.request.deadline) - now();
    if (remainingMs <= 0) {
      await failJob(job, DEADLINE_REASON, deps.gateway);
      return;
    }

    const result = await executeSandbox({
      origin: sandbox.handle.origin,
      accessToken: sandbox.accessToken,
      envelope,
      timeoutMs: Math.min(remainingMs, EXECUTE_TIMEOUT_MS),
      requestFetch,
      leaseSignal: lease.signal,
    });
    await lease.settled();
    if (lease.lost() || result.kind === "retry") {
      return;
    }
    if (result.kind === "fail") {
      await failJob(job, result.reason, deps.gateway);
      return;
    }

    try {
      await deps.gateway.complete(job.jobId, {
        fencingToken: job.fencingToken,
        resultCiphertext: result.response.resultCiphertext,
        resultHash: result.response.resultHash,
        resultSize: result.response.resultSize,
      });
    } catch (error) {
      if (error instanceof LeaseLostError) {
        return;
      }

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
  let leaseLost = false;
  let pending = Promise.resolve();
  const intervalMs =
    (deps.leaseSeconds * MILLISECONDS_PER_SECOND) / HEARTBEAT_DIVISOR;
  const timer = setInterval(() => {
    pending = pending.then(async () => {
      if (leaseLost) {
        return;
      }

      try {
        await deps.gateway.heartbeat(job.jobId, {
          fencingToken: job.fencingToken,
          leaseSeconds: deps.leaseSeconds,
        });
      } catch (error) {
        if (error instanceof LeaseLostError) {
          leaseLost = true;
          controller.abort();
        }
      }
    });
  }, intervalMs);
  timer.unref();

  return {
    signal: controller.signal,
    lost: () => leaseLost,
    settled: () => pending,
    stop(): void {
      clearInterval(timer);
    },
  };
}

async function decryptRequest(
  job: ClaimedJob,
  identity: ClaimedIdentity,
  client: DstackClient,
): Promise<JobRequestEnvelope | undefined> {
  const derived = await deriveEnclaveKey(
    client,
    identity.userPsId,
    identity.epoch,
  );

  try {
    if (getAddress(derived.address) !== getAddress(identity.enclaveAddress)) {
      return undefined;
    }

    return await openJobRequest(
      job.requestCiphertext,
      derived.key,
      DECRYPT_ONLY_ECIES,
    );
  } catch (error) {
    if (error instanceof JobEnvelopeError) {
      return undefined;
    }
    return undefined;
  } finally {
    derived.key.fill(0);
  }
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
): SandboxSpec {
  return {
    userPsId: identity.userPsId,
    epoch: identity.epoch,
    image: deps.image,
    env: {
      VANA_MASTER_KEY_SIGNATURE: toHex(signature),
      PS_ACCESS_TOKEN: accessToken,
      PS_SERVER_ADDRESS: identity.enclaveAddress,
      PS_SERVER_PUBLIC_KEY: identity.enclavePublicKey,
      SYNC_ENABLED: deps.sync === "enabled" ? SYNC_ENABLED : SYNC_DISABLED,
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

async function executeSandbox(options: ExecuteOptions): Promise<ExecuteResult> {
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
    typeof value.resultCiphertext === "string" &&
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
    return decryptEcies(
      privateKey,
      Buffer.concat([
        encrypted.iv,
        encrypted.ephemPublicKey,
        encrypted.ciphertext,
        encrypted.mac,
      ]),
    );
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
