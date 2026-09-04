import { createServer, type Server } from "node:http";
import { NodeECIESProvider } from "@opendatalabs/vana-sdk/node";
import { sealJobRequest } from "@opendatalabs/vana-sdk/crypto/envelope/job";
import { vi } from "vitest";
import type { Address, Hex } from "viem";
import { createFakeDstackClient } from "../dstack/fake.js";
import type { DstackClient } from "../dstack/client.js";
import { WALLET_PURPOSE, type UserPsId } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import {
  createDockerRuntime,
  type DockerClient,
} from "../sandbox/docker-runtime.js";
import { createSandboxRegistry } from "../sandbox/registry.js";
import {
  assertSandboxEnv,
  type SandboxHandle,
  type SandboxRuntime,
  type SandboxSpec,
} from "../sandbox/runtime.js";
import { seal } from "../sealing/envelope.js";
import { LeaseLostError, type GatewayClient } from "./gateway-client.js";
import { runJob, type RunJobDeps } from "./run.js";
import type {
  ClaimResponse,
  JobExecuteError,
  JobExecuteResponse,
  JobRequestEnvelope,
} from "./types.js";

const APP_ID = "11".repeat(20);
const USER_PS_ID = `0x${"22".repeat(32)}` as UserPsId;
const OWNER = `0x${"33".repeat(20)}` as Address;
const BUILDER = `0x${"44".repeat(20)}` as Address;
const GRANT_ID = `0x${"55".repeat(32)}` as Hex;
const EPOCH = 2;
const NOW_MS = Date.parse("2026-09-03T12:00:00.000Z");
const DEADLINE = "2026-09-03T12:05:00.000Z";
const JOB_ID = "job-1";
const CHAIN_ID = 14_800;
const AGENT_URL = "http://agent:8787";
const TAMPER_BIT = 1;
const RESULT = {
  resultObjectKey: `jobresults/${CHAIN_ID}/${JOB_ID}`,
  resultHash: `0x${"66".repeat(32)}`,
  resultSize: 10,
} satisfies JobExecuteResponse;

interface Fixture {
  client: DstackClient;
  deps: RunJobDeps;
  gateway: GatewayClient;
  identity: ClaimResponse["identity"];
  job: ClaimResponse["job"];
  request: JobRequestEnvelope;
  runtime: MemoryRuntime;
  keyFill: ReturnType<typeof vi.fn>;
}

class MemoryRuntime implements SandboxRuntime {
  specs: SandboxSpec[] = [];

  constructor(private readonly origin: string) {}

  async reconcile(): Promise<void> {}

  async start(spec: SandboxSpec): Promise<SandboxHandle> {
    this.specs.push(spec);

    return { id: "sandbox-1", origin: this.origin };
  }

  async stop(): Promise<void> {}

  async inspect(): Promise<{ running: boolean }> {
    return { running: true };
  }
}

let sandboxServer: Server;
let sandboxOrigin: string;
let sandboxResponse: JobExecuteResponse | JobExecuteError = RESULT;
let sandboxStatus = 200;

beforeEach(async () => {
  sandboxResponse = RESULT;
  sandboxStatus = 200;
  sandboxServer = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) {
      chunks.push(Buffer.from(chunk));
    }

    expect(request.url).toBe("/enclave/v1/jobs/execute");
    expect(request.headers.authorization).toMatch(/^Bearer [0-9a-f]{64}$/);
    expect(JSON.parse(Buffer.concat(chunks).toString("utf8"))).toMatchObject({
      request: { jobId: JOB_ID },
    });
    response.statusCode = sandboxStatus;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify(sandboxResponse));
  });
  await new Promise<void>((resolve) =>
    sandboxServer.listen(0, "127.0.0.1", resolve),
  );
  const address = sandboxServer.address();
  if (!address || typeof address === "string") {
    throw new Error("Sandbox test server did not bind");
  }
  sandboxOrigin = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  vi.useRealTimers();
  await new Promise<void>((resolve, reject) => {
    sandboxServer.close((error) => (error ? reject(error) : resolve()));
  });
});

async function createFixture(): Promise<Fixture> {
  const baseClient = createFakeDstackClient({ appId: APP_ID });
  const identityInfo = await deriveEnclaveIdentity(
    baseClient,
    USER_PS_ID,
    EPOCH,
  );
  const sealedEnvelope = await seal(
    baseClient,
    USER_PS_ID,
    EPOCH,
    new Uint8Array(65).fill(7),
  );
  const request: JobRequestEnvelope = {
    request: {
      v: 1,
      jobId: JOB_ID,
      owner: OWNER,
      builder: BUILDER,
      builderPublicKey: identityInfo.publicKey,
      grantId: GRANT_ID,
      scope: "profile.email",
      operation: "raw_read",
      pinnedVersion: null,
      deadline: DEADLINE,
    },
    auth: "Web3Signed test.signature",
  };
  const requestCiphertext = await sealJobRequest(
    request,
    identityInfo.publicKey,
    new NodeECIESProvider(),
  );
  const job: ClaimResponse["job"] = {
    jobId: JOB_ID,
    chainId: CHAIN_ID,
    owner: OWNER,
    builder: BUILDER,
    grantId: GRANT_ID,
    scope: request.request.scope,
    operation: "raw_read",
    pinnedVersion: null,
    requestCiphertext,
    attempt: 1,
    deadlineAt: DEADLINE,
    claimExpiresAt: DEADLINE,
    fencingToken: 1,
  };
  const identity: ClaimResponse["identity"] = {
    userPsId: USER_PS_ID,
    epoch: EPOCH,
    enclaveAddress: identityInfo.address,
    enclavePublicKey: identityInfo.publicKey,
    sealedEnvelope,
  };
  const gateway = gatewayFake();
  const runtime = new MemoryRuntime(sandboxOrigin);
  const registry = createSandboxRegistry({
    runtime,
    idleTtlMs: 60_000,
  });
  const keyFill = vi.fn();
  const client: DstackClient = {
    ...baseClient,
    async deriveKey(path, purpose) {
      const derived = await baseClient.deriveKey(path, purpose);
      if (purpose === WALLET_PURPOSE) {
        const originalFill = derived.key.fill.bind(derived.key);
        derived.key.fill = ((value: number) => {
          keyFill(value);

          return originalFill(value);
        }) as Uint8Array["fill"];
      }

      return derived;
    },
  };
  const deps: RunJobDeps = {
    client,
    gateway,
    registry,
    image: "personal-server:test",
    gatewayUrl: "https://gateway.example",
    agentUrl: AGENT_URL,
    chainId: CHAIN_ID,
    contracts: {
      dataRegistry: "0x1111111111111111111111111111111111111111",
      dataPortabilityServer: "0x2222222222222222222222222222222222222222",
      dataPortabilityGrantees: "0x3333333333333333333333333333333333333333",
      dataPortabilityPermissions: "0x4444444444444444444444444444444444444444",
    },
    gatewayBypassSecret: "preview-secret",
    leaseSeconds: 30,
    sync: "disabled",
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => NOW_MS,
  };

  return {
    client,
    deps,
    gateway,
    identity,
    job,
    request,
    runtime,
    keyFill,
  };
}

async function waitForExecute(
  fetchMock: typeof fetch | undefined,
): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    if (vi.mocked(fetchMock!).mock.calls.length > 0) {
      return;
    }

    await vi.advanceTimersByTimeAsync(0);
  }

  throw new Error("Sandbox execution did not start");
}

function gatewayFake(): GatewayClient {
  return {
    claim: vi.fn(),
    heartbeat: vi.fn().mockResolvedValue(fencedResponse()),
    complete: vi.fn().mockResolvedValue(fencedResponse()),
    fail: vi.fn().mockResolvedValue(fencedResponse()),
    nodeHeartbeat: vi.fn(),
  };
}

function fencedResponse(claimExpiresAt = DEADLINE) {
  return {
    success: true as const,
    jobId: JOB_ID,
    state: "running" as const,
    claimExpiresAt,
  };
}

function jobError(code: string, retryable: boolean): JobExecuteError {
  return {
    error: {
      code: code as JobExecuteError["error"]["code"],
      message: "fixed error",
      retryable,
    },
  };
}

describe("runJob", () => {
  it("runs a claim with a matching chain id", async () => {
    const fixture = await createFixture();

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.complete).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      ...RESULT,
    });
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.runtime.specs[0]).toMatchObject({
      userPsId: USER_PS_ID,
      epoch: EPOCH,
      image: "personal-server:test",
      env: {
        VANA_MASTER_KEY_SIGNATURE: `0x${"07".repeat(65)}`,
        PS_SERVER_ADDRESS: fixture.identity.enclaveAddress,
        PS_SERVER_PUBLIC_KEY: fixture.identity.enclavePublicKey,
        SYNC_ENABLED: "false",
        GATEWAY_URL: "https://gateway.example",
        ENCLAVE_AGENT_URL: AGENT_URL,
        CHAIN_ID: String(CHAIN_ID),
        DATA_REGISTRY_CONTRACT: "0x1111111111111111111111111111111111111111",
        DATA_PORTABILITY_SERVER_CONTRACT:
          "0x2222222222222222222222222222222222222222",
        DATA_PORTABILITY_GRANTEES_CONTRACT:
          "0x3333333333333333333333333333333333333333",
        DATA_PORTABILITY_PERMISSIONS_CONTRACT:
          "0x4444444444444444444444444444444444444444",
        VERCEL_PROTECTION_BYPASS: "preview-secret",
      },
    });
    expect(fixture.runtime.specs[0]?.env.PS_ACCESS_TOKEN).toMatch(
      /^[0-9a-f]{64}$/,
    );
    expect(Object.keys(fixture.runtime.specs[0]?.env ?? {}).sort()).toEqual(
      [
        "PS_ACCESS_TOKEN",
        "PS_SERVER_ADDRESS",
        "PS_SERVER_PUBLIC_KEY",
        "SYNC_ENABLED",
        "VANA_MASTER_KEY_SIGNATURE",
        "VERCEL_PROTECTION_BYPASS",
        "GATEWAY_URL",
        "ENCLAVE_AGENT_URL",
        "CHAIN_ID",
        "DATA_REGISTRY_CONTRACT",
        "DATA_PORTABILITY_SERVER_CONTRACT",
        "DATA_PORTABILITY_GRANTEES_CONTRACT",
        "DATA_PORTABILITY_PERMISSIONS_CONTRACT",
      ].sort(),
    );
    expect(fixture.runtime.specs[0]?.env.STORAGE_API_URL).toBeUndefined();
    expect(fixture.keyFill).toHaveBeenCalledWith(0);
  });

  it("defers a completion failure to lease recovery", async () => {
    const fixture = await createFixture();
    const completionError = new Error("complete unavailable");
    vi.mocked(fixture.gateway.complete).mockRejectedValue(completionError);
    const release = vi.spyOn(fixture.deps.registry, "release");

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.complete).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      ...RESULT,
    });
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(release).toHaveBeenCalledWith(`${USER_PS_ID}:${EPOCH}`);
    expect(fixture.deps.logger.warn).toHaveBeenCalledWith(
      {
        jobId: JOB_ID,
        stage: "complete",
        error: { name: "Error", message: "complete unavailable" },
        causes: [],
      },
      "Enclave job stage failed",
    );
  });

  it("uses the configured chain when the claim omits chainId", async () => {
    const fixture = await createFixture();
    delete fixture.job.chainId;

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.complete).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      ...RESULT,
    });
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.runtime.specs[0]?.env.CHAIN_ID).toBe(String(CHAIN_ID));
  });

  it("fails a Gateway job for a different sandbox chain", async () => {
    const fixture = await createFixture();
    fixture.job.chainId = 14_801;

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      reason: "CHAIN_MISMATCH",
    });
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
    expect(fixture.runtime.specs).toHaveLength(0);
    expect(fixture.deps.logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({
        jobId: JOB_ID,
        error: expect.objectContaining({ name: "SandboxChainMismatchError" }),
      }),
      "Enclave job stage failed",
    );
  });

  it("forwards the configured storage API URL to the sandbox", async () => {
    const fixture = await createFixture();
    fixture.deps.storageApiUrl = "https://storage-dev.vana.org";

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.runtime.specs[0]?.env.STORAGE_API_URL).toBe(
      "https://storage-dev.vana.org",
    );
    expect(() =>
      assertSandboxEnv(fixture.runtime.specs[0]?.env ?? {}),
    ).not.toThrow();
  });

  it("awaits the configured work delay on the docker runtime path", async () => {
    const fixture = await createFixture();
    const sandboxPort = Number(new URL(sandboxOrigin).port);
    const docker: DockerClient = {
      run: vi.fn(async (command) =>
        command === "create" ? "container-id" : "",
      ),
      inspect: vi.fn().mockResolvedValue({
        running: true,
        hostPort: sandboxPort,
      }),
    };
    const runtime = createDockerRuntime({
      docker,
      runtimeHost: "127.0.0.1",
      health: async () => true,
    });
    fixture.deps.registry = createSandboxRegistry({ runtime });
    fixture.deps.workDelayMs = 120_000;
    let finishDelay: (() => void) | undefined;
    fixture.deps.sleep = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          finishDelay = resolve;
        }),
    );
    fixture.deps.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(RESULT), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await vi.waitFor(() =>
      expect(fixture.deps.sleep).toHaveBeenCalledWith(120_000),
    );

    expect(fixture.deps.fetch).not.toHaveBeenCalled();
    finishDelay?.();
    await running;
    expect(fixture.deps.fetch).toHaveBeenCalledOnce();
    expect(docker.run).toHaveBeenCalledWith(
      "create",
      expect.any(Array),
      undefined,
      expect.objectContaining({
        VANA_MASTER_KEY_SIGNATURE: expect.any(String),
        PS_ACCESS_TOKEN: expect.any(String),
        VERCEL_PROTECTION_BYPASS: "preview-secret",
      }),
    );
  });

  it("fails a request whose inner binding does not match the claim", async () => {
    const fixture = await createFixture();
    fixture.job.scope = "profile.other";

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      reason: "REQUEST_INVALID",
    });
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("lets the lease lapse when the derived node identity mismatches", async () => {
    const fixture = await createFixture();
    fixture.identity.enclaveAddress = OWNER;

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
    expect(fixture.deps.logger.warn).toHaveBeenCalledOnce();
  });

  it("logs sandbox acquisition errors with their bounded cause chain", async () => {
    const fixture = await createFixture();
    const dockerError = new Error("docker create exited with code 125");
    const runtimeError = new Error("sandbox runtime failed", {
      cause: dockerError,
    });
    dockerError.cause = runtimeError;
    vi.spyOn(fixture.runtime, "start").mockRejectedValue(runtimeError);

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.deps.logger.warn).toHaveBeenCalledWith(
      {
        jobId: JOB_ID,
        stage: "sandbox-acquire",
        error: { name: "Error", message: "sandbox runtime failed" },
        causes: [
          { name: "Error", message: "docker create exited with code 125" },
        ],
      },
      "Enclave job stage failed",
    );
  });

  it("fails a request with invalid ciphertext", async () => {
    const fixture = await createFixture();
    const ciphertext = Buffer.from(fixture.job.requestCiphertext, "base64");
    ciphertext[ciphertext.length - 1] ^= TAMPER_BIT;
    fixture.job.requestCiphertext = ciphertext.toString("base64");

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      reason: "REQUEST_INVALID",
    });
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("fails a non-retryable sandbox error with its code", async () => {
    sandboxStatus = 403;
    sandboxResponse = jobError("GRANT_REVOKED", false);
    const fixture = await createFixture();

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      reason: "GRANT_REVOKED",
    });
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("lets the lease lapse after a retryable sandbox error", async () => {
    sandboxStatus = 409;
    sandboxResponse = jobError("VERSION_MISMATCH", true);
    const fixture = await createFixture();

    await runJob(fixture.job, fixture.identity, fixture.deps);

    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("heartbeats every lease third while execution is pending", async () => {
    vi.useFakeTimers();
    const fixture = await createFixture();
    let resolveFetch: ((response: Response) => void) | undefined;
    fixture.deps.fetch = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          resolveFetch = resolve;
        }),
    ) as typeof fetch;
    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await waitForExecute(fixture.deps.fetch);

    await vi.advanceTimersByTimeAsync(9_999);
    expect(fixture.gateway.heartbeat).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(fixture.gateway.heartbeat).toHaveBeenCalledWith(JOB_ID, {
      fencingToken: 1,
      leaseSeconds: 30,
    });

    resolveFetch?.(
      new Response(JSON.stringify(jobError("VERSION_MISMATCH", true)), {
        status: 409,
      }),
    );
    await running;
  });

  it("aborts silently when a heartbeat loses the lease", async () => {
    vi.useFakeTimers();
    const fixture = await createFixture();
    vi.mocked(fixture.gateway.heartbeat).mockRejectedValue(
      new LeaseLostError(),
    );
    fixture.deps.fetch = vi.fn((_input, init) => {
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new Error("abort")),
        );
      });
    }) as typeof fetch;
    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await waitForExecute(fixture.deps.fetch);

    await vi.advanceTimersByTimeAsync(10_000);
    await running;

    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("aborts after heartbeat failures pass the confirmed lease deadline", async () => {
    vi.useFakeTimers();
    const fixture = await createFixture();
    let currentTime = NOW_MS;
    let resolveFetch: ((response: Response) => void) | undefined;
    const aborted = vi.fn();
    fixture.job.claimExpiresAt = new Date(NOW_MS + 15_000).toISOString();
    fixture.deps.now = () => currentTime;
    vi.mocked(fixture.gateway.heartbeat).mockRejectedValue(
      new Error("gateway unavailable"),
    );
    fixture.deps.fetch = vi.fn((_input, init) => {
      return new Promise<Response>((resolve, reject) => {
        resolveFetch = resolve;
        init?.signal?.addEventListener("abort", () => {
          aborted();
          reject(new Error("abort"));
        });
      });
    }) as typeof fetch;
    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await waitForExecute(fixture.deps.fetch);

    currentTime += 10_000;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(aborted).not.toHaveBeenCalled();

    currentTime += 10_000;
    await vi.advanceTimersByTimeAsync(10_000);
    resolveFetch?.(
      new Response(JSON.stringify(jobError("VERSION_MISMATCH", true)), {
        status: 409,
      }),
    );
    await running;

    expect(aborted).toHaveBeenCalledOnce();
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("aborts at the lease deadline while a heartbeat is still pending", async () => {
    vi.useFakeTimers();
    const fixture = await createFixture();
    let currentTime = NOW_MS;
    let rejectHeartbeat: ((error: Error) => void) | undefined;
    let resolveFetch: ((response: Response) => void) | undefined;
    const aborted = vi.fn();
    fixture.job.claimExpiresAt = new Date(NOW_MS + 15_000).toISOString();
    fixture.deps.now = () => currentTime;
    vi.mocked(fixture.gateway.heartbeat).mockImplementation(
      () =>
        new Promise((_resolve, reject) => {
          rejectHeartbeat = reject;
        }),
    );
    fixture.deps.fetch = vi.fn((_input, init) => {
      return new Promise<Response>((resolve, reject) => {
        resolveFetch = resolve;
        init?.signal?.addEventListener("abort", () => {
          aborted();
          reject(new Error("abort"));
        });
      });
    }) as typeof fetch;
    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await waitForExecute(fixture.deps.fetch);

    currentTime += 15_000;
    await vi.advanceTimersByTimeAsync(15_000);
    const abortsAtDeadline = aborted.mock.calls.length;

    rejectHeartbeat?.(new Error("heartbeat timeout"));
    resolveFetch?.(
      new Response(JSON.stringify(jobError("VERSION_MISMATCH", true)), {
        status: 409,
      }),
    );
    await running;

    expect(abortsAtDeadline).toBe(1);
    expect(fixture.deps.logger.warn).toHaveBeenCalledOnce();
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });

  it("uses a later successful heartbeat to extend the lease deadline", async () => {
    vi.useFakeTimers();
    const fixture = await createFixture();
    let currentTime = NOW_MS;
    let resolveFetch: ((response: Response) => void) | undefined;
    const aborted = vi.fn();
    fixture.job.claimExpiresAt = new Date(NOW_MS + 25_000).toISOString();
    fixture.deps.now = () => currentTime;
    vi.mocked(fixture.gateway.heartbeat)
      .mockRejectedValueOnce(new Error("gateway unavailable"))
      .mockResolvedValueOnce(
        fencedResponse(new Date(NOW_MS + 50_000).toISOString()),
      );
    fixture.deps.fetch = vi.fn((_input, init) => {
      return new Promise<Response>((resolve, reject) => {
        resolveFetch = resolve;
        init?.signal?.addEventListener("abort", () => {
          aborted();
          reject(new Error("abort"));
        });
      });
    }) as typeof fetch;
    const running = runJob(fixture.job, fixture.identity, fixture.deps);
    await waitForExecute(fixture.deps.fetch);

    currentTime += 10_000;
    await vi.advanceTimersByTimeAsync(10_000);
    currentTime += 10_000;
    await vi.advanceTimersByTimeAsync(10_000);
    currentTime += 5_000;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(aborted).not.toHaveBeenCalled();

    resolveFetch?.(
      new Response(JSON.stringify(jobError("VERSION_MISMATCH", true)), {
        status: 409,
      }),
    );
    await running;

    expect(fixture.gateway.heartbeat).toHaveBeenCalledTimes(2);
    expect(fixture.gateway.fail).not.toHaveBeenCalled();
    expect(fixture.gateway.complete).not.toHaveBeenCalled();
  });
});
