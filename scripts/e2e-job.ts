import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { access, mkdtemp, rm, unlink } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  BUILDER_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  MASTER_KEY_MESSAGE,
  NodeECIESProvider,
  PERSONAL_SERVER_REGISTRATION_DEFAULT_VERIFYING_CONTRACT,
  buildPersonalServerRegistrationTypedData,
  buildWeb3SignedHeader,
  builderRegistrationDomain,
  createGatewayClient,
  grantRegistrationDomain,
  grantRevocationDomain,
  type Builder,
  type DataPortabilityGatewayConfig,
  type GatewayClient,
  type GatewayGrantResponse,
  type ServerInfo,
} from "@opendatalabs/vana-sdk/node";
import {
  canonicalJobRequestBytes,
  openJobResult,
  sealJobRequest,
} from "@opendatalabs/vana-sdk/crypto/envelope/job";
import type {
  JobRequest,
  JobStatus,
  JobSubmission,
} from "@opendatalabs/vana-sdk/protocol/jobs";
import {
  buildMasterSignatureDelivery,
  encryptMasterSignatureDelivery,
  userPsId,
  verifyEnclaveIdentityEvidence,
  type IdentityResponse,
  type SealedSecretSubmission,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { getAddress, isHex, type Hex } from "viem";
import {
  generatePrivateKey,
  privateKeyToAccount,
  type PrivateKeyAccount,
} from "viem/accounts";
import type { ServerAccount } from "../packages/core/src/keys/server-account.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import { createFakeDstackClient } from "../packages/enclave/src/dstack/fake.js";
import { createServer } from "../packages/server/src/bootstrap.js";
import { saveConfig } from "../packages/server/src/config/index.js";
import {
  StepFailure,
  hasStepFailures,
  printSummary,
  record,
  requestJson,
  requireResponse,
  runStep,
  type HttpResult,
} from "./e2e-lib.js";
import {
  DEFAULT_FAKE_APP_ID,
  fakeGatewayAnchors,
} from "./print-fake-anchors.js";

const DEFAULT_GATEWAY_URL = "http://127.0.0.1:3000";
const DEFAULT_CHAIN_ID = 14_800;
const DEFAULT_AGENT_SECRET = "dev-agent-secret";
const DEFAULT_AGENT_PORT = 8787;
const SEED_SERVER_PORT = 8080;
const AGENT_HOST = "127.0.0.1";
const JOB_SCOPE = "e2e.jobs.v1";
const JOB_EXECUTE_PATH = "/v1/jobs/execute";
const JOBS_PATH = "/v1/jobs";
const RAW_READ = "raw_read";
const LEASE_SECONDS = 30;
const SANDBOX_CAPACITY = 20;
const JOB_WAIT_SECONDS = 25;
const JOB_DEADLINE_MS = 600_000;
const AGENT_READY_TIMEOUT_MS = 15_000;
const HEARTBEAT_TIMEOUT_MS = 30_000;
const JOB_TIMEOUT_MS = 60_000;
const RECOVERY_TIMEOUT_MS = 90_000;
const REMOTE_RECOVERY_TIMEOUT_MS = 300_000;
const REMOTE_CLAIM_TIMEOUT_MS = 15_000;
const REMOTE_SEED_TIMEOUT_MS = 120_000;
const REMOTE_HEARTBEAT_MAX_AGE_MS = 60_000;
const MAX_RECOVERY_SUBMISSIONS = 8;
const POLL_INTERVAL_MS = 1_000;
const LEASE_KILL_DELAY_MS = 5_000;
const LEASE_WORK_DELAY_MS = 120_000;
const FORCE_KILL_SIGNAL = "SIGKILL";
const KEEP_ROOT = "1";
const NODE_SECRET_BYTES = 32;
const FIRST_EPOCH = 1;
const MIN_POSITIVE_INTEGER = 1;
const AUTO_PORT = 0;
const AGENT_START_POLL_MS = 100;
const NO_WAIT_SECONDS = 0;
const HTTP_OK = 200;
const HTTP_CREATED = 201;
const HTTP_ACCEPTED = 202;
const HTTP_FORBIDDEN = 403;
const HTTP_NOT_FOUND = 404;
const EXIT_SUCCESS = 0;
const EXIT_FAILURE = 1;
const TRUE_VALUE = "1";
const REMOTE_ENABLED = "1";
const GRANT_VERSION_ONE = 1n;
const GRANT_VERSION_REVOKED = 2n;
const GRANT_VERSION_FRESH = 3n;
const NO_EXPIRY = 0n;
const JSON_CONTENT_TYPE = "application/json";
const FAKE_IMAGE = "unused-in-level-a";
const OWNER_RECORD = { hello: "jobs", n: 1 } as const;
const DECRYPT_FAILURE_REASON = "REQUEST_INVALID";
const SHA256 = "sha256";
const JOB_FAILURE_CODES = new Set(["AUTH_INVALID", "BUILDER_MISMATCH"]);

interface AgentProcess {
  child: ChildProcess;
  nodeId?: string;
  nodeSecret?: string;
  origin: string;
}

interface TeeNodeInfo {
  appId: Hex;
  composeHash: Hex;
  instanceId: string;
}

interface JobContext {
  gatewayUrl: string;
  operatorSecret: string;
  chainId: number;
  gatewayConfig: DataPortabilityGatewayConfig;
  fakeRoot: string;
  agentSecret: string;
  owner: PrivateKeyAccount;
  ownerSignature: Hex;
  userPsId: Hex;
  ecies: NodeECIESProvider;
  remote: boolean;
  remoteNodeIds: string[];
  warmRuns: number;
  recovery: boolean;
}

interface RegisteredBuilder {
  account: PrivateKeyAccount;
  id: Hex;
  privateKey: Hex;
}

interface JobEnvelopeOptions {
  ctx: JobContext;
  identity: IdentityResponse["identity"];
  builder: PrivateKeyAccount;
  grantId: Hex;
  authSigner?: PrivateKeyAccount;
  encryptionKey?: Hex;
}

interface CreatedJob {
  request: JobRequest;
  submission: JobSubmission;
}

const agents: AgentProcess[] = [];
const nodeIds: string[] = [];
let cleanupStarted = false;
let rootToRemove: string | undefined;
let cleanupContext:
  { gatewayUrl: string; operatorSecret: string; fakeRoot: string } | undefined;
let originalFetch: typeof fetch | undefined;

function positiveInt(raw: string | undefined, fallback: number): number {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < MIN_POSITIVE_INTEGER) {
    throw new Error(`Expected a positive integer, received ${raw ?? value}`);
  }

  return value;
}

function nonnegativeInt(raw: string | undefined, fallback: number): number {
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(
      `Expected a non-negative integer, received ${raw ?? value}`,
    );
  }

  return value;
}

function hexKey(raw: string | undefined): Hex {
  const key = (raw ?? generatePrivateKey()) as Hex;
  if (!isHex(key) || key.length !== 66) {
    throw new Error("OWNER_PRIVATE_KEY must be a 32-byte 0x-prefixed hex key");
  }

  return key;
}

async function buildContext(): Promise<JobContext> {
  const gatewayUrl = (process.env.GATEWAY_URL ?? DEFAULT_GATEWAY_URL).replace(
    /\/+$/,
    "",
  );
  installGatewayBypass(gatewayUrl, process.env.VERCEL_PROTECTION_BYPASS);
  const remote = process.env.E2E_REMOTE === REMOTE_ENABLED;
  const remoteNodeIds = (process.env.E2E_NODE_IDS ?? "")
    .split(",")
    .map((nodeId) => nodeId.trim())
    .filter(Boolean);
  if (remote && remoteNodeIds.length === 0) {
    throw new Error("E2E_NODE_IDS is required when E2E_REMOTE=1");
  }
  const operatorSecret = process.env.OPERATOR_SECRET ?? process.env.CRON_SECRET;
  if (!operatorSecret) {
    throw new Error("OPERATOR_SECRET or CRON_SECRET is required");
  }
  const chainId = positiveInt(process.env.CHAIN_ID, DEFAULT_CHAIN_ID);
  const fakeRoot = remote
    ? ""
    : (process.env.SANDBOX_FAKE_ROOT ??
      (await mkdtemp(join(tmpdir(), "vana-job-e2e-"))));
  rootToRemove = remote ? undefined : fakeRoot;
  const owner = privateKeyToAccount(hexKey(process.env.OWNER_PRIVATE_KEY));
  const ownerSignature = await owner.signMessage({
    message: MASTER_KEY_MESSAGE,
  });
  const gatewayConfig = gatewayConfigFor(chainId);

  return {
    gatewayUrl,
    operatorSecret,
    chainId,
    gatewayConfig,
    fakeRoot,
    agentSecret: process.env.E2E_AGENT_SECRET ?? DEFAULT_AGENT_SECRET,
    owner,
    ownerSignature,
    userPsId: userPsId(chainId, owner.address),
    ecies: new NodeECIESProvider(),
    remote,
    remoteNodeIds,
    warmRuns: nonnegativeInt(process.env.E2E_WARM_RUNS, 0),
    recovery: process.env.E2E_RECOVERY === TRUE_VALUE,
  };
}

function installGatewayBypass(
  gatewayUrl: string,
  secret: string | undefined,
): void {
  if (!secret || originalFetch) return;
  const gatewayOrigin = new URL(gatewayUrl).origin;
  originalFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const requestUrl = new URL(
      input instanceof Request ? input.url : input.toString(),
    );
    if (requestUrl.origin !== gatewayOrigin) {
      return originalFetch!(input, init);
    }
    const headers = new Headers(
      input instanceof Request ? input.headers : undefined,
    );
    new Headers(init?.headers).forEach((value, key) => headers.set(key, value));
    headers.set("x-vercel-protection-bypass", secret);

    return originalFetch!(input, { ...init, headers });
  };
}

// These four env overrides mirror data-gateway's contract configuration. Its
// `.env.example` uses a Moksha DataRegistry unlike the SDK's baked default:
// https://github.com/vana-com/data-gateway/blob/main/.env.example
function gatewayConfigFor(chainId: number): DataPortabilityGatewayConfig {
  const defaults = ServerConfigSchema.parse({}).gateway.contracts;

  return {
    chainId,
    contracts: {
      ...defaults,
      dataRegistry:
        process.env.DATA_REGISTRY_CONTRACT ??
        "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
      dataPortabilityServer:
        process.env.DATA_PORTABILITY_SERVER_CONTRACT ??
        defaults.dataPortabilityServer,
      dataPortabilityGrantees:
        process.env.DATA_PORTABILITY_GRANTEES_CONTRACT ??
        defaults.dataPortabilityGrantees,
      dataPortabilityPermissions:
        process.env.DATA_PORTABILITY_PERMISSIONS_CONTRACT ??
        defaults.dataPortabilityPermissions,
    },
  } satisfies DataPortabilityGatewayConfig;
}

async function freePort(preferred?: number): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(preferred ?? AUTO_PORT, AGENT_HOST, () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Unable to allocate an agent port"));
        return;
      }
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolvePort(address.port);
      });
    });
  });
}

async function startAgent(
  ctx: JobContext,
  port: number,
  node?: { id: string; secret: string; workDelayMs?: number },
): Promise<AgentProcess> {
  const child = spawn(
    process.execPath,
    [resolve("packages/enclave/dist/agent/main.js")],
    {
      detached: true,
      env: {
        DSTACK_FAKE: TRUE_VALUE,
        DSTACK_FAKE_APP_ID: DEFAULT_FAKE_APP_ID.slice(2),
        ENCLAVE_AGENT_SECRET: ctx.agentSecret,
        ENCLAVE_AGENT_HOST: AGENT_HOST,
        ENCLAVE_AGENT_PORT: String(port),
        ...(node
          ? {
              GATEWAY_URL: ctx.gatewayUrl,
              NODE_ID: node.id,
              NODE_SECRET: node.secret,
              SANDBOX_RUNTIME: "fake",
              SANDBOX_SYNC: "disabled",
              SANDBOX_FAKE_ROOT: ctx.fakeRoot,
              PS_ENTRY: resolve("packages/server/dist/index.js"),
              PS_IMAGE: FAKE_IMAGE,
              LEASE_SECONDS: String(LEASE_SECONDS),
              ...(node.workDelayMs === undefined
                ? {}
                : { WORK_DELAY_MS: String(node.workDelayMs) }),
            }
          : {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const agent = {
    child,
    origin: `http://${AGENT_HOST}:${port}`,
    ...(node ? { nodeId: node.id, nodeSecret: node.secret } : {}),
  };
  agents.push(agent);
  forwardChild(child, node?.id ?? "identity-agent");
  await waitForAgent(agent, ctx.agentSecret);

  return agent;
}

function forwardChild(child: ChildProcess, label: string): void {
  const write = (chunk: string | Buffer): void => {
    process.stderr.write(`[${label}] ${chunk.toString()}`);
  };
  child.stdout?.on("data", write);
  child.stderr?.on("data", write);
}

async function waitForAgent(
  agent: AgentProcess,
  secret: string,
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + AGENT_READY_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (agent.child.exitCode !== null) {
      throw new Error("Fake enclave agent exited before becoming healthy");
    }
    try {
      const response = await fetch(`${agent.origin}/agent/v1/health`, {
        headers: { Authorization: `Bearer ${secret}` },
      });
      if (response.ok) {
        return record(await response.json()) ?? {};
      }
    } catch {
      // The listener is still starting.
    }
    await delay(AGENT_START_POLL_MS);
  }

  throw new Error(`Timed out waiting for ${agent.origin}/agent/v1/health`);
}

function stopAgent(agent: AgentProcess): void {
  const pid = agent.child.pid;
  if (!pid || agent.child.exitCode !== null) return;
  try {
    process.kill(-pid, FORCE_KILL_SIGNAL);
  } catch {
    // Best effort: the process may have exited between the check and kill.
  }
}

async function fakeNodeInfo(): Promise<TeeNodeInfo> {
  const info = await createFakeDstackClient({
    appId: DEFAULT_FAKE_APP_ID.slice(2),
  }).info();

  return {
    appId: prefixedHex(info.appId),
    composeHash: prefixedHex(info.composeHash),
    instanceId: info.instanceId,
  };
}

function prefixedHex(value: string): Hex {
  return (value.startsWith("0x") ? value : `0x${value}`) as Hex;
}

async function registerNode(
  ctx: JobContext,
  nodeId: string,
  secret: string,
  origin: string,
  info: TeeNodeInfo,
): Promise<void> {
  const result = await operatorRequest(ctx, "POST", "/v1/tee-nodes", {
    nodeId,
    appId: info.appId,
    composeHash: info.composeHash,
    publicUrl: origin,
    capacity: SANDBOX_CAPACITY,
    secret,
  });
  requireResponse(
    result,
    [HTTP_OK, HTTP_CREATED],
    (body) => record(body)?.state === "pending",
    "Expected a pending TEE node registration",
  );
  nodeIds.push(nodeId);
}

async function operatorRequest(
  ctx: Pick<JobContext, "gatewayUrl" | "operatorSecret">,
  method: string,
  path: string,
  body?: unknown,
): Promise<HttpResult> {
  return requestJson(
    method,
    `${ctx.gatewayUrl}${path}`,
    body,
    {
      Authorization: `Bearer ${ctx.operatorSecret}`,
    },
    "secrets",
  );
}

async function waitForHeartbeat(
  ctx: JobContext,
  nodeId: string,
): Promise<void> {
  const deadline = Date.now() + HEARTBEAT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const result = await operatorRequest(ctx, "GET", "/v1/tee-nodes");
    const nodes = Array.isArray(result.response.body)
      ? result.response.body
      : [];
    const node = nodes
      .map(record)
      .find((candidate) => candidate?.nodeId === nodeId);
    if (typeof node?.lastHeartbeatAt === "string") return;
    await delay(POLL_INTERVAL_MS);
  }

  throw new Error(`Timed out waiting for heartbeat from ${nodeId}`);
}

async function admitNode(ctx: JobContext, nodeId: string): Promise<void> {
  const result = await operatorRequest(
    ctx,
    "POST",
    `/v1/tee-nodes/${encodeURIComponent(nodeId)}/admit`,
  );
  requireResponse(
    result,
    HTTP_OK,
    (body) => record(body)?.state === "admitted",
    "Expected the TEE node to become admitted",
  );
}

async function verifyRemoteNodes(ctx: JobContext): Promise<string> {
  const result = await operatorRequest(ctx, "GET", "/v1/tee-nodes");
  const nodes = Array.isArray(result.response.body)
    ? result.response.body.map(record)
    : [];
  const now = Date.now();
  for (const nodeId of ctx.remoteNodeIds) {
    const node = nodes.find((candidate) => candidate?.nodeId === nodeId);
    const heartbeat =
      typeof node?.lastHeartbeatAt === "string"
        ? Date.parse(node.lastHeartbeatAt)
        : Number.NaN;
    if (
      node?.state !== "admitted" ||
      !Number.isFinite(heartbeat) ||
      now - heartbeat > REMOTE_HEARTBEAT_MAX_AGE_MS
    ) {
      throw new Error(
        `Remote node ${nodeId} is not admitted with a heartbeat from the last 60 seconds`,
      );
    }
  }

  return `nodeIds=${ctx.remoteNodeIds.join(",")}`;
}

async function registerBuilder(ctx: JobContext): Promise<RegisteredBuilder> {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const message = {
    ownerAddress: ctx.owner.address,
    granteeAddress: account.address,
    publicKey: account.publicKey,
    appUrl: "http://127.0.0.1/e2e-job-builder",
  };
  const signature = await ctx.owner.signTypedData({
    domain: builderRegistrationDomain(ctx.gatewayConfig),
    types: BUILDER_REGISTRATION_TYPES,
    primaryType: "BuilderRegistration",
    message,
  });
  const result = await requestJson(
    "POST",
    `${ctx.gatewayUrl}/v1/builders`,
    message,
    { Authorization: `Web3Signed ${signature}` },
  );
  const body = record(result.response.body);
  requireResponse(
    result,
    HTTP_CREATED,
    () => typeof body?.builderId === "string" && isHex(body.builderId),
    "Expected builder registration to return a builderId",
  );

  return { account, id: body!.builderId as Hex, privateKey };
}

async function createGrant(
  ctx: JobContext,
  builderId: Hex,
  version: bigint,
): Promise<Hex> {
  const message = {
    grantorAddress: ctx.owner.address,
    granteeId: builderId,
    scopes: [JOB_SCOPE],
    grantVersion: version,
    expiresAt: NO_EXPIRY,
  };
  const signature = await ctx.owner.signTypedData({
    domain: grantRegistrationDomain(ctx.gatewayConfig),
    types: GRANT_REGISTRATION_TYPES,
    primaryType: "GrantRegistration",
    message,
  });
  const body = {
    ...message,
    grantVersion: message.grantVersion.toString(),
    expiresAt: message.expiresAt.toString(),
  };
  const result = await requestJson(
    "POST",
    `${ctx.gatewayUrl}/v1/grants`,
    body,
    { Authorization: `Web3Signed ${signature}` },
  );
  const response = record(result.response.body);
  requireResponse(
    result,
    [HTTP_OK, HTTP_CREATED],
    () => typeof response?.grantId === "string" && isHex(response.grantId),
    "Expected grant registration to return a grantId",
  );

  return response!.grantId as Hex;
}

async function revokeGrant(ctx: JobContext, grantId: Hex): Promise<void> {
  const message = {
    grantorAddress: ctx.owner.address,
    grantId,
    grantVersion: GRANT_VERSION_REVOKED,
  };
  const signature = await ctx.owner.signTypedData({
    domain: grantRevocationDomain(ctx.gatewayConfig),
    types: GRANT_REVOCATION_TYPES,
    primaryType: "GrantRevocation",
    message,
  });
  const result = await requestJson(
    "DELETE",
    `${ctx.gatewayUrl}/v1/grants/${grantId}`,
    {
      grantorAddress: ctx.owner.address,
      grantVersion: message.grantVersion.toString(),
    },
    { Authorization: `Web3Signed ${signature}` },
  );
  requireResponse(
    result,
    HTTP_OK,
    (body) => record(body)?.success === true,
    "Expected the owner grant to be revoked",
  );
}

function seedGateway(): GatewayClient {
  const gateway = {
    isRegisteredBuilder: async () => false,
    getBuilder: async (): Promise<Builder | null> => null,
    getGrant: async (): Promise<GatewayGrantResponse | null> => null,
    listGrantsByUser: async () => [],
    getSchemaForScope: async () => null,
    getSchema: async () => null,
    getServer: async () => null,
    getFile: async () => null,
    listFilesSince: async () => ({ files: [], cursor: null }),
    registerServer: async () => ({ alreadyRegistered: true }),
    registerFile: async () => ({}),
    createGrant: async () => ({ grantId: `0x${"00".repeat(32)}` }),
    revokeGrant: async () => undefined,
  };

  return gateway as unknown as GatewayClient;
}

function sandboxRoot(ctx: JobContext): string {
  return join(ctx.fakeRoot, `${ctx.userPsId}-${FIRST_EPOCH}`);
}

async function seedRecord(ctx: JobContext): Promise<string | undefined> {
  if (ctx.remote) {
    return seedRemoteRecord(ctx);
  }

  const root = sandboxRoot(ctx);
  const origin = `http://${AGENT_HOST}:${SEED_SERVER_PORT}`;
  const config = ServerConfigSchema.parse({
    server: { port: SEED_SERVER_PORT, origin },
    gateway: { ...ctx.gatewayConfig, url: ctx.gatewayUrl },
    sync: { enabled: false },
    tunnel: { enabled: false },
    devUi: { enabled: false },
    logging: { level: "error" },
  });
  await saveConfig(config, { rootPath: root });
  const server = await createServer(config, {
    rootPath: root,
    ownerSignature: ctx.ownerSignature,
    gatewayClient: seedGateway(),
  });
  try {
    const rawBody = JSON.stringify(OWNER_RECORD);
    const authorization = await buildAuth(
      ctx.owner,
      origin,
      "POST",
      `/v1/data/${JOB_SCOPE}`,
      new TextEncoder().encode(rawBody),
    );
    const response = await server.app.request(
      `${origin}/v1/data/${JOB_SCOPE}`,
      {
        method: "POST",
        headers: {
          Authorization: authorization,
          "Content-Type": JSON_CONTENT_TYPE,
        },
        body: rawBody,
      },
    );
    if (response.status !== HTTP_CREATED) {
      throw new Error(`Record seed failed with status ${response.status}`);
    }
  } finally {
    await server.cleanup();
  }
  await unlink(join(root, "key.json"));

  return undefined;
}

async function seedRemoteRecord(ctx: JobContext): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "vana-job-seed-"));
  const origin = `http://${AGENT_HOST}:${SEED_SERVER_PORT}`;
  const config = ServerConfigSchema.parse({
    server: { port: SEED_SERVER_PORT, origin },
    gateway: { ...ctx.gatewayConfig, url: ctx.gatewayUrl },
    storage: { backend: "vana" },
    sync: { enabled: true },
    tunnel: { enabled: false },
    devUi: { enabled: false },
    logging: { level: "error" },
  });
  const serverAccount: ServerAccount = {
    address: ctx.owner.address,
    publicKey: ctx.owner.publicKey,
    signMessage: (message) => ctx.owner.signMessage({ message }),
    signTypedData: (params) => ctx.owner.signTypedData(params),
  };
  const gatewayClient = ownerSeedGateway(ctx, serverAccount);
  const server = await createServer(config, {
    rootPath: root,
    ownerSignature: ctx.ownerSignature,
    gatewayClient,
    serverAccount,
  });
  try {
    if (!server.syncManager) {
      throw new Error("Remote seed server did not start its sync manager");
    }
    const rawBody = JSON.stringify(OWNER_RECORD);
    const authorization = await buildAuth(
      ctx.owner,
      origin,
      "POST",
      `/v1/data/${JOB_SCOPE}`,
      new TextEncoder().encode(rawBody),
    );
    const response = await server.app.request(
      `${origin}/v1/data/${JOB_SCOPE}`,
      {
        method: "POST",
        headers: {
          Authorization: authorization,
          "Content-Type": JSON_CONTENT_TYPE,
        },
        body: rawBody,
      },
    );
    if (response.status !== HTTP_CREATED) {
      throw new Error(`Record seed failed with status ${response.status}`);
    }

    await server.startBackgroundServices();
    await server.syncManager.trigger();
    const deadline = Date.now() + REMOTE_SEED_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const status = server.syncManager.getStatus();
      if (status.errors.length > 0) {
        throw new Error(
          `Remote seed sync failed: ${JSON.stringify(status.errors)}`,
        );
      }
      const version = await remoteScopeVersion(ctx);
      if (status.pendingFiles === 0 && !status.syncing && version) {
        return version;
      }
      await delay(POLL_INTERVAL_MS);
    }

    const status = server.syncManager.getStatus();
    throw new Error(
      `Remote seed timed out: pending=${status.pendingFiles} syncing=${status.syncing} errors=${JSON.stringify(status.errors)}`,
    );
  } finally {
    await server.cleanup();
    await rm(root, { recursive: true, force: true });
  }
}

function ownerSeedGateway(
  ctx: JobContext,
  serverAccount: ServerAccount,
): GatewayClient {
  const gateway = createGatewayClient(ctx.gatewayUrl);
  const ownerServer: ServerInfo = {
    id: "owner-seed",
    ownerAddress: ctx.owner.address,
    serverAddress: serverAccount.address,
    publicKey: serverAccount.publicKey,
    serverUrl: "http://127.0.0.1/e2e-owner-seed",
    addedAt: new Date().toISOString(),
    revokedAt: null,
  };

  // This fixture signs as the owner, so uploads do not need a registered
  // Personal Server. Satisfy only the local sync gate; all network operations
  // still use the real SDK client.
  return new Proxy(gateway, {
    get(target, property, receiver) {
      if (property === "getServer") {
        return async () => ownerServer;
      }
      const value = Reflect.get(target, property, receiver) as unknown;

      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

async function remoteScopeVersion(
  ctx: JobContext,
): Promise<string | undefined> {
  const result = await requestJson(
    "GET",
    `${ctx.gatewayUrl}/v1/data?user=${encodeURIComponent(ctx.owner.address)}&limit=100`,
  );
  if (result.response.status !== HTTP_OK) return undefined;
  const rows = record(record(result.response.body)?.data)?.dataPoints;
  if (!Array.isArray(rows)) return undefined;
  const match = rows
    .map(record)
    .find((candidate) => candidate?.scope === JOB_SCOPE);
  const version = match?.expectedVersion;

  return typeof version === "string" || typeof version === "number"
    ? String(version)
    : undefined;
}

async function buildAuth(
  account: PrivateKeyAccount,
  aud: string,
  method: string,
  uri: string,
  body?: Uint8Array,
): Promise<string> {
  return buildWeb3SignedHeader({
    signMessage: (message) => account.signMessage({ message }),
    aud,
    method,
    uri,
    ...(body ? { body } : {}),
    nonce: randomUUID(),
  });
}

async function createJob(options: JobEnvelopeOptions): Promise<CreatedJob> {
  const jobId = randomUUID();
  const deadline = new Date(Date.now() + JOB_DEADLINE_MS).toISOString();
  const request: JobRequest = {
    v: FIRST_EPOCH,
    jobId,
    owner: options.ctx.owner.address,
    builder: options.builder.address,
    builderPublicKey: options.builder.publicKey,
    grantId: options.grantId,
    scope: JOB_SCOPE,
    operation: RAW_READ,
    pinnedVersion: null,
    deadline,
  };
  const authSigner = options.authSigner ?? options.builder;
  const bodyHash = `${SHA256}:${createHash(SHA256)
    .update(canonicalJobRequestBytes(request))
    .digest("hex")}`;
  const auth = await buildWeb3SignedHeader({
    signMessage: (message) => authSigner.signMessage({ message }),
    aud: options.ctx.gatewayUrl,
    method: "POST",
    uri: JOB_EXECUTE_PATH,
    bodyHash,
    nonce: randomUUID(),
  });
  const requestCiphertext = await sealJobRequest(
    { request, auth },
    options.encryptionKey ?? options.identity.publicKey,
    options.ctx.ecies,
  );

  return {
    request,
    submission: {
      owner: request.owner,
      grantId: request.grantId,
      scope: request.scope,
      operation: request.operation,
      idempotencyKey: randomUUID(),
      jobId,
      deadline,
      requestCiphertext,
    },
  };
}

async function submitJob(
  ctx: JobContext,
  builder: PrivateKeyAccount,
  job: CreatedJob,
  waitSeconds: number,
): Promise<HttpResult> {
  const bodyBytes = new TextEncoder().encode(JSON.stringify(job.submission));
  const authorization = await buildAuth(
    builder,
    ctx.gatewayUrl,
    "POST",
    JOBS_PATH,
    bodyBytes,
  );

  return requestJson(
    "POST",
    `${ctx.gatewayUrl}${JOBS_PATH}?wait=${waitSeconds}`,
    job.submission,
    { Authorization: authorization },
  );
}

function jobFromResult(result: HttpResult): JobStatus | undefined {
  const job = record(record(result.response.body)?.job);

  return job as JobStatus | undefined;
}

async function getJob(
  ctx: JobContext,
  builder: PrivateKeyAccount,
  jobId: string,
): Promise<HttpResult> {
  const path = `${JOBS_PATH}/${encodeURIComponent(jobId)}`;
  const authorization = await buildAuth(builder, ctx.gatewayUrl, "GET", path);

  return requestJson("GET", `${ctx.gatewayUrl}${path}`, undefined, {
    Authorization: authorization,
  });
}

async function pollJob(
  ctx: JobContext,
  builder: PrivateKeyAccount,
  jobId: string,
  timeoutMs: number,
): Promise<JobStatus> {
  const deadline = Date.now() + timeoutMs;
  let last: HttpResult | undefined;
  while (Date.now() < deadline) {
    last = await getJob(ctx, builder, jobId);
    const job = jobFromResult(last);
    if (
      job &&
      ["completed", "failed", "expired", "cancelled"].includes(job.state)
    ) {
      return job;
    }
    await delay(POLL_INTERVAL_MS);
  }

  throw new StepFailure(
    `Timed out waiting for terminal job ${jobId}`,
    last?.request ?? {
      method: "GET",
      url: `${ctx.gatewayUrl}${JOBS_PATH}/${jobId}`,
    },
    last?.response ?? { status: "TIMEOUT", body: null },
  );
}

async function assertResult(
  ctx: JobContext,
  builderKey: Hex,
  status: JobStatus,
  expectedVersion?: string,
): Promise<void> {
  if (!status.resultCiphertext) {
    throw new Error("Completed job did not include resultCiphertext");
  }
  const result = await openJobResult(
    status.resultCiphertext,
    builderKey,
    ctx.ecies,
    { jobId: status.jobId, scope: JOB_SCOPE },
  );
  if (typeof result.version !== "string") {
    throw new Error("Job result version was not a string");
  }
  if (expectedVersion && result.version !== String(expectedVersion)) {
    throw new Error(
      `Expected job result version ${expectedVersion}, received ${result.version}`,
    );
  }
  if (result.contentType !== JSON_CONTENT_TYPE) {
    throw new Error(`Unexpected result content type ${result.contentType}`);
  }
  const envelope = record(
    JSON.parse(Buffer.from(result.body, "base64").toString("utf8")),
  );
  const data = record(envelope?.data);
  if (data?.hello !== OWNER_RECORD.hello || data.n !== OWNER_RECORD.n) {
    throw new Error("Decrypted job result did not contain the seeded record");
  }
  if ("$writtenBy" in (data ?? {})) {
    throw new Error("Job result disclosed owner-only $writtenBy metadata");
  }
}

async function submitAndDecrypt(
  ctx: JobContext,
  identity: IdentityResponse["identity"],
  builder: RegisteredBuilder,
  grantId: Hex,
  expectedVersion: string | undefined,
): Promise<{ job: CreatedJob; submitMs: number }> {
  const job = await createJob({
    ctx,
    identity,
    builder: builder.account,
    grantId,
  });
  const submittedAt = performance.now();
  const result = await submitJob(ctx, builder.account, job, JOB_WAIT_SECONDS);
  const submitMs = Math.round(performance.now() - submittedAt);
  const status = jobFromResult(result);
  requireResponse(
    result,
    HTTP_OK,
    () => status?.state === "completed" && status.attempt === 1,
    "Expected the raw read job to complete inline on attempt 1",
  );
  await assertResult(ctx, builder.privateKey, status!, expectedVersion);

  return { job, submitMs };
}

async function recoverRemoteLease(
  ctx: JobContext,
  identity: IdentityResponse["identity"],
  builder: RegisteredBuilder,
  grantId: Hex,
  expectedVersion: string | undefined,
): Promise<string> {
  for (let attempt = 1; attempt <= MAX_RECOVERY_SUBMISSIONS; attempt += 1) {
    const recoveryJob = await createJob({
      ctx,
      identity,
      builder: builder.account,
      grantId,
    });
    const submitted = await submitJob(
      ctx,
      builder.account,
      recoveryJob,
      NO_WAIT_SECONDS,
    );
    requireResponse(
      submitted,
      HTTP_ACCEPTED,
      (body) => record(body)?.state === "queued",
      "Expected lease-recovery job submission to queue",
    );
    const slowStatus = await waitForSlowClaim(
      ctx,
      builder.account,
      recoveryJob.request.jobId,
    );
    if (!slowStatus) continue;

    console.error(
      `RECOVERY_JOB ${recoveryJob.request.jobId} in flight on the slow node; stop that node now`,
    );
    const status = await pollJob(
      ctx,
      builder.account,
      recoveryJob.request.jobId,
      REMOTE_RECOVERY_TIMEOUT_MS,
    );
    if (status.state !== "completed" || status.attempt !== 2) {
      throw new Error(
        `Expected attempt-2 completion, received ${status.state}:${status.attempt}`,
      );
    }
    await assertResult(ctx, builder.privateKey, status, expectedVersion);

    return `jobId=${recoveryJob.request.jobId}`;
  }

  throw new Error(
    `Fast node claimed all ${MAX_RECOVERY_SUBMISSIONS} recovery jobs`,
  );
}

async function waitForSlowClaim(
  ctx: JobContext,
  builder: PrivateKeyAccount,
  jobId: string,
): Promise<JobStatus | undefined> {
  const deadline = Date.now() + REMOTE_CLAIM_TIMEOUT_MS;
  let lastStatus: JobStatus | undefined;
  while (Date.now() < deadline) {
    const result = await getJob(ctx, builder, jobId);
    lastStatus = jobFromResult(result);
    if (lastStatus?.state === "completed" && lastStatus.attempt === 1) {
      return undefined;
    }
    if (
      lastStatus &&
      ["failed", "expired", "cancelled"].includes(lastStatus.state)
    ) {
      throw new Error(
        `Recovery candidate ended as ${lastStatus.state}:${lastStatus.attempt}`,
      );
    }
    await delay(POLL_INTERVAL_MS);
  }

  return lastStatus && ["claimed", "running"].includes(lastStatus.state)
    ? lastStatus
    : undefined;
}

async function registerJobAgent(
  ctx: JobContext,
  label: string,
  workDelayMs?: number,
): Promise<AgentProcess> {
  const port = await freePort();
  const nodeId = `e2e-${label}-${randomUUID()}`;
  const nodeSecret = randomBytes(NODE_SECRET_BYTES).toString("hex");
  const origin = `http://${AGENT_HOST}:${port}`;
  const info = await fakeNodeInfo();
  await registerNode(ctx, nodeId, nodeSecret, origin, info);
  const agent = await startAgent(ctx, port, {
    id: nodeId,
    secret: nodeSecret,
    ...(workDelayMs === undefined ? {} : { workDelayMs }),
  });
  await waitForHeartbeat(ctx, nodeId);
  await admitNode(ctx, nodeId);

  return agent;
}

async function cleanup(): Promise<void> {
  if (cleanupStarted) return;
  cleanupStarted = true;
  const context = cleanupContext;
  if (context) {
    for (const nodeId of nodeIds) {
      await operatorRequest(
        context,
        "POST",
        `/v1/tee-nodes/${encodeURIComponent(nodeId)}/drain`,
      ).catch(() => undefined);
      await operatorRequest(
        context,
        "POST",
        `/v1/tee-nodes/${encodeURIComponent(nodeId)}/remove`,
      ).catch(() => undefined);
    }
  }
  for (const agent of agents) stopAgent(agent);
  if (rootToRemove && process.env.KEEP_E2E_ROOT !== KEEP_ROOT) {
    await rm(rootToRemove, { recursive: true, force: true });
  }
  if (originalFetch) {
    globalThis.fetch = originalFetch;
    originalFetch = undefined;
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function main(): Promise<void> {
  const ctx = await buildContext();
  cleanupContext = ctx;
  const anchors = fakeGatewayAnchors();
  const verifyingContract = getAddress(
    process.env.DATA_PORTABILITY_SERVER_CONTRACT ??
      PERSONAL_SERVER_REGISTRATION_DEFAULT_VERIFYING_CONTRACT,
  );
  const identityAgent = ctx.remote
    ? undefined
    : await startAgent(ctx, await freePort(DEFAULT_AGENT_PORT));
  let identity: IdentityResponse | undefined;
  let builder: RegisteredBuilder | undefined;
  let grantId: Hex | undefined;
  let agentA: AgentProcess | undefined;

  await runStep("1", "prepare identity", [], async () => {
    const result = await requestJson("POST", `${ctx.gatewayUrl}/v1/identity`, {
      ownerAddress: ctx.owner.address,
      chainId: ctx.chainId,
    });
    const body = result.response.body as IdentityResponse;
    requireResponse(
      result,
      HTTP_OK,
      () =>
        body.created === true &&
        body.state === "prepared" &&
        body.identity.userPsId.toLowerCase() === ctx.userPsId.toLowerCase(),
      "Expected a fresh prepared identity",
    );
    identity = body;
  });

  await runStep("2", "verify enclave evidence", ["1"], async () => {
    await verifyEnclaveIdentityEvidence(
      identity!.identity,
      {
        kmsRootPubkey: (process.env.ENCLAVE_KMS_ROOT_PUBKEY ??
          anchors.kmsRootPubkey) as Hex,
        appIds: (process.env.ENCLAVE_APP_ID_ALLOWLIST ?? anchors.appId)
          .split(",")
          .map((appId) => appId.trim() as Hex),
      },
      {
        ownerAddress: ctx.owner.address,
        chainId: ctx.chainId,
        epoch: FIRST_EPOCH,
      },
    );
  });

  await runStep("3", "register identity", ["1", "2"], async () => {
    const typedData = buildPersonalServerRegistrationTypedData({
      ownerAddress: ctx.owner.address,
      serverAddress: identity!.identity.address,
      serverPublicKey: identity!.identity.publicKey,
      serverUrl: identity!.serverUrl,
      chainId: ctx.chainId,
      verifyingContract,
    });
    const signature = await ctx.owner.signTypedData(typedData);
    const result = await requestJson(
      "POST",
      `${ctx.gatewayUrl}/v1/identity/${ctx.userPsId}/register`,
      { version: "v2", message: typedData.message },
      { Authorization: `Web3Signed ${signature}` },
    );
    requireResponse(
      result,
      HTTP_CREATED,
      (body) => record(body)?.state === "registered",
      "Expected a registered identity",
    );
  });

  await runStep("4", "seal master signature", ["1", "2", "3"], async () => {
    const delivery = await buildMasterSignatureDelivery(
      identity!.identity,
      ctx.ownerSignature,
    );
    const ciphertext = await encryptMasterSignatureDelivery(
      delivery,
      identity!.identity.publicKey,
      ctx.ecies,
    );
    const submission: SealedSecretSubmission = {
      userPsId: ctx.userPsId,
      epoch: FIRST_EPOCH,
      enclaveAddress: identity!.identity.address,
      ciphertext,
    };
    const result = await requestJson(
      "POST",
      `${ctx.gatewayUrl}/v1/identity/${ctx.userPsId}/secret`,
      submission,
    );
    requireResponse(
      result,
      HTTP_CREATED,
      (body) => record(body)?.sealed === true,
      "Expected the master signature to be sealed",
    );
    if (identityAgent) stopAgent(identityAgent);
  });

  await runStep(
    "5",
    ctx.remote ? "verify remote nodes" : "register and admit node A",
    ["4"],
    async () => {
      if (ctx.remote) return verifyRemoteNodes(ctx);
      agentA = await registerJobAgent(ctx, "node-a");
      return `nodeId=${agentA.nodeId}`;
    },
  );

  await runStep("6", "register builder", ["5"], async () => {
    builder = await registerBuilder(ctx);
    return `builderId=${builder.id}`;
  });

  await runStep("7", "create owner grant", ["6"], async () => {
    grantId = await createGrant(ctx, builder!.id, GRANT_VERSION_ONE);
    return `grantId=${grantId}`;
  });

  let expectedVersion: string | undefined;
  await runStep("8", "seed one record", ["7"], async () => {
    expectedVersion = await seedRecord(ctx);
    if (!ctx.remote) await access(join(sandboxRoot(ctx), "index.db"));
    return expectedVersion ? `expectedVersion=${expectedVersion}` : undefined;
  });

  let completedJob: CreatedJob | undefined;
  await runStep("9", "submit and decrypt raw read", ["8"], async () => {
    const completed = await submitAndDecrypt(
      ctx,
      identity!.identity,
      builder!,
      grantId!,
      expectedVersion,
    );
    completedJob = completed.job;
    return `submit_ms=${completed.submitMs}`;
  });

  if (ctx.warmRuns > 0) {
    await runStep("9w", "warm submit and decrypt cycles", ["9"], async () => {
      const timings: number[] = [];
      for (let run = 0; run < ctx.warmRuns; run += 1) {
        const completed = await submitAndDecrypt(
          ctx,
          identity!.identity,
          builder!,
          grantId!,
          expectedVersion,
        );
        timings.push(completed.submitMs);
      }
      return `warm_ms=${timings.join(",")}`;
    });
  }

  await runStep("10", "enforce job status ownership", ["9"], async () => {
    const own = await getJob(
      ctx,
      builder!.account,
      completedJob!.request.jobId,
    );
    requireResponse(
      own,
      HTTP_OK,
      (body) => record(record(body)?.job)?.state === "completed",
      "Expected the submitting builder to read completed status",
    );
    const other = privateKeyToAccount(generatePrivateKey());
    const hidden = await getJob(ctx, other, completedJob!.request.jobId);
    requireResponse(
      hidden,
      HTTP_NOT_FOUND,
      () => true,
      "Expected another signer to receive 404",
    );
  });

  await runStep("11", "reject wrong builder keys", ["9"], async () => {
    const wrongAuth = await createJob({
      ctx,
      identity: identity!.identity,
      builder: builder!.account,
      grantId: grantId!,
      authSigner: privateKeyToAccount(generatePrivateKey()),
    });
    await submitJob(ctx, builder!.account, wrongAuth, JOB_WAIT_SECONDS);
    const authStatus = await pollJob(
      ctx,
      builder!.account,
      wrongAuth.request.jobId,
      JOB_TIMEOUT_MS,
    );
    if (
      authStatus.state !== "failed" ||
      !JOB_FAILURE_CODES.has(authStatus.failureReason ?? "")
    ) {
      throw new Error(
        `Unexpected wrong-auth outcome ${authStatus.state}:${authStatus.failureReason}`,
      );
    }

    const wrongEncryption = privateKeyToAccount(generatePrivateKey());
    const wrongBox = await createJob({
      ctx,
      identity: identity!.identity,
      builder: builder!.account,
      grantId: grantId!,
      encryptionKey: wrongEncryption.publicKey,
    });
    await submitJob(ctx, builder!.account, wrongBox, JOB_WAIT_SECONDS);
    const boxStatus = await pollJob(
      ctx,
      builder!.account,
      wrongBox.request.jobId,
      JOB_TIMEOUT_MS,
    );
    if (
      boxStatus.state !== "failed" ||
      boxStatus.failureReason !== DECRYPT_FAILURE_REASON
    ) {
      throw new Error(
        `Unexpected wrong-box outcome ${boxStatus.state}:${boxStatus.failureReason}`,
      );
    }
  });

  await runStep("12", "reject revoked grant", ["11"], async () => {
    await revokeGrant(ctx, grantId!);
    const revokedJob = await createJob({
      ctx,
      identity: identity!.identity,
      builder: builder!.account,
      grantId: grantId!,
    });
    const submitted = await submitJob(
      ctx,
      builder!.account,
      revokedJob,
      JOB_WAIT_SECONDS,
    );
    let outcome: string;
    if (submitted.response.status === HTTP_FORBIDDEN) {
      const code = record(submitted.response.body)?.code;
      if (code !== "GRANT_INVALID") {
        throw new Error(`Unexpected revoked admission code ${String(code)}`);
      }
      outcome = "gateway=GRANT_INVALID";
    } else {
      const status = await pollJob(
        ctx,
        builder!.account,
        revokedJob.request.jobId,
        JOB_TIMEOUT_MS,
      );
      if (
        status.state !== "failed" ||
        status.failureReason !== "GRANT_REVOKED"
      ) {
        throw new Error(
          `Unexpected revoked job outcome ${status.state}:${status.failureReason}`,
        );
      }
      outcome = "sandbox=GRANT_REVOKED";
    }
    grantId = await createGrant(ctx, builder!.id, GRANT_VERSION_FRESH);
    return outcome;
  });

  await runStep("13", "recover an expired lease", ["12"], async () => {
    if (ctx.remote) {
      if (!ctx.recovery) return "skipped: E2E_RECOVERY unset";
      return recoverRemoteLease(
        ctx,
        identity!.identity,
        builder!,
        grantId!,
        expectedVersion,
      );
    }

    stopAgent(agentA!);
    const agentB = await registerJobAgent(ctx, "node-b", LEASE_WORK_DELAY_MS);
    const recoveryJob = await createJob({
      ctx,
      identity: identity!.identity,
      builder: builder!.account,
      grantId: grantId!,
    });
    const submitted = await submitJob(
      ctx,
      builder!.account,
      recoveryJob,
      NO_WAIT_SECONDS,
    );
    requireResponse(
      submitted,
      HTTP_ACCEPTED,
      (body) => record(body)?.state === "queued",
      "Expected lease-recovery job submission to queue",
    );
    await delay(LEASE_KILL_DELAY_MS);
    stopAgent(agentB);
    await registerJobAgent(ctx, "node-c");
    const status = await pollJob(
      ctx,
      builder!.account,
      recoveryJob.request.jobId,
      RECOVERY_TIMEOUT_MS,
    );
    if (status.state !== "completed" || status.attempt !== 2) {
      throw new Error(
        `Expected attempt-2 completion, received ${status.state}:${status.attempt}`,
      );
    }
    await assertResult(ctx, builder!.privateKey, status, expectedVersion);
  });

  printSummary();
  process.exitCode = hasStepFailures() ? EXIT_FAILURE : EXIT_SUCCESS;
}

process.once("SIGINT", () => {
  void cleanup().finally(() => process.exit(EXIT_FAILURE));
});
process.once("SIGTERM", () => {
  void cleanup().finally(() => process.exit(EXIT_FAILURE));
});

main()
  .catch((error: unknown) => {
    console.error(
      `Job E2E setup failed: ${error instanceof Error ? error.message : String(error)}`,
    );
    process.exitCode = EXIT_FAILURE;
  })
  .finally(cleanup);
