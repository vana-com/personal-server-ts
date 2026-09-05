import os from "node:os";
import { createConnection, isIPv4 } from "node:net";
import type { DstackClient } from "../dstack/client.js";
import { isAddress } from "viem";
import { createFakeDstackClient } from "../dstack/fake.js";
import { createRealDstackClient } from "../dstack/real.js";
import { DEFAULT_LEASE_SECONDS, MAX_LEASE_SECONDS } from "../jobs/types.js";
import {
  DEFAULT_SANDBOX_CPUS,
  DEFAULT_SANDBOX_MEMORY,
  DEFAULT_SANDBOX_PIDS_LIMIT,
} from "../sandbox/docker-runtime.js";
import { SANDBOX_IDLE_TTL_SECONDS, SANDBOX_MAX } from "../sandbox/registry.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const DEFAULT_FAKE_APP_ID = "0000000000000000000000000000000000000001";
const FAKE_DSTACK_ENABLED = "1";
const SANDBOX_DEBUG_ENABLED = "1";
const MIN_PORT = 1;
const MAX_PORT = 65_535;
const DEFAULT_DOCKER_HOST = "tcp://sandbox-runtime:2375";
const DEFAULT_SANDBOX_RUNTIME = "docker";
const DEFAULT_SYNC_MODE = "enabled";
const DEFAULT_DOCKER_PORT = 2_375;
const ROUTE_RESOLUTION_TIMEOUT_MS = 5_000;
const MILLISECONDS_PER_SECOND = 1_000;
const MIN_POSITIVE_INTEGER = 1;
const MIN_NONNEGATIVE_INTEGER = 0;
const DOCKER_IMAGE_DIGEST_PATTERN = /^.+@sha256:[0-9a-f]{64}$/;
const DOCKER_IMAGE_ID_PATTERN = /^sha256:[0-9a-f]{64}$/;
const HTTPS_PROTOCOL = "https:";
const DOCKER_IMAGE_ERROR =
  "PS_IMAGE must be a sha256 digest (name@sha256:<64 hex>) or a Docker image id (sha256:<64 hex>) for the docker runtime";
const DOCKER_GATEWAY_ERROR =
  "GATEWAY_URL must use https for the docker runtime";
const MEMORY_PATTERN = /^[1-9][0-9]*(?:\.[0-9]+)?[kmgt]?$/i;
const MAINNET_CHAIN_ID = 1_480;
const MOKSHA_CHAIN_ID = 14_800;
const DEFAULT_STORAGE_API_URLS = {
  [MAINNET_CHAIN_ID]: "https://storage.vana.org",
  [MOKSHA_CHAIN_ID]: "https://storage-dev.vana.org",
} as const;
const DEFAULT_CONTRACTS = {
  dataRegistry: "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867",
  dataPortabilityPermissions: "0x4d3FA76064D88e0454cFc4CaD7e5FeC3e3124011",
  dataPortabilityServer: "0xCae2CE0e9caa6643ed28186cF57bd40Bd9E17Eab",
  dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
} as const;

export type SupportedChainId = typeof MAINNET_CHAIN_ID | typeof MOKSHA_CHAIN_ID;

export interface SandboxContracts {
  dataRegistry: string;
  dataPortabilityPermissions: string;
  dataPortabilityServer: string;
  dataPortabilityGrantees: string;
}

export type SandboxRuntimeKind = "docker" | "fake";
export type SandboxSyncMode = "enabled" | "disabled";

export interface AgentJobsConfig {
  gatewayUrl: string;
  storageApiUrl: string;
  sandboxAgentUrl?: string;
  chainId: SupportedChainId;
  contracts: SandboxContracts;
  nodeId: string;
  nodeSecret: string;
  runtime: SandboxRuntimeKind;
  image: string;
  sandboxMax: number;
  sandboxMemory: string;
  sandboxCpus: string;
  sandboxPidsLimit: number;
  idleTtlMs: number;
  leaseSeconds: number;
  dockerHost: string;
  psEntry?: string;
  fakeRoot?: string;
  sync: SandboxSyncMode;
  workDelayMs: number;
  sandboxDebug: boolean;
  gatewayBypassSecret?: string;
}

export interface AgentConfig {
  host: string;
  port: number;
  secret: string;
  client: DstackClient;
  jobs?: AgentJobsConfig;
}

export function agentConfigFromEnv(env: NodeJS.ProcessEnv): AgentConfig {
  const secret = env.ENCLAVE_AGENT_SECRET;
  if (!secret) {
    throw new Error("ENCLAVE_AGENT_SECRET is required");
  }

  const jobs = jobsConfig(env);

  return {
    host: env.ENCLAVE_AGENT_HOST ?? DEFAULT_HOST,
    port: readPort(env.ENCLAVE_AGENT_PORT),
    secret,
    client:
      env.DSTACK_FAKE === FAKE_DSTACK_ENABLED
        ? createFakeDstackClient({
            appId: env.DSTACK_FAKE_APP_ID ?? DEFAULT_FAKE_APP_ID,
          })
        : createRealDstackClient(),
    ...(jobs ? { jobs } : {}),
  };
}

function jobsConfig(env: NodeJS.ProcessEnv): AgentJobsConfig | undefined {
  if (!env.GATEWAY_URL || !env.NODE_ID || !env.NODE_SECRET) {
    return undefined;
  }

  const runtime = readRuntime(env.SANDBOX_RUNTIME);
  const image = env.PS_IMAGE;
  if (!image) {
    throw new Error("PS_IMAGE is required when jobs are enabled");
  }

  const sync = readSync(env.SANDBOX_SYNC);
  const chainId = readChainId(env.CHAIN_ID);
  const contracts = readContracts(env);
  const sandboxMax = readInteger(
    env.SANDBOX_MAX,
    "SANDBOX_MAX",
    SANDBOX_MAX,
    MIN_POSITIVE_INTEGER,
  );
  const sandboxMemory = readMemory(env.SANDBOX_MEMORY);
  const sandboxCpus = readCpus(env.SANDBOX_CPUS);
  const sandboxPidsLimit = readInteger(
    env.SANDBOX_PIDS_LIMIT,
    "SANDBOX_PIDS_LIMIT",
    DEFAULT_SANDBOX_PIDS_LIMIT,
    MIN_POSITIVE_INTEGER,
  );
  const idleTtlSeconds = readInteger(
    env.SANDBOX_IDLE_TTL_SECONDS,
    "SANDBOX_IDLE_TTL_SECONDS",
    SANDBOX_IDLE_TTL_SECONDS,
    MIN_POSITIVE_INTEGER,
  );
  const leaseSeconds = readInteger(
    env.LEASE_SECONDS,
    "LEASE_SECONDS",
    DEFAULT_LEASE_SECONDS,
    MIN_POSITIVE_INTEGER,
    MAX_LEASE_SECONDS,
  );
  const workDelayMs = readInteger(
    env.WORK_DELAY_MS,
    "WORK_DELAY_MS",
    MIN_NONNEGATIVE_INTEGER,
    MIN_NONNEGATIVE_INTEGER,
  );

  let gatewayUrl: URL;
  try {
    gatewayUrl = new URL(env.GATEWAY_URL);
  } catch {
    throw new Error("GATEWAY_URL must be a valid URL");
  }
  const storageApiUrlValue =
    env.STORAGE_API_URL ?? DEFAULT_STORAGE_API_URLS[chainId];
  if (storageApiUrlValue) {
    let storageApiUrl: URL;
    try {
      storageApiUrl = new URL(storageApiUrlValue);
    } catch {
      throw new Error("STORAGE_API_URL must be a valid URL");
    }
    if (storageApiUrl.protocol !== HTTPS_PROTOCOL) {
      throw new Error("STORAGE_API_URL must use https");
    }
  }
  if (
    runtime === "docker" &&
    !DOCKER_IMAGE_DIGEST_PATTERN.test(image) &&
    !DOCKER_IMAGE_ID_PATTERN.test(image)
  ) {
    throw new Error(DOCKER_IMAGE_ERROR);
  }
  if (runtime === "docker" && gatewayUrl.protocol !== HTTPS_PROTOCOL) {
    throw new Error(DOCKER_GATEWAY_ERROR);
  }
  if (workDelayMs > MIN_NONNEGATIVE_INTEGER) {
    console.error({
      level: "warn",
      workDelayMs,
      message: `WORK_DELAY_MS=${workDelayMs}ms is set — this node artificially delays every job; do not use in production`,
    });
  }

  return {
    gatewayUrl: env.GATEWAY_URL,
    storageApiUrl: storageApiUrlValue,
    ...(env.SANDBOX_AGENT_URL
      ? { sandboxAgentUrl: env.SANDBOX_AGENT_URL }
      : {}),
    chainId,
    contracts,
    nodeId: env.NODE_ID,
    nodeSecret: env.NODE_SECRET,
    runtime,
    image,
    sandboxMax,
    sandboxMemory,
    sandboxCpus,
    sandboxPidsLimit,
    idleTtlMs: idleTtlSeconds * MILLISECONDS_PER_SECOND,
    leaseSeconds,
    dockerHost: env.DOCKER_HOST ?? DEFAULT_DOCKER_HOST,
    ...(runtime === "fake" && env.PS_ENTRY ? { psEntry: env.PS_ENTRY } : {}),
    ...(runtime === "fake" && env.SANDBOX_FAKE_ROOT
      ? { fakeRoot: env.SANDBOX_FAKE_ROOT }
      : {}),
    sync,
    workDelayMs,
    sandboxDebug: env.SANDBOX_DEBUG === SANDBOX_DEBUG_ENABLED,
    ...(env.VERCEL_PROTECTION_BYPASS
      ? { gatewayBypassSecret: env.VERCEL_PROTECTION_BYPASS }
      : {}),
  };
}

export interface SandboxAgentUrlOptions {
  override?: string;
  dockerHost: string;
  agentPort: number;
}

interface SandboxAgentUrlDeps {
  routeAddress?: (host: string, port: number) => Promise<string>;
  networkInterfaces?: typeof os.networkInterfaces;
}

export async function resolveSandboxAgentUrl(
  options: SandboxAgentUrlOptions,
  deps: SandboxAgentUrlDeps = {},
): Promise<string> {
  if (options.override) {
    return options.override;
  }

  let dockerUrl: URL;
  try {
    dockerUrl = new URL(options.dockerHost);
  } catch {
    throw new Error("DOCKER_HOST must be a valid URL");
  }
  const dockerPort = dockerUrl.port
    ? Number(dockerUrl.port)
    : DEFAULT_DOCKER_PORT;
  const routeAddress = deps.routeAddress ?? localAddressForRoute;
  let address: string | undefined;
  try {
    const routedAddress = await routeAddress(dockerUrl.hostname, dockerPort);
    if (isIPv4(routedAddress)) {
      address = routedAddress;
    }
  } catch {
    // Fall back to the first externally reachable IPv4 on unusual hosts.
  }
  address ??= firstNonLoopbackIpv4(
    (deps.networkInterfaces ?? os.networkInterfaces)(),
  );
  if (!address) {
    throw new Error("Could not resolve an IPv4 address reachable by sandboxes");
  }

  return `http://${address}:${options.agentPort}`;
}

function localAddressForRoute(host: string, port: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host, port });
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const address = socket.localAddress;
      socket.destroy();
      if (error) {
        reject(error);
      } else if (address) {
        resolve(address);
      } else {
        reject(new Error("Route did not select a local address"));
      }
    };
    const timer = setTimeout(
      () => finish(new Error("Timed out resolving the Docker host route")),
      ROUTE_RESOLUTION_TIMEOUT_MS,
    );
    timer.unref();
    socket.once("connect", () => finish());
    socket.once("error", finish);
  });
}

function firstNonLoopbackIpv4(
  interfaces: ReturnType<typeof os.networkInterfaces>,
): string | undefined {
  for (const addresses of Object.values(interfaces)) {
    const address = addresses?.find(
      (candidate) => !candidate.internal && candidate.family === "IPv4",
    );
    if (address) return address.address;
  }

  return undefined;
}

function readMemory(value: string | undefined): string {
  const memory = value ?? DEFAULT_SANDBOX_MEMORY;
  if (!MEMORY_PATTERN.test(memory)) {
    throw new Error("SANDBOX_MEMORY must be a positive Docker memory value");
  }

  return memory;
}

function readCpus(value: string | undefined): string {
  const cpus = value ?? DEFAULT_SANDBOX_CPUS;
  const parsed = Number(cpus);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error("SANDBOX_CPUS must be a positive number");
  }
  const host = os.availableParallelism();
  if (parsed > host) {
    console.error({
      level: "warn",
      configured: parsed,
      host,
      effective: host,
      message: "SANDBOX_CPUS exceeds host capacity; clamping",
    });

    return String(host);
  }

  return cpus;
}

function readChainId(value: string | undefined): SupportedChainId {
  const chainId = value === undefined ? MOKSHA_CHAIN_ID : Number(value);
  if (chainId !== MAINNET_CHAIN_ID && chainId !== MOKSHA_CHAIN_ID) {
    throw new Error("CHAIN_ID must be 1480 or 14800");
  }

  return chainId;
}

function readContracts(env: NodeJS.ProcessEnv): SandboxContracts {
  return {
    dataRegistry: readAddress(
      env.DATA_REGISTRY_CONTRACT,
      "DATA_REGISTRY_CONTRACT",
      DEFAULT_CONTRACTS.dataRegistry,
    ),
    dataPortabilityServer: readAddress(
      env.DATA_PORTABILITY_SERVER_CONTRACT,
      "DATA_PORTABILITY_SERVER_CONTRACT",
      DEFAULT_CONTRACTS.dataPortabilityServer,
    ),
    dataPortabilityGrantees: readAddress(
      env.DATA_PORTABILITY_GRANTEES_CONTRACT,
      "DATA_PORTABILITY_GRANTEES_CONTRACT",
      DEFAULT_CONTRACTS.dataPortabilityGrantees,
    ),
    dataPortabilityPermissions: readAddress(
      env.DATA_PORTABILITY_PERMISSIONS_CONTRACT,
      "DATA_PORTABILITY_PERMISSIONS_CONTRACT",
      DEFAULT_CONTRACTS.dataPortabilityPermissions,
    ),
  };
}

function readAddress(
  value: string | undefined,
  name: string,
  fallback: string,
): string {
  const address = value ?? fallback;
  if (!isAddress(address)) {
    throw new Error(`${name} must be an address`);
  }

  return address;
}

function readRuntime(value: string | undefined): SandboxRuntimeKind {
  const runtime = value ?? DEFAULT_SANDBOX_RUNTIME;
  if (runtime !== "docker" && runtime !== "fake") {
    throw new Error("SANDBOX_RUNTIME must be docker or fake");
  }

  return runtime;
}

function readSync(value: string | undefined): SandboxSyncMode {
  const sync = value ?? DEFAULT_SYNC_MODE;
  if (sync !== "enabled" && sync !== "disabled") {
    throw new Error("SANDBOX_SYNC must be enabled or disabled");
  }

  return sync;
}

function readInteger(
  value: string | undefined,
  name: string,
  fallback: number,
  minimum: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }

  return parsed;
}

function readPort(value: string | undefined): number {
  if (value === undefined) {
    return DEFAULT_PORT;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port < MIN_PORT || port > MAX_PORT) {
    throw new Error("ENCLAVE_AGENT_PORT must be an integer from 1 to 65535");
  }

  return port;
}
