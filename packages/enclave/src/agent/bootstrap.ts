import type { DstackClient } from "../dstack/client.js";
import { createFakeDstackClient } from "../dstack/fake.js";
import { createRealDstackClient } from "../dstack/real.js";
import { DEFAULT_LEASE_SECONDS, MAX_LEASE_SECONDS } from "../jobs/types.js";
import { SANDBOX_IDLE_TTL_SECONDS, SANDBOX_MAX } from "../sandbox/registry.js";

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 8787;
const DEFAULT_FAKE_APP_ID = "0000000000000000000000000000000000000001";
const FAKE_DSTACK_ENABLED = "1";
const MIN_PORT = 1;
const MAX_PORT = 65_535;
const DEFAULT_DOCKER_HOST = "tcp://sandbox-runtime:2375";
const DEFAULT_SANDBOX_RUNTIME = "docker";
const DEFAULT_SYNC_MODE = "enabled";
const MILLISECONDS_PER_SECOND = 1_000;
const MIN_POSITIVE_INTEGER = 1;
const MIN_NONNEGATIVE_INTEGER = 0;

export type SandboxRuntimeKind = "docker" | "fake";
export type SandboxSyncMode = "enabled" | "disabled";

export interface AgentJobsConfig {
  gatewayUrl: string;
  nodeId: string;
  nodeSecret: string;
  runtime: SandboxRuntimeKind;
  image: string;
  sandboxMax: number;
  idleTtlMs: number;
  leaseSeconds: number;
  dockerHost: string;
  psEntry?: string;
  fakeRoot?: string;
  sync: SandboxSyncMode;
  workDelayMs: number;
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
  const sandboxMax = readInteger(
    env.SANDBOX_MAX,
    "SANDBOX_MAX",
    SANDBOX_MAX,
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

  try {
    new URL(env.GATEWAY_URL);
  } catch {
    throw new Error("GATEWAY_URL must be a valid URL");
  }

  return {
    gatewayUrl: env.GATEWAY_URL,
    nodeId: env.NODE_ID,
    nodeSecret: env.NODE_SECRET,
    runtime,
    image,
    sandboxMax,
    idleTtlMs: idleTtlSeconds * MILLISECONDS_PER_SECOND,
    leaseSeconds,
    dockerHost: env.DOCKER_HOST ?? DEFAULT_DOCKER_HOST,
    ...(runtime === "fake" && env.PS_ENTRY ? { psEntry: env.PS_ENTRY } : {}),
    ...(runtime === "fake" && env.SANDBOX_FAKE_ROOT
      ? { fakeRoot: env.SANDBOX_FAKE_ROOT }
      : {}),
    sync,
    workDelayMs,
    ...(env.VERCEL_PROTECTION_BYPASS
      ? { gatewayBypassSecret: env.VERCEL_PROTECTION_BYPASS }
      : {}),
  };
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
