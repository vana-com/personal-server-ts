import { execFile } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sleepWithAbort, throwIfAborted } from "./abort.js";
import type {
  HealthProbe,
  SyncProbe,
  SyncProbeResult,
  SyncStatusProbe,
} from "./probes.js";
import { probeHealth, probeSyncStatus } from "./probes.js";
import {
  assertSandboxEnv,
  SECRET_ENV_KEYS,
  type SandboxHandle,
  type SandboxRuntime,
  type SandboxSpec,
} from "./runtime.js";

const DEFAULT_DOCKER_HOST = "tcp://sandbox-runtime:2375";
const DEFAULT_DOCKER_BINARY = "docker";
const GVISOR_RUNTIME = "runsc-ptrace";
const CONTAINER_USER = "1000:1000";
const DROPPED_CAPABILITIES = "ALL";
const NO_NEW_PRIVILEGES = "no-new-privileges:true";
const DATA_TMPFS =
  "/data:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700";
const CONTAINER_PORT = 8080;
const MILLISECONDS_PER_MINUTE = 60_000;
const DEFAULT_HEALTH_TIMEOUT_MS = 2 * MILLISECONDS_PER_MINUTE;
const DEFAULT_SYNC_TIMEOUT_MS = 20 * MILLISECONDS_PER_MINUTE;
const POLL_INTERVAL_MS = 250;
const WAIT_LOG_INTERVAL_MS = 30_000;
const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const SYNC_DISABLED = "false";
const CREATE_COMMAND = "create";
const LIST_COMMAND = "ps";
const START_COMMAND = "start";
const INSPECT_COMMAND = "inspect";
const LOGS_COMMAND = "logs";
const REMOVE_COMMAND = "rm";
const FORCE_FLAG = "--force";
const VOLUMES_FLAG = "--volumes";
const FORMAT_FLAG = "--format";
const PUBLISH_FLAG = "--publish";
const PUBLISHED_PORT = `0:${CONTAINER_PORT}`;
const RUNNING_FORMAT = "{{.State.Running}}";
const HOST_PORT_FORMAT =
  '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}';
const RUNNING_VALUE = "true";
const ALL_FLAG = "--all";
const QUIET_FLAG = "--quiet";
const FILTER_FLAG = "--filter";
const LABEL_FLAG = "--label";
const TAIL_FLAG = "--tail";
const SANDBOX_LABEL = "org.vana.personal-server.sandbox=true";
const SANDBOX_NAME_FILTER = "name=^/ps-";
const NOT_FOUND_PATTERN = /No such container/i;
const SYNC_TOKEN_MESSAGE = "Sandbox sync requires PS_ACCESS_TOKEN";
const INVALID_DOCKER_HOST = "DOCKER_HOST must have a hostname";
const STDERR_TAIL_LENGTH = 2_048;
const SECRET_ENV_KEY_SET = new Set<string>(SECRET_ENV_KEYS);
const SECRET_ENV_DIRECTORY_PREFIX = "ps-docker-env-";
const SECRET_ENV_FILENAME = "sandbox.env";
const SECRET_ENV_LINE_BREAK = /[\r\n]/;
const NON_TRANSIENT_SANDBOX_PATTERNS = [
  /range of CPUs is from/i,
  /invalid (?:cpu|memory|pids|resource)/i,
  /minimum memory limit/i,
  /no such image/i,
  /manifest unknown/i,
  /unknown(?: or invalid)? runtime/i,
  /runtime .* (?:unavailable|not found)/i,
];

export const DEFAULT_SANDBOX_MEMORY = "512m";
export const DEFAULT_SANDBOX_CPUS = "2";
export const DEFAULT_SANDBOX_PIDS_LIMIT = 256;

const FIXED_ENV = {
  CLOUD_MODE: "true",
  DEV_UI_ENABLED: "false",
  TUNNEL_ENABLED: "false",
  ENCLAVE_MODE: "true",
  PERSONAL_SERVER_ROOT_PATH: "/data",
  SERVER_ORIGIN: `http://localhost:${CONTAINER_PORT}`,
} as const;

export interface ContainerInspection {
  running: boolean;
  hostPort?: number;
}

/** DockerClient promoted from spike/sandbox launcher.ts. */
export interface DockerClient {
  run(
    command: string,
    args: string[],
    env?: Record<string, string>,
    redactions?: Record<string, string>,
  ): Promise<string>;
  inspect(id: string): Promise<ContainerInspection>;
}

export interface DockerRuntimeOptions {
  docker?: DockerClient;
  dockerHost?: string;
  runtimeHost?: string;
  dockerBinary?: string;
  healthTimeoutMs?: number;
  syncTimeoutMs?: number;
  health?: HealthProbe;
  sync?: SyncProbe;
  syncStatus?: SyncStatusProbe;
  logger?: SandboxWaitLogger;
  sleep?: (milliseconds: number) => Promise<void>;
  now?: () => number;
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
}

export interface SandboxWaitLogger {
  info(context: Record<string, unknown>, message: string): void;
}

export function isNonTransientDockerSandboxError(error: unknown): boolean {
  if (
    !(error instanceof Error) ||
    !/^Docker (?:create|start) failed:/i.test(error.message)
  ) {
    return false;
  }

  return NON_TRANSIENT_SANDBOX_PATTERNS.some((pattern) =>
    pattern.test(error.message),
  );
}

export function createDockerRuntime(
  options: DockerRuntimeOptions = {},
): SandboxRuntime {
  const dockerHost = options.dockerHost ?? DEFAULT_DOCKER_HOST;
  const docker =
    options.docker ??
    createDockerClient({
      binary: options.dockerBinary,
      host: dockerHost,
    });
  const runtimeHost = options.runtimeHost ?? hostFromDocker(dockerHost);
  const health = options.health ?? probeHealth;
  const sync = options.sync;
  const syncStatus =
    options.syncStatus ??
    (sync
      ? async (origin: string, accessToken: string, signal?: AbortSignal) => ({
          ready: await sync(origin, accessToken, signal),
        })
      : probeSyncStatus);
  const sleep = options.sleep ?? delay;
  const now = options.now ?? Date.now;
  const healthTimeoutMs = options.healthTimeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS;
  const syncTimeoutMs = options.syncTimeoutMs ?? DEFAULT_SYNC_TIMEOUT_MS;
  const memory = options.memory ?? DEFAULT_SANDBOX_MEMORY;
  const cpus = options.cpus ?? DEFAULT_SANDBOX_CPUS;
  const pidsLimit = options.pidsLimit ?? DEFAULT_SANDBOX_PIDS_LIMIT;

  return {
    async reconcile(): Promise<void> {
      const output = await docker.run(LIST_COMMAND, [
        ALL_FLAG,
        QUIET_FLAG,
        FILTER_FLAG,
        SANDBOX_NAME_FILTER,
      ]);
      const ids = output.split(/\s+/).filter(Boolean);
      if (ids.length > 0) {
        await docker.run(REMOVE_COMMAND, [FORCE_FLAG, VOLUMES_FLAG, ...ids]);
      }
    },
    async start(spec, signal): Promise<SandboxHandle> {
      throwIfAborted(signal);
      assertSandboxEnv(spec.env);

      const name = sandboxName(spec);
      const environment = { ...spec.env, ...FIXED_ENV };
      await removeExistingSandbox(docker, name);
      const secretFile = await createSecretEnvFile(environment);
      let containerId: string;
      try {
        containerId = await docker.run(
          CREATE_COMMAND,
          createArgs(
            name,
            spec.image,
            environment,
            memory,
            cpus,
            pidsLimit,
            secretFile.path,
          ),
          undefined,
          secretEnv(environment),
        );
      } finally {
        await rm(secretFile.directory, { recursive: true, force: true });
      }

      try {
        throwIfAborted(signal);
        await docker.run(START_COMMAND, [containerId]);
        const startedAt = now();
        const createdAt = new Date(startedAt).toISOString();
        spec.onStatus?.({ containerId, createdAt, lastSyncStatus: null });
        const origin = await waitForHealth({
          containerId,
          name,
          docker,
          runtimeHost,
          health,
          sleep,
          now,
          deadline: startedAt + healthTimeoutMs,
          timeoutMs: healthTimeoutMs,
          logger: options.logger,
          signal,
        });
        spec.onProgress?.("healthy");

        if (spec.env.SYNC_ENABLED !== SYNC_DISABLED) {
          const accessToken = spec.env.PS_ACCESS_TOKEN;
          if (!accessToken) {
            throw new Error(SYNC_TOKEN_MESSAGE);
          }

          const syncStartedAt = now();
          await waitForSync({
            origin,
            name,
            accessToken,
            syncStatus,
            sleep,
            now,
            startedAt: syncStartedAt,
            deadline: syncStartedAt + syncTimeoutMs,
            timeoutMs: syncTimeoutMs,
            logger: options.logger,
            signal,
            onStatus: (lastSyncStatus) =>
              spec.onStatus?.({ containerId, createdAt, lastSyncStatus }),
          });
        }
        spec.onProgress?.("synced");
        throwIfAborted(signal);

        return { id: containerId, origin };
      } catch (error) {
        await docker.run(REMOVE_COMMAND, [
          FORCE_FLAG,
          VOLUMES_FLAG,
          containerId,
        ]);
        throw error;
      }
    },
    async stop(id): Promise<void> {
      await docker.run(REMOVE_COMMAND, [FORCE_FLAG, VOLUMES_FLAG, id]);
    },
    async inspect(id): Promise<{ running: boolean }> {
      const inspection = await docker.inspect(id);

      return { running: inspection.running };
    },
    logs(id, tail): Promise<string> {
      return docker.run(LOGS_COMMAND, [TAIL_FLAG, String(tail), id]);
    },
  };
}

interface DockerClientOptions {
  binary?: string;
  host?: string;
}

function createDockerClient(options: DockerClientOptions): DockerClient {
  const binary = options.binary ?? DEFAULT_DOCKER_BINARY;
  const host = options.host ?? DEFAULT_DOCKER_HOST;

  return {
    run: (command, args, env, redactions) =>
      runDocker(binary, host, command, args, env, redactions),
    async inspect(id): Promise<ContainerInspection> {
      const [running, hostPortValue] = await Promise.all([
        runDocker(binary, host, INSPECT_COMMAND, [
          FORMAT_FLAG,
          RUNNING_FORMAT,
          id,
        ]),
        runDocker(binary, host, INSPECT_COMMAND, [
          FORMAT_FLAG,
          HOST_PORT_FORMAT,
          id,
        ]),
      ]);
      const hostPort = parseHostPort(hostPortValue);

      return {
        running: running === RUNNING_VALUE,
        ...(hostPort === undefined ? {} : { hostPort }),
      };
    },
  };
}

function runDocker(
  binary: string,
  host: string,
  command: string,
  args: string[],
  env?: Record<string, string>,
  redactions?: Record<string, string>,
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      [command, ...args],
      { env: { ...env, DOCKER_HOST: host } },
      (error, stdout, stderr) => {
        if (error) {
          reject(dockerCommandError(command, error, stderr, redactions ?? env));
          return;
        }

        resolve(
          (command === LOGS_COMMAND ? `${stdout}${stderr}` : stdout).trim(),
        );
      },
    );
  });
}

function dockerCommandError(
  command: string,
  error: Error,
  stderr: string,
  env?: Record<string, string>,
): Error {
  const cause = new Error(redactSecrets(error.message, env));
  cause.name = error.name;
  const stderrTail = redactSecrets(stderr.trim(), env).slice(
    -STDERR_TAIL_LENGTH,
  );
  if (!stderrTail) {
    return cause;
  }

  return new Error(`Docker ${command} failed: ${stderrTail}`, { cause });
}

function redactSecrets(value: string, env?: Record<string, string>): string {
  let redacted = value;
  for (const secret of Object.values(env ?? {})) {
    if (secret) {
      redacted = redacted.replaceAll(secret, "[REDACTED]");
    }
  }

  return redacted;
}

function createArgs(
  name: string,
  image: string,
  environment: Record<string, string>,
  memory: string,
  cpus: string,
  pidsLimit: number,
  secretEnvFile: string,
): string[] {
  const args = [
    "--name",
    name,
    LABEL_FLAG,
    SANDBOX_LABEL,
    "--memory",
    memory,
    "--cpus",
    cpus,
    "--pids-limit",
    String(pidsLimit),
    "--runtime",
    GVISOR_RUNTIME,
    "--user",
    CONTAINER_USER,
    "--read-only",
    "--cap-drop",
    DROPPED_CAPABILITIES,
    "--security-opt",
    NO_NEW_PRIVILEGES,
    "--tmpfs",
    DATA_TMPFS,
    PUBLISH_FLAG,
    PUBLISHED_PORT,
  ];

  for (const [key, value] of Object.entries(environment).sort()) {
    if (!SECRET_ENV_KEY_SET.has(key)) {
      args.push("--env", `${key}=${value}`);
    }
  }
  args.push("--env-file", secretEnvFile);
  args.push(image);

  return args;
}

interface SecretEnvFile {
  directory: string;
  path: string;
}

async function createSecretEnvFile(
  environment: Record<string, string>,
): Promise<SecretEnvFile> {
  const secrets = secretEnv(environment);
  for (const [key, value] of Object.entries(secrets)) {
    if (SECRET_ENV_LINE_BREAK.test(value)) {
      throw new Error(`${key} must not contain a line break`);
    }
  }
  const directory = await mkdtemp(join(tmpdir(), SECRET_ENV_DIRECTORY_PREFIX));
  try {
    await chmod(directory, 0o700);
    const path = join(directory, SECRET_ENV_FILENAME);
    const content = Object.entries(secrets)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => `${key}=${value}\n`)
      .join("");
    await writeFile(path, content, { mode: 0o600, flag: "wx" });

    return { directory, path };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

async function removeExistingSandbox(
  docker: DockerClient,
  name: string,
): Promise<void> {
  try {
    await docker.run(REMOVE_COMMAND, [FORCE_FLAG, VOLUMES_FLAG, name]);
  } catch (error) {
    if (error instanceof Error && NOT_FOUND_PATTERN.test(error.message)) {
      return;
    }
    throw error;
  }
}

function secretEnv(
  environment: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter(([key]) => SECRET_ENV_KEY_SET.has(key)),
  );
}

interface HealthWaitOptions {
  containerId: string;
  name: string;
  docker: DockerClient;
  runtimeHost: string;
  health: HealthProbe;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => number;
  deadline: number;
  timeoutMs: number;
  logger?: SandboxWaitLogger;
  signal?: AbortSignal;
}

async function waitForHealth(options: HealthWaitOptions): Promise<string> {
  const startedAt = options.deadline - options.timeoutMs;
  let nextLogAt = WAIT_LOG_INTERVAL_MS;
  let lastStatus = "port-unavailable";
  while (true) {
    throwIfAborted(options.signal);
    const inspection = await options.docker.inspect(options.containerId);
    if (!inspection.running) {
      throw new Error(`Sandbox ${options.name} exited before becoming healthy`);
    }

    if (inspection.hostPort !== undefined) {
      /*
       * agent -> sandbox-runtime:<hostPort> -> dind DNAT -> sandbox:8080
       *
       * Sibling sandboxes can reach published dind ports. Every sandbox API
       * route uses its own PS_ACCESS_TOKEN bearer; --icc=false only blocks
       * direct container-to-container traffic.
       */
      const origin = `http://${options.runtimeHost}:${inspection.hostPort}`;
      const healthy = options.signal
        ? await options.health(origin, options.signal)
        : await options.health(origin);
      if (healthy) {
        return origin;
      }
      lastStatus = "unhealthy";
    }

    const currentTime = options.now();
    const waitingMs = currentTime - startedAt;
    if (waitingMs >= nextLogAt) {
      options.logger?.info(
        { name: options.name, waitingMs, lastStatus },
        "Waiting for sandbox health",
      );
      nextLogAt += WAIT_LOG_INTERVAL_MS;
    }
    if (currentTime >= options.deadline) {
      throw new Error(
        `Sandbox ${options.name} did not become healthy within ${options.timeoutMs}ms`,
      );
    }

    await sleepWithAbort(options.sleep, POLL_INTERVAL_MS, options.signal);
  }
}

function hostFromDocker(dockerHost: string): string {
  const hostname = new URL(dockerHost).hostname;
  if (!hostname) {
    throw new Error(INVALID_DOCKER_HOST);
  }

  return hostname;
}

function parseHostPort(value: string): number | undefined {
  if (!value) {
    return undefined;
  }

  const hostPort = Number(value);
  if (!Number.isSafeInteger(hostPort) || hostPort <= 0) {
    return undefined;
  }

  return hostPort;
}

interface SyncWaitOptions {
  origin: string;
  name: string;
  accessToken: string;
  syncStatus: SyncStatusProbe;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => number;
  startedAt: number;
  deadline: number;
  timeoutMs: number;
  logger?: SandboxWaitLogger;
  onStatus?: (status: NonNullable<SyncProbeResult["status"]>) => void;
  signal?: AbortSignal;
}

async function waitForSync(options: SyncWaitOptions): Promise<void> {
  let nextLogAt = WAIT_LOG_INTERVAL_MS;
  while (true) {
    throwIfAborted(options.signal);
    const result = options.signal
      ? await options.syncStatus(
          options.origin,
          options.accessToken,
          options.signal,
        )
      : await options.syncStatus(options.origin, options.accessToken);
    if (result.status) {
      options.onStatus?.(result.status);
    }
    if (result.ready) {
      return;
    }

    const currentTime = options.now();
    const waitingMs = currentTime - options.startedAt;
    if (waitingMs >= nextLogAt) {
      options.logger?.info(
        {
          name: options.name,
          waitingMs,
          syncing: result.status?.syncing,
          pendingFiles: result.status?.pendingFiles,
          lastSync: result.status?.lastSync,
          errorCount: result.status?.errors?.length ?? 0,
        },
        "Waiting for sandbox sync",
      );
      nextLogAt += WAIT_LOG_INTERVAL_MS;
    }
    if (currentTime >= options.deadline) {
      throw new Error(
        `Sandbox ${options.name} did not sync within ${options.timeoutMs}ms`,
      );
    }

    await sleepWithAbort(options.sleep, POLL_INTERVAL_MS, options.signal);
  }
}

function sandboxName(spec: SandboxSpec): string {
  const suffix = `${spec.userPsId.slice(2)}-${spec.epoch}`;
  if (!NAME_PATTERN.test(suffix)) {
    throw new Error(`Invalid sandbox name: ${suffix}`);
  }

  return `ps-${suffix}`;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
