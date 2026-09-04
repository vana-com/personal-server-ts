import { execFile } from "node:child_process";
import type { HealthProbe, SyncProbe } from "./probes.js";
import { probeHealth, probeSync } from "./probes.js";
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
const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const SYNC_DISABLED = "false";
const CREATE_COMMAND = "create";
const LIST_COMMAND = "ps";
const START_COMMAND = "start";
const INSPECT_COMMAND = "inspect";
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
const SANDBOX_LABEL = "org.vana.personal-server.sandbox=true";
const SANDBOX_NAME_FILTER = "name=^/ps-";
const NOT_FOUND_PATTERN = /No such container/i;
const SYNC_TOKEN_MESSAGE = "Sandbox sync requires PS_ACCESS_TOKEN";
const INVALID_DOCKER_HOST = "DOCKER_HOST must have a hostname";
const STDERR_TAIL_LENGTH = 2_048;
const SECRET_ENV_KEY_SET = new Set<string>(SECRET_ENV_KEYS);

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
  sleep?: (milliseconds: number) => Promise<void>;
  now?: () => number;
  memory?: string;
  cpus?: string;
  pidsLimit?: number;
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
  const sync = options.sync ?? probeSync;
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
    async start(spec): Promise<SandboxHandle> {
      assertSandboxEnv(spec.env);

      const name = sandboxName(spec);
      const environment = { ...spec.env, ...FIXED_ENV };
      await removeExistingSandbox(docker, name);
      const containerId = await docker.run(
        CREATE_COMMAND,
        createArgs(name, spec.image, environment, memory, cpus, pidsLimit),
        secretEnv(environment),
      );

      try {
        await docker.run(START_COMMAND, [containerId]);
        const startedAt = now();
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
        });

        if (spec.env.SYNC_ENABLED !== SYNC_DISABLED) {
          const accessToken = spec.env.PS_ACCESS_TOKEN;
          if (!accessToken) {
            throw new Error(SYNC_TOKEN_MESSAGE);
          }

          await waitForSync({
            origin,
            name,
            accessToken,
            sync,
            sleep,
            now,
            deadline: startedAt + syncTimeoutMs,
            timeoutMs: syncTimeoutMs,
          });
        }

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
    run: (command, args, env) => runDocker(binary, host, command, args, env),
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
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      [command, ...args],
      { env: { ...env, DOCKER_HOST: host } },
      (error, stdout, stderr) => {
        if (error) {
          reject(dockerCommandError(command, error, stderr, env));
          return;
        }

        resolve(stdout.trim());
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
    args.push("--env", SECRET_ENV_KEY_SET.has(key) ? key : `${key}=${value}`);
  }
  args.push(image);

  return args;
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
}

async function waitForHealth(options: HealthWaitOptions): Promise<string> {
  while (true) {
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
      if (await options.health(origin)) {
        return origin;
      }
    }

    if (options.now() >= options.deadline) {
      throw new Error(
        `Sandbox ${options.name} did not become healthy within ${options.timeoutMs}ms`,
      );
    }

    await options.sleep(POLL_INTERVAL_MS);
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
  sync: SyncProbe;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => number;
  deadline: number;
  timeoutMs: number;
}

async function waitForSync(options: SyncWaitOptions): Promise<void> {
  while (!(await options.sync(options.origin, options.accessToken))) {
    if (options.now() >= options.deadline) {
      throw new Error(
        `Sandbox ${options.name} did not sync within ${options.timeoutMs}ms`,
      );
    }

    await options.sleep(POLL_INTERVAL_MS);
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
