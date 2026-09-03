import { execFile } from "node:child_process";
import type { HealthProbe, SyncProbe } from "./probes.js";
import { probeHealth, probeSync } from "./probes.js";
import {
  assertSandboxEnv,
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
const DEFAULT_HEALTH_TIMEOUT_MS = 60_000;
const DEFAULT_SYNC_TIMEOUT_MS = 20 * 60_000;
const POLL_INTERVAL_MS = 250;
const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const SYNC_DISABLED = "false";
const CREATE_COMMAND = "create";
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
const SYNC_TOKEN_MESSAGE = "Sandbox sync requires PS_ACCESS_TOKEN";
const INVALID_DOCKER_HOST = "DOCKER_HOST must have a hostname";

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
  run(command: string, args: string[]): Promise<string>;
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

  return {
    async start(spec): Promise<SandboxHandle> {
      assertSandboxEnv(spec.env);

      const name = sandboxName(spec);
      const environment = { ...spec.env, ...FIXED_ENV };
      const containerId = await docker.run(
        CREATE_COMMAND,
        createArgs(name, spec.image, environment),
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
    run: (command, args) => runDocker(binary, host, command, args),
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
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      [command, ...args],
      { env: { DOCKER_HOST: host } },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(stdout.trim());
      },
    );
  });
}

function createArgs(
  name: string,
  image: string,
  environment: Record<string, string>,
): string[] {
  const args = [
    "--name",
    name,
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
    args.push("--env", `${key}=${value}`);
  }
  args.push(image);

  return args;
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
