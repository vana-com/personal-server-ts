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
const RUNNING_FORMAT = "{{.State.Running}}";
const IP_ADDRESS_FORMAT =
  "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}";
const RUNNING_VALUE = "true";
const SYNC_TOKEN_MESSAGE = "Sandbox sync requires PS_ACCESS_TOKEN";

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
  ipAddress?: string;
}

/** DockerClient promoted from spike/sandbox launcher.ts. */
export interface DockerClient {
  run(command: string, args: string[]): Promise<string>;
  inspect(id: string): Promise<ContainerInspection>;
}

export interface DockerRuntimeOptions {
  docker?: DockerClient;
  dockerHost?: string;
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
  const docker =
    options.docker ??
    createDockerClient({
      binary: options.dockerBinary,
      host: options.dockerHost,
    });
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
      const [running, ipAddress] = await Promise.all([
        runDocker(binary, host, INSPECT_COMMAND, [
          FORMAT_FLAG,
          RUNNING_FORMAT,
          id,
        ]),
        runDocker(binary, host, INSPECT_COMMAND, [
          FORMAT_FLAG,
          IP_ADDRESS_FORMAT,
          id,
        ]),
      ]);

      return {
        running: running === RUNNING_VALUE,
        ...(ipAddress ? { ipAddress } : {}),
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

    if (inspection.ipAddress) {
      const origin = `http://${inspection.ipAddress}:${CONTAINER_PORT}`;
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
