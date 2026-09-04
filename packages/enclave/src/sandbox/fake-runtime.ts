import { spawn as nodeSpawn } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import type { HealthProbe, SyncProbe } from "./probes.js";
import { probeHealth, probeSync } from "./probes.js";
import {
  assertSandboxEnv,
  type SandboxHandle,
  type SandboxRuntime,
  type SandboxSpec,
} from "./runtime.js";

const LOOPBACK_HOST = "127.0.0.1";
const TEMP_ROOT_PREFIX = "ps-sandbox-";
const DEFAULT_HEALTH_TIMEOUT_MS = 60_000;
const DEFAULT_SYNC_TIMEOUT_MS = 20 * 60_000;
const POLL_INTERVAL_MS = 250;
const SYNC_DISABLED = "false";
const FORCE_KILL_SIGNAL = "SIGKILL";
const NAME_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
const TRUE_VALUE = "true";
const FALSE_VALUE = "false";
const SYNC_TOKEN_MESSAGE = "Sandbox sync requires PS_ACCESS_TOKEN";
const PORT_ERROR_MESSAGE = "Unable to allocate a sandbox port";
const DEFAULT_PS_ENTRY = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../packages/server/dist/index.js",
);

export interface SpawnChild {
  stdout: Readable | null;
  stderr: Readable | null;
  kill(signal: NodeJS.Signals): boolean;
  once?(event: "exit", listener: () => void): unknown;
}

export type SpawnFn = (
  command: string,
  args: string[],
  options: {
    env: Record<string, string>;
    stdio: ["ignore", "pipe", "pipe"];
  },
) => SpawnChild;

export interface FakeRuntimeOptions {
  psEntry?: string;
  fakeRoot?: string;
  spawn?: SpawnFn;
  healthTimeoutMs?: number;
  syncTimeoutMs?: number;
  health?: HealthProbe;
  sync?: SyncProbe;
  sleep?: (milliseconds: number) => Promise<void>;
  now?: () => number;
  pickPort?: () => Promise<number>;
}

interface RunningSandbox {
  child: SpawnChild;
  root: string;
  preserveRoot: boolean;
  running: boolean;
}

export function createFakeRuntime(
  options: FakeRuntimeOptions = {},
): SandboxRuntime {
  const psEntry = options.psEntry ?? DEFAULT_PS_ENTRY;
  const spawn = options.spawn ?? spawnChild;
  const health = options.health ?? probeHealth;
  const sync = options.sync ?? probeSync;
  const sleep = options.sleep ?? delay;
  const now = options.now ?? Date.now;
  const pickPort = options.pickPort ?? freePort;
  const healthTimeoutMs = options.healthTimeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS;
  const syncTimeoutMs = options.syncTimeoutMs ?? DEFAULT_SYNC_TIMEOUT_MS;
  const configuredRoot = options.fakeRoot;
  const sandboxes = new Map<string, RunningSandbox>();

  return {
    async reconcile(): Promise<void> {
      await Promise.all(
        [...sandboxes.keys()].map((id) => stopSandbox(id, sandboxes)),
      );
    },
    async start(spec): Promise<SandboxHandle> {
      assertSandboxEnv(spec.env);

      const id = sandboxId(spec);
      const port = await pickPort();
      const origin = `http://${LOOPBACK_HOST}:${port}`;
      const preserveRoot = configuredRoot !== undefined;
      const root = preserveRoot
        ? join(configuredRoot, `${spec.userPsId}-${spec.epoch}`)
        : await mkdtemp(`${tmpdir()}/${TEMP_ROOT_PREFIX}`);
      if (preserveRoot) {
        await mkdir(root, { recursive: true });
      }
      const environment = childEnv(spec, port, origin, root);
      let child: SpawnChild;
      try {
        child = spawn(process.execPath, [psEntry], {
          env: environment,
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (error) {
        if (!preserveRoot) {
          await rm(root, { recursive: true, force: true });
        }
        throw error;
      }

      const running = { child, root, preserveRoot, running: true };
      sandboxes.set(id, running);
      child.once?.("exit", () => {
        running.running = false;
      });
      forwardOutput(id, child);

      try {
        const startedAt = now();
        await waitForHealth({
          origin,
          id,
          health,
          isRunning: () => running.running,
          sleep,
          now,
          deadline: startedAt + healthTimeoutMs,
          timeoutMs: healthTimeoutMs,
        });
        spec.onProgress?.("healthy");

        if (spec.env.SYNC_ENABLED !== SYNC_DISABLED) {
          const accessToken = spec.env.PS_ACCESS_TOKEN;
          if (!accessToken) {
            throw new Error(SYNC_TOKEN_MESSAGE);
          }

          await waitForSync({
            origin,
            id,
            accessToken,
            sync,
            sleep,
            now,
            deadline: startedAt + syncTimeoutMs,
            timeoutMs: syncTimeoutMs,
          });
        }
        spec.onProgress?.("synced");

        return { id, origin };
      } catch (error) {
        await stopSandbox(id, sandboxes);
        throw error;
      }
    },
    stop: (id) => stopSandbox(id, sandboxes),
    async inspect(id): Promise<{ running: boolean }> {
      return { running: sandboxes.get(id)?.running ?? false };
    },
  };
}

function spawnChild(
  command: string,
  args: string[],
  options: {
    env: Record<string, string>;
    stdio: ["ignore", "pipe", "pipe"];
  },
): SpawnChild {
  return nodeSpawn(command, args, options);
}

function childEnv(
  spec: SandboxSpec,
  port: number,
  origin: string,
  root: string,
): Record<string, string> {
  return {
    ...spec.env,
    CLOUD_MODE: TRUE_VALUE,
    DEV_UI_ENABLED: FALSE_VALUE,
    TUNNEL_ENABLED: FALSE_VALUE,
    ENCLAVE_MODE: TRUE_VALUE,
    PERSONAL_SERVER_ROOT_PATH: root,
    SERVER_ORIGIN: origin,
    SERVER_PORT: String(port),
  };
}

function forwardOutput(id: string, child: SpawnChild): void {
  const write = (chunk: string | Buffer): void => {
    process.stderr.write(`[${id}] ${chunk.toString()}`);
  };

  child.stdout?.on("data", write);
  child.stderr?.on("data", write);
}

async function freePort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, LOOPBACK_HOST, () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        server.close();
        reject(new Error(PORT_ERROR_MESSAGE));
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

interface HealthWaitOptions {
  origin: string;
  id: string;
  health: HealthProbe;
  isRunning: () => boolean;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => number;
  deadline: number;
  timeoutMs: number;
}

async function waitForHealth(options: HealthWaitOptions): Promise<void> {
  while (!(await options.health(options.origin))) {
    if (!options.isRunning()) {
      throw new Error(`Sandbox ${options.id} exited before becoming healthy`);
    }

    if (options.now() >= options.deadline) {
      throw new Error(
        `Sandbox ${options.id} did not become healthy within ${options.timeoutMs}ms`,
      );
    }

    await options.sleep(POLL_INTERVAL_MS);
  }
}

interface SyncWaitOptions {
  origin: string;
  id: string;
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
        `Sandbox ${options.id} did not sync within ${options.timeoutMs}ms`,
      );
    }

    await options.sleep(POLL_INTERVAL_MS);
  }
}

function sandboxId(spec: SandboxSpec): string {
  const suffix = `${spec.userPsId.slice(2)}-${spec.epoch}`;
  if (!NAME_PATTERN.test(suffix)) {
    throw new Error(`Invalid sandbox name: ${suffix}`);
  }

  return `ps-${suffix}`;
}

async function stopSandbox(
  id: string,
  sandboxes: Map<string, RunningSandbox>,
): Promise<void> {
  const sandbox = sandboxes.get(id);
  if (!sandbox) {
    return;
  }

  sandboxes.delete(id);
  if (sandbox.running) {
    sandbox.child.kill(FORCE_KILL_SIGNAL);
  }
  if (!sandbox.preserveRoot) {
    await rm(sandbox.root, { recursive: true, force: true });
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}
