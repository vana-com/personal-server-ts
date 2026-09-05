import { describe, expect, it, vi } from "vitest";
import type { Hex } from "viem";
import { access, readFile, stat } from "node:fs/promises";
import {
  createDockerRuntime,
  isNonTransientDockerSandboxError,
  type ContainerInspection,
  type DockerClient,
} from "./docker-runtime.js";
import type { SandboxSpec } from "./runtime.js";

const USER_PS_ID = `0x${"12".repeat(32)}` as Hex;
const ACCESS_TOKEN = "access-token";
const MASTER_KEY_SIGNATURE = `0x${"11".repeat(65)}`;
const IMAGE = "example/personal-server@sha256:digest";
const STDERR_TAIL_BYTES = 2_048;

const { execFileMock } = vi.hoisted(() => ({ execFileMock: vi.fn() }));

vi.mock("node:child_process", () => ({ execFile: execFileMock }));

function sandboxSpec(env: Record<string, string> = {}): SandboxSpec {
  return {
    userPsId: USER_PS_ID,
    epoch: 7,
    image: IMAGE,
    env: {
      VANA_MASTER_KEY_SIGNATURE: MASTER_KEY_SIGNATURE,
      PS_ACCESS_TOKEN: ACCESS_TOKEN,
      PS_SERVER_ADDRESS: `0x${"22".repeat(20)}`,
      PS_SERVER_PUBLIC_KEY: `0x${"33".repeat(33)}`,
      SYNC_ENABLED: "false",
      ...env,
    },
  };
}

function scriptedDocker(
  inspections: ContainerInspection[] = [{ running: true, hostPort: 49_152 }],
): DockerClient & {
  calls: Array<{
    command: string;
    args: string[];
    env?: Record<string, string>;
  }>;
} {
  const calls: Array<{
    command: string;
    args: string[];
    env?: Record<string, string>;
  }> = [];

  return {
    calls,
    async run(command, args, env?: Record<string, string>) {
      calls.push({ command, args, ...(env ? { env } : {}) });
      if (command === "create") return "container-id";

      return "";
    },
    async inspect() {
      return inspections.shift() ?? { running: false };
    },
  };
}

describe("docker sandbox runtime", () => {
  it.each([
    "range of CPUs is from 0.01 to 1.00",
    "No such image: personal-server@sha256:missing",
    "unknown runtime specified: runsc-ptrace",
  ])("classifies permanent create failure: %s", (diagnostic) => {
    expect(
      isNonTransientDockerSandboxError(
        new Error(`Docker create failed: ${diagnostic}`),
      ),
    ).toBe(true);
  });

  it.each(["daemon is busy", "network timeout"])(
    "leaves transient create failure retryable: %s",
    (diagnostic) => {
      expect(
        isNonTransientDockerSandboxError(
          new Error(`Docker create failed: ${diagnostic}`),
        ),
      ).toBe(false);
    },
  );

  it("surfaces a bounded stderr tail when docker create fails", async () => {
    const prefix = "x".repeat(STDERR_TAIL_BYTES);
    const diagnostic = "runtime runsc-ptrace is unavailable";
    execFileMock
      .mockImplementationOnce((_binary, _args, _options, callback) => {
        callback(new Error("No such container"), "", "No such container");
      })
      .mockImplementationOnce((_binary, _args, _options, callback) => {
        callback(
          new Error(`Command failed: docker create ${ACCESS_TOKEN}`),
          "",
          `${prefix}${ACCESS_TOKEN}${MASTER_KEY_SIGNATURE}${diagnostic}`,
        );
      });
    const runtime = createDockerRuntime();

    const error = await runtime.start(sandboxSpec()).catch((cause) => cause);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).toContain(diagnostic);
    expect((error as Error).message).not.toContain(prefix);
    expect((error as Error).message).not.toContain(ACCESS_TOKEN);
    expect((error as Error).message).not.toContain(MASTER_KEY_SIGNATURE);
    expect((error as Error).cause).toMatchObject({
      message: "Command failed: docker create [REDACTED]",
    });
  });

  it("creates an exactly hardened gVisor container", async () => {
    const docker = scriptedDocker();
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
      sleep: async () => {},
    });

    await runtime.start(sandboxSpec());

    expect(docker.calls[0]).toEqual({
      command: "rm",
      args: ["--force", "--volumes", `ps-${USER_PS_ID.slice(2)}-7`],
    });
    expect(docker.calls[1]).toEqual({
      command: "create",
      args: [
        "--name",
        `ps-${USER_PS_ID.slice(2)}-7`,
        "--label",
        "org.vana.personal-server.sandbox=true",
        "--memory",
        "512m",
        "--cpus",
        "2",
        "--pids-limit",
        "256",
        "--runtime",
        "runsc-ptrace",
        "--user",
        "1000:1000",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--tmpfs",
        "/data:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700",
        "--publish",
        "0:8080",
        "--env",
        "CLOUD_MODE=true",
        "--env",
        "DEV_UI_ENABLED=false",
        "--env",
        "ENCLAVE_MODE=true",
        "--env",
        "PERSONAL_SERVER_ROOT_PATH=/data",
        "--env",
        `PS_SERVER_ADDRESS=0x${"22".repeat(20)}`,
        "--env",
        `PS_SERVER_PUBLIC_KEY=0x${"33".repeat(33)}`,
        "--env",
        "SERVER_ORIGIN=http://localhost:8080",
        "--env",
        "SYNC_ENABLED=false",
        "--env",
        "TUNNEL_ENABLED=false",
        "--env-file",
        expect.stringMatching(/ps-docker-env-.*\/sandbox\.env$/),
        IMAGE,
      ],
    });
    expect(docker.calls[1]?.args.join(" ")).not.toContain(ACCESS_TOKEN);
    expect(docker.calls[1]?.args.join(" ")).not.toContain(MASTER_KEY_SIGNATURE);
    expect(docker.calls[1]?.args).not.toContain("--mount");
  });

  it("applies configured sandbox resource limits", async () => {
    const docker = scriptedDocker();
    const runtime = createDockerRuntime({
      docker,
      memory: "768m",
      cpus: "1.5",
      pidsLimit: 128,
      health: async () => true,
    });

    await runtime.start(sandboxSpec());

    expect(docker.calls[1]?.args).toEqual(
      expect.arrayContaining([
        "--memory",
        "768m",
        "--cpus",
        "1.5",
        "--pids-limit",
        "128",
      ]),
    );
  });

  it("passes sandbox secrets through a private temporary env file", async () => {
    let envFilePath = "";
    let envFileContent = "";
    let envFileMode = 0;
    let createArgs: string[] = [];
    let createEnv: Record<string, string> | undefined;
    const docker: DockerClient = {
      async run(command, args, env) {
        if (command === "create") {
          createArgs = args;
          createEnv = env;
          const envFileIndex = args.indexOf("--env-file");
          expect(envFileIndex).toBeGreaterThan(-1);
          envFilePath = args[envFileIndex + 1] ?? "";
          envFileContent = await readFile(envFilePath, "utf8");
          envFileMode = (await stat(envFilePath)).mode & 0o777;

          return "container-id";
        }

        return "";
      },
      async inspect() {
        return { running: true, hostPort: 49_152 };
      },
    };
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
    });

    await runtime.start(
      sandboxSpec({ VERCEL_PROTECTION_BYPASS: "preview-secret" }),
    );

    expect(envFileMode).toBe(0o600);
    expect(envFileContent.split("\n").filter(Boolean).sort()).toEqual(
      [
        `PS_ACCESS_TOKEN=${ACCESS_TOKEN}`,
        `VANA_MASTER_KEY_SIGNATURE=${MASTER_KEY_SIGNATURE}`,
        "VERCEL_PROTECTION_BYPASS=preview-secret",
      ].sort(),
    );
    expect(createArgs.join(" ")).not.toContain("preview-secret");
    expect(createArgs.join(" ")).not.toContain(ACCESS_TOKEN);
    expect(createArgs.join(" ")).not.toContain(MASTER_KEY_SIGNATURE);
    expect(createEnv).toBeUndefined();
    await expect(access(envFilePath)).rejects.toThrow();
  });

  it("removes every labeled sandbox during boot reconciliation", async () => {
    const docker = scriptedDocker();
    docker.run = vi
      .fn()
      .mockResolvedValueOnce("orphan-1\norphan-2")
      .mockResolvedValue("");
    const runtime = createDockerRuntime({ docker });

    await runtime.reconcile();

    expect(docker.run).toHaveBeenNthCalledWith(1, "ps", [
      "--all",
      "--quiet",
      "--filter",
      "name=^/ps-",
    ]);
    expect(docker.run).toHaveBeenNthCalledWith(2, "rm", [
      "--force",
      "--volumes",
      "orphan-1",
      "orphan-2",
    ]);
  });

  it("reads a bounded tail through docker logs", async () => {
    const docker = scriptedDocker();
    docker.run = vi.fn().mockResolvedValue("sandbox output");
    const runtime = createDockerRuntime({ docker });

    await expect(runtime.logs?.("container-id", 500)).resolves.toBe(
      "sandbox output",
    );
    expect(docker.run).toHaveBeenCalledWith("logs", [
      "--tail",
      "500",
      "container-id",
    ]);
  });

  it("inspects container exit state with one docker call", async () => {
    execFileMock.mockClear();
    execFileMock.mockImplementationOnce((_binary, args, _options, callback) => {
      expect(args).toEqual(["inspect", "container-id"]);
      callback(
        null,
        JSON.stringify([
          {
            State: {
              Running: false,
              ExitCode: 137,
              OOMKilled: true,
              FinishedAt: "2026-09-04T12:01:00.000Z",
            },
            NetworkSettings: { Ports: { "8080/tcp": null } },
          },
        ]),
        "",
      );
    });
    const runtime = createDockerRuntime();

    await expect(runtime.inspect("container-id")).resolves.toEqual({
      running: false,
      exitCode: 137,
      oomKilled: true,
      finishedAt: "2026-09-04T12:01:00.000Z",
    });
    expect(execFileMock).toHaveBeenCalledOnce();
  });

  it("returns both stdout and stderr from docker logs", async () => {
    execFileMock.mockImplementationOnce((_binary, _args, _options, callback) =>
      callback(null, "stdout line\n", "stderr line\n"),
    );
    const runtime = createDockerRuntime();

    await expect(runtime.logs?.("container-id", 100)).resolves.toBe(
      "stdout line\nstderr line",
    );
  });

  it("waits for the mapped port and uses the runtime host", async () => {
    const docker = scriptedDocker([
      { running: true },
      { running: true, hostPort: 49_153 },
    ]);
    const health = vi.fn().mockResolvedValue(true);
    const sleep = vi.fn().mockResolvedValue(undefined);
    const runtime = createDockerRuntime({
      docker,
      dockerHost: "tcp://runtime.internal:2375",
      health,
      sleep,
    });

    const handle = await runtime.start(sandboxSpec());

    expect(sleep).toHaveBeenCalledOnce();
    expect(health).toHaveBeenCalledOnce();
    expect(health).toHaveBeenCalledWith("http://runtime.internal:49153");
    expect(handle.origin).toBe("http://runtime.internal:49153");
  });

  it("allows two minutes for concurrent cold starts by default", async () => {
    const docker = scriptedDocker([
      { running: true, hostPort: 49_153 },
      { running: true, hostPort: 49_153 },
    ]);
    const health = vi.fn().mockResolvedValueOnce(false).mockResolvedValue(true);
    const sleep = vi.fn().mockResolvedValue(undefined);
    const now = vi.fn().mockReturnValueOnce(0).mockReturnValue(60_000);
    const runtime = createDockerRuntime({ docker, health, sleep, now });

    await expect(runtime.start(sandboxSpec())).resolves.toMatchObject({
      id: "container-id",
    });
    expect(health).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledOnce();
  });

  it("logs the latest health status every 30 seconds while waiting", async () => {
    vi.useFakeTimers();
    const docker = scriptedDocker();
    docker.inspect = vi.fn().mockResolvedValue({
      running: true,
      hostPort: 49_152,
    });
    const health = vi.fn().mockResolvedValue(false);
    const logger = { info: vi.fn() };
    const runtime = createDockerRuntime({
      docker,
      health,
      logger,
      healthTimeoutMs: 31_000,
    });

    const starting = runtime.start(sandboxSpec());
    const outcome = starting.catch((error: unknown) => error);
    await vi.waitFor(() => expect(health).toHaveBeenCalledOnce());
    await vi.advanceTimersByTimeAsync(30_000);

    expect(logger.info).toHaveBeenCalledWith(
      {
        name: `ps-${USER_PS_ID.slice(2)}-7`,
        waitingMs: 30_000,
        lastStatus: "unhealthy",
      },
      "Waiting for sandbox health",
    );

    await vi.advanceTimersByTimeAsync(1_250);
    await expect(outcome).resolves.toMatchObject({
      message: expect.stringContaining("did not become healthy within 31000ms"),
    });
  });

  it("aborts a health wait and removes the container", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const docker = scriptedDocker();
    docker.inspect = vi.fn().mockResolvedValue({
      running: true,
      hostPort: 49_152,
    });
    const health = vi.fn().mockResolvedValue(false);
    const runtime = createDockerRuntime({
      docker,
      health,
      healthTimeoutMs: 1_000,
    });

    const outcome = runtime
      .start(sandboxSpec(), controller.signal)
      .catch((error: unknown) => error);
    await vi.waitFor(() => expect(health).toHaveBeenCalledOnce());
    controller.abort();
    await vi.advanceTimersByTimeAsync(1_000);

    await expect(outcome).resolves.toMatchObject({ name: "AbortError" });
    expect(docker.calls.at(-1)).toEqual({
      command: "rm",
      args: ["--force", "--volumes", "container-id"],
    });
  });

  it("removes a container that exits before health", async () => {
    const docker = scriptedDocker([{ running: false }]);
    const runtime = createDockerRuntime({
      docker,
      health: async () => false,
      sleep: async () => {},
    });

    await expect(runtime.start(sandboxSpec())).rejects.toThrow(
      "exited before becoming healthy",
    );
    expect(docker.calls.at(-1)).toEqual({
      command: "rm",
      args: ["--force", "--volumes", "container-id"],
    });
  });

  it("removes the container when sync reports errors", async () => {
    const docker = scriptedDocker();
    const sync = vi.fn().mockRejectedValue(new Error("Sandbox sync failed"));
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
      sync,
      sleep: async () => {},
    });

    await expect(
      runtime.start(sandboxSpec({ SYNC_ENABLED: "true" })),
    ).rejects.toThrow("Sandbox sync failed");
    expect(docker.calls.at(-1)?.command).toBe("rm");
  });

  it("aborts a sync wait and removes the container", async () => {
    vi.useFakeTimers();
    const controller = new AbortController();
    const docker = scriptedDocker();
    const syncStatus = vi.fn().mockResolvedValue({ ready: false });
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
      syncStatus,
    });

    const outcome = runtime
      .start(sandboxSpec({ SYNC_ENABLED: "true" }), controller.signal)
      .catch((error: unknown) => error);
    await vi.waitFor(() => expect(syncStatus).toHaveBeenCalledOnce());
    controller.abort();
    await vi.advanceTimersByTimeAsync(250);

    await expect(outcome).resolves.toMatchObject({ name: "AbortError" });
    expect(docker.calls.at(-1)).toEqual({
      command: "rm",
      args: ["--force", "--volumes", "container-id"],
    });
  });

  it("logs the latest sync status every 30 seconds while waiting", async () => {
    vi.useFakeTimers();
    const docker = scriptedDocker();
    const logger = { info: vi.fn() };
    const status = {
      syncing: true,
      pendingFiles: 4,
      lastSync: null,
      errors: [],
    };
    let ready = false;
    const syncStatus = vi.fn(async () => ({
      ready,
      status,
    }));
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
      logger,
      syncStatus,
    });

    const starting = runtime.start(sandboxSpec({ SYNC_ENABLED: "true" }));
    await vi.waitFor(() => expect(syncStatus).toHaveBeenCalledOnce());
    await vi.advanceTimersByTimeAsync(30_000);

    expect(logger.info).toHaveBeenCalledWith(
      {
        name: `ps-${USER_PS_ID.slice(2)}-7`,
        waitingMs: 30_000,
        syncing: true,
        pendingFiles: 4,
        lastSync: null,
        errorCount: 0,
      },
      "Waiting for sandbox sync",
    );

    ready = true;
    await vi.advanceTimersByTimeAsync(250);
    await starting;
  });

  it("skips sync when explicitly disabled", async () => {
    const docker = scriptedDocker();
    const sync = vi.fn();
    const runtime = createDockerRuntime({
      docker,
      health: async () => true,
      sync,
      sleep: async () => {},
    });

    await runtime.start(sandboxSpec());

    expect(sync).not.toHaveBeenCalled();
  });

  it("rejects environment keys outside the sandbox allowlist", async () => {
    const runtime = createDockerRuntime({ docker: scriptedDocker() });

    await expect(
      runtime.start(sandboxSpec({ DATABASE_URL: "secret" })),
    ).rejects.toThrow("Unknown sandbox environment key: DATABASE_URL");
  });
});
