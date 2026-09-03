import { describe, expect, it, vi } from "vitest";
import type { Hex } from "viem";
import {
  createDockerRuntime,
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
  it("surfaces a bounded stderr tail when docker create fails", async () => {
    const prefix = "x".repeat(STDERR_TAIL_BYTES);
    const diagnostic = "runtime runsc-ptrace is unavailable";
    execFileMock.mockImplementationOnce(
      (_binary, _args, _options, callback) => {
        callback(
          new Error(`Command failed: docker create ${ACCESS_TOKEN}`),
          "",
          `${prefix}${ACCESS_TOKEN}${MASTER_KEY_SIGNATURE}${diagnostic}`,
        );
      },
    );
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
      command: "create",
      args: [
        "--name",
        `ps-${USER_PS_ID.slice(2)}-7`,
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
        "PS_ACCESS_TOKEN",
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
        "--env",
        "VANA_MASTER_KEY_SIGNATURE",
        IMAGE,
      ],
      env: {
        PS_ACCESS_TOKEN: ACCESS_TOKEN,
        VANA_MASTER_KEY_SIGNATURE: MASTER_KEY_SIGNATURE,
      },
    });
    expect(docker.calls[0]?.args.join(" ")).not.toContain(ACCESS_TOKEN);
    expect(docker.calls[0]?.args.join(" ")).not.toContain(MASTER_KEY_SIGNATURE);
    expect(docker.calls[0]?.args).not.toContain("--mount");
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
