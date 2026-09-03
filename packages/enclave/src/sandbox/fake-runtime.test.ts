import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import type { Hex } from "viem";
import {
  createFakeRuntime,
  type SpawnChild,
  type SpawnFn,
} from "./fake-runtime.js";

const USER_PS_ID = `0x${"ab".repeat(32)}` as Hex;
const PS_ENTRY = "/repo/packages/server/dist/index.js";

function fakeChild(): SpawnChild & { kill: ReturnType<typeof vi.fn> } {
  return {
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    kill: vi.fn().mockReturnValue(true),
  };
}

describe("fake sandbox runtime", () => {
  it("spawns the Personal Server with isolated sandbox environment", async () => {
    const child = fakeChild();
    const spawn = vi.fn<SpawnFn>().mockReturnValue(child);
    const health = vi.fn().mockResolvedValue(true);
    const runtime = createFakeRuntime({
      spawn,
      psEntry: PS_ENTRY,
      health,
      sleep: async () => {},
      pickPort: async () => 43_210,
    });

    const handle = await runtime.start({
      userPsId: USER_PS_ID,
      epoch: 3,
      image: "unused-in-level-a",
      env: {
        VANA_MASTER_KEY_SIGNATURE: "signature",
        PS_ACCESS_TOKEN: "token",
        PS_SERVER_ADDRESS: "address",
        PS_SERVER_PUBLIC_KEY: "public-key",
        SYNC_ENABLED: "false",
      },
    });

    const [command, args, options] = spawn.mock.calls[0] ?? [];
    expect(command).toBe(process.execPath);
    expect(args).toEqual([PS_ENTRY]);
    expect(options?.env).toEqual({
      CLOUD_MODE: "true",
      DEV_UI_ENABLED: "false",
      ENCLAVE_MODE: "true",
      PERSONAL_SERVER_ROOT_PATH: expect.stringContaining("ps-sandbox-"),
      PS_ACCESS_TOKEN: "token",
      PS_SERVER_ADDRESS: "address",
      PS_SERVER_PUBLIC_KEY: "public-key",
      SERVER_ORIGIN: handle.origin,
      SERVER_PORT: expect.any(String),
      SYNC_ENABLED: "false",
      TUNNEL_ENABLED: "false",
      VANA_MASTER_KEY_SIGNATURE: "signature",
    });
    expect(options?.stdio).toEqual(["ignore", "pipe", "pipe"]);
    expect(handle.id).toBe(`ps-${USER_PS_ID.slice(2)}-3`);
    expect(health).toHaveBeenCalledWith(handle.origin);

    await runtime.stop(handle.id);

    expect(child.kill).toHaveBeenCalledWith("SIGKILL");
    await expect(runtime.inspect(handle.id)).resolves.toEqual({
      running: false,
    });
  });

  it("polls sync unless it is disabled", async () => {
    const spawn = vi.fn<SpawnFn>().mockReturnValue(fakeChild());
    const sync = vi.fn().mockResolvedValue(true);
    const runtime = createFakeRuntime({
      spawn,
      health: async () => true,
      sync,
      sleep: async () => {},
      pickPort: async () => 43_211,
    });

    const handle = await runtime.start({
      userPsId: USER_PS_ID,
      epoch: 4,
      image: "unused",
      env: {
        PS_ACCESS_TOKEN: "token",
        SYNC_ENABLED: "true",
      },
    });

    expect(sync).toHaveBeenCalledWith(
      expect.stringMatching(/^http:\/\//),
      "token",
    );
    await runtime.stop(handle.id);
  });
});
