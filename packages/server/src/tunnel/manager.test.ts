import { EventEmitter } from "node:events";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type * as ChildProcess from "node:child_process";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createTestWallet } from "@opendatalabs/personal-server-ts-core/test-utils";
import { loadOrCreateServerAccount } from "../keys/server-account.js";
import { TunnelManager } from "./manager.js";

const spawnMock = vi.hoisted(() => vi.fn());

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof ChildProcess>();
  return {
    ...actual,
    spawn: spawnMock,
  };
});

class FakeChildProcess extends EventEmitter {
  stdout = new EventEmitter();
  stderr = new EventEmitter();
  kill = vi.fn();
}

describe("tunnel/manager", () => {
  describe("TunnelManager", () => {
    let manager: TunnelManager;
    let tempDir: string;

    beforeEach(async () => {
      tempDir = await mkdtemp(join(tmpdir(), "test-tunnel-"));
      manager = new TunnelManager(tempDir);
      spawnMock.mockReset();
    });

    afterEach(async () => {
      await rm(tempDir, { recursive: true, force: true });
    });

    it("initial status is stopped", () => {
      const status = manager.getStatus();
      expect(status.status).toBe("stopped");
      expect(status.enabled).toBe(true);
      expect(status.publicUrl).toBeNull();
      expect(status.connectedSince).toBeNull();
      expect(status.routable).toBeUndefined();
    });

    it("isRunning returns false when stopped", () => {
      expect(manager.isRunning()).toBe(false);
    });

    it("getPublicUrl returns null when not connected", () => {
      expect(manager.getPublicUrl()).toBeNull();
    });

    it("stop() is safe to call when already stopped", async () => {
      await expect(manager.stop()).resolves.toBeUndefined();
    });

    describe("setVerified", () => {
      it("sets status to connected when reachable", () => {
        manager.setVerified(true);
        const status = manager.getStatus();
        expect(status.status).toBe("stopped");
        expect(status.routable).toBe(true);
        expect(status.warning).toBeUndefined();
        expect(status.error).toBeUndefined();
      });

      it("sets routing warning when not reachable without changing process status", () => {
        manager.setVerified(false, "connection refused");
        const status = manager.getStatus();
        expect(status.status).toBe("stopped");
        expect(status.routable).toBe(false);
        expect(status.warning).toBe("connection refused");
        expect(status.error).toBeUndefined();
      });

      it("uses default error message when not reachable and no reason given", () => {
        manager.setVerified(false);
        const status = manager.getStatus();
        expect(status.routable).toBe(false);
        expect(status.warning).toBe("Tunnel URL not reachable");
      });

      it("clears previous routing warning when verified as reachable", () => {
        manager.setVerified(false, "some error");
        manager.setVerified(true);
        const status = manager.getStatus();
        expect(status.routable).toBe(true);
        expect(status.warning).toBeUndefined();
      });
    });

    describe("start", () => {
      async function createExecutable(): Promise<string> {
        const binaryPath = join(tempDir, "frpc");
        await writeFile(binaryPath, "#!/bin/sh\n");
        await chmod(binaryPath, 0o755);
        return binaryPath;
      }

      async function createStartConfig() {
        const owner = createTestWallet(0);
        const serverKeypair = loadOrCreateServerAccount(
          join(tempDir, "key.json"),
        );
        return {
          walletAddress: serverKeypair.address,
          ownerAddress: owner.address,
          serverKeypair,
          runId: "run-1",
          serverAddr: "frpc.server.vana.org",
          serverPort: 7000,
          localPort: 8080,
        };
      }

      it("keeps frpc alive when startup reports a retryable registration failure", async () => {
        const proc = new FakeChildProcess();
        spawnMock.mockReturnValue(proc);

        const start = manager.start(
          await createStartConfig(),
          await createExecutable(),
        );
        await vi.waitFor(() => expect(spawnMock).toHaveBeenCalled());
        proc.stderr.emit(
          "data",
          Buffer.from("start error: Signer is not a registered server\n"),
        );

        const publicUrl = await start;
        expect(publicUrl).toMatch(
          /^https:\/\/0x[0-9a-f]{40}\.server\.vana\.org$/,
        );
        expect(proc.kill).not.toHaveBeenCalled();
        expect(manager.getStatus()).toMatchObject({
          status: "starting",
          publicUrl,
          warning: expect.stringContaining("Signer is not a registered server"),
        });

        proc.stdout.emit("data", Buffer.from("start proxy success\n"));
        expect(manager.getStatus()).toMatchObject({
          status: "connected",
          publicUrl,
          warning: undefined,
        });
      });
    });
  });
});
