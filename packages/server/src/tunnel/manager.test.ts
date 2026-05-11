import { describe, it, expect, beforeEach } from "vitest";
import { TunnelManager } from "./manager.js";

describe("tunnel/manager", () => {
  describe("TunnelManager", () => {
    let manager: TunnelManager;

    beforeEach(() => {
      manager = new TunnelManager("/tmp/test-tunnel");
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
  });
});
