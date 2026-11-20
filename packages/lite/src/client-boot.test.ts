import "fake-indexeddb/auto";
import { expect, it, vi } from "vitest";
import type * as Relay from "./relay.js";
import { startPsLiteRelayClient } from "./relay.js";
import { startPersonalServer } from "./client.js";

vi.mock("./relay.js", async (original) => ({
  ...(await original<typeof Relay>()),
  startPsLiteRelayClient: vi.fn(() => ({ close: vi.fn() })),
}));
const signature =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

it.each([false, true])(
  "gates incoming relay on registration commit (stop while pending: %s)",
  async (stopBeforeCommit) => {
    vi.mocked(startPsLiteRelayClient).mockClear();
    let commit!: () => void;
    const held = new Promise<void>((resolve) => {
      commit = resolve;
    });
    let entered!: () => void;
    const submitting = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const getServer = vi.fn(async () => null);
    const registerServer = vi.fn(async () => {
      entered();
      await held;
      return { alreadyRegistered: false, serverId: "server-test" };
    });
    const ps = await startPersonalServer({
      ownerSignature: signature,
      ownerReadBeforeRegistration: true,
      configDefaults: { sync: { enabled: false } },
      gateway: { getServer, registerServer } as never,
      relay: { sessionId: "boot-test", publicSuffix: "relay.example" },
    });
    try {
      expect(startPsLiteRelayClient).not.toHaveBeenCalled();
      expect((await ps.localInfo()).registration.registered).toBe(false);
      expect(getServer).not.toHaveBeenCalled();
      const request = await ps.prepareRegistration();
      const registration = ps.submitRegistration({
        request,
        signature: "0xregistration",
      });
      await submitting;
      expect(startPsLiteRelayClient).not.toHaveBeenCalled();
      if (stopBeforeCommit) await ps.stop();
      commit();
      await registration;
      expect(startPsLiteRelayClient).toHaveBeenCalledTimes(
        stopBeforeCommit ? 0 : 1,
      );
    } finally {
      commit();
      await ps.stop();
    }
  },
);
