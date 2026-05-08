import { describe, expect, it } from "vitest";
import {
  createMemoryPsLiteStateStore,
  loadOrCreatePsLiteConfig,
  loadOrCreatePsLiteServerIdentity,
  savePsLiteConfig,
} from "./state.js";

const OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

describe("PS Lite browser state", () => {
  it("loads default config and persists edits", async () => {
    const store = createMemoryPsLiteStateStore();

    const config = await loadOrCreatePsLiteConfig(store);
    expect(config.server.port).toBe(8080);

    const saved = await savePsLiteConfig(store, {
      ...config,
      server: { ...config.server, origin: "https://lite.example" },
    });

    expect(saved.server.origin).toBe("https://lite.example");
    await expect(loadOrCreatePsLiteConfig(store)).resolves.toMatchObject({
      server: { origin: "https://lite.example" },
    });
  });

  it("creates an encrypted browser server identity and unlocks it after reload", async () => {
    const store = createMemoryPsLiteStateStore();
    const first = await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    expect(first.persisted.encryptedPrivateKey.ciphertext).not.toContain("0x");
    const persisted = await store.get("server-identity-v1");
    expect(persisted).toMatchObject({
      address: first.account.address,
      publicKey: first.account.publicKey,
      createdAt: "2026-05-08T00:00:00.000Z",
    });

    const second = await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
    });

    expect(second.account.address).toBe(first.account.address);
    await expect(second.account.signMessage("hello")).resolves.toMatch(/^0x/);
  });

  it("rejects unlock with the wrong owner-derived key", async () => {
    const store = createMemoryPsLiteStateStore();
    await loadOrCreatePsLiteServerIdentity({
      store,
      ownerSignature: OWNER_SIGNATURE,
    });

    await expect(
      loadOrCreatePsLiteServerIdentity({
        store,
        ownerSignature: `0x${"11".repeat(65)}`,
      }),
    ).rejects.toThrow();
  });
});
