import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { ServerSigningUnavailableError } from "../errors/catalog.js";
import { createPublicOnlyAccount } from "./public-only-account.js";

const PRIVATE_KEY = `0x${"11".repeat(32)}` as const;

describe("createPublicOnlyAccount", () => {
  it("exposes identity but refuses every signing operation", async () => {
    const identity = privateKeyToAccount(PRIVATE_KEY);
    const account = createPublicOnlyAccount({
      address: identity.address,
      publicKey: identity.publicKey,
    });

    expect(account.address).toBe(identity.address);
    expect(account.publicKey).toBe(identity.publicKey);
    await expect(account.signMessage("secret")).rejects.toBeInstanceOf(
      ServerSigningUnavailableError,
    );
    await expect(
      account.signTypedData({
        domain: {},
        types: {},
        primaryType: "Never",
        message: {},
      }),
    ).rejects.toBeInstanceOf(ServerSigningUnavailableError);
  });

  it("rejects an address that does not match the public key", () => {
    const identity = privateKeyToAccount(PRIVATE_KEY);

    expect(() =>
      createPublicOnlyAccount({
        address: "0x2222222222222222222222222222222222222222",
        publicKey: identity.publicKey,
      }),
    ).toThrow("Public key does not match server address");
  });
});
