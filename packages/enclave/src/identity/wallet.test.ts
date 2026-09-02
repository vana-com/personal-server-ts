import { describe, expect, it } from "vitest";
import { recoverMessageAddress } from "viem";
import { createFakeDstackClient } from "../dstack/fake.js";
import { userPsId } from "./paths.js";
import { deriveEnclaveAccount, deriveEnclaveIdentity } from "./wallet.js";

const APP_A = "app-a";
const APP_B = "app-b";
const OWNER = "0x1234567890AbcdEF1234567890aBcdef12345678" as const;
const ID = userPsId(14800, OWNER);
const UNCOMPRESSED_PUBKEY_HEX_LENGTH = 2 + 65 * 2;

describe("deriveEnclaveAccount", () => {
  it("same appId and path on two clients gives the same address", async () => {
    const one = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A, instanceId: "node-1" }),
      ID,
    );
    const two = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A, instanceId: "node-2" }),
      ID,
    );

    expect(two.address).toBe(one.address);
    expect(two.privateKey).toBe(one.privateKey);
  });

  it("different appId gives a different address", async () => {
    const a = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A }),
      ID,
    );
    const b = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_B }),
      ID,
    );

    expect(b.address).not.toBe(a.address);
  });

  it("different user gives a different address under one appId", async () => {
    const client = createFakeDstackClient({ appId: APP_A });
    const a = await deriveEnclaveAccount(client, ID);
    const b = await deriveEnclaveAccount(client, userPsId(14801, OWNER));

    expect(b.address).not.toBe(a.address);
  });

  it("exposes an uncompressed public key and signs recoverable messages", async () => {
    const account = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A }),
      ID,
    );
    const signature = await account.signMessage("hello");

    expect(account.publicKey.startsWith("0x04")).toBe(true);
    expect(account.publicKey).toHaveLength(UNCOMPRESSED_PUBKEY_HEX_LENGTH);
    expect(await recoverMessageAddress({ message: "hello", signature })).toBe(
      account.address,
    );
  });
});

describe("deriveEnclaveIdentity", () => {
  it("matches the full account and carries no key", async () => {
    const client = createFakeDstackClient({ appId: APP_A });
    const identity = await deriveEnclaveIdentity(client, ID);
    const account = await deriveEnclaveAccount(client, ID);

    expect(identity.address).toBe(account.address);
    expect(identity.publicKey).toBe(account.publicKey);
    expect(identity.signatureChain).toHaveLength(2);
  });
});
