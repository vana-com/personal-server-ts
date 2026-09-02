import { describe, expect, it } from "vitest";
import { recoverMessageAddress } from "viem";
import { createFakeDstackClient } from "../dstack/fake.js";
import { FIRST_EPOCH, userPsId } from "./paths.js";
import { deriveEnclaveAccount, deriveEnclaveIdentity } from "./wallet.js";

const APP_A = "0000000000000000000000000000000000000001";
const APP_B = "0000000000000000000000000000000000000002";
const OWNER = "0x1234567890AbcdEF1234567890aBcdef12345678" as const;
const ID = userPsId(14800, OWNER);
const NEXT_EPOCH = FIRST_EPOCH + 1;
const UNCOMPRESSED_PUBKEY_HEX_LENGTH = 2 + 65 * 2;

describe("deriveEnclaveAccount", () => {
  it("same appId and path on two clients gives the same address", async () => {
    const one = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A, instanceId: "node-1" }),
      ID,
      FIRST_EPOCH,
    );
    const two = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A, instanceId: "node-2" }),
      ID,
      FIRST_EPOCH,
    );

    expect(two.address).toBe(one.address);
    expect(two.privateKey).toBe(one.privateKey);
  });

  it("different appId gives a different address", async () => {
    const a = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A }),
      ID,
      FIRST_EPOCH,
    );
    const b = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_B }),
      ID,
      FIRST_EPOCH,
    );

    expect(b.address).not.toBe(a.address);
  });

  it("different user gives a different address under one appId", async () => {
    const client = createFakeDstackClient({ appId: APP_A });
    const a = await deriveEnclaveAccount(client, ID, FIRST_EPOCH);
    const b = await deriveEnclaveAccount(
      client,
      userPsId(14801, OWNER),
      FIRST_EPOCH,
    );

    expect(b.address).not.toBe(a.address);
  });

  it("exposes an uncompressed public key and signs recoverable messages", async () => {
    const account = await deriveEnclaveAccount(
      createFakeDstackClient({ appId: APP_A }),
      ID,
      FIRST_EPOCH,
    );
    const signature = await account.signMessage("hello");

    expect(account.publicKey.startsWith("0x04")).toBe(true);
    expect(account.publicKey).toHaveLength(UNCOMPRESSED_PUBKEY_HEX_LENGTH);
    expect(await recoverMessageAddress({ message: "hello", signature })).toBe(
      account.address,
    );
  });

  it("different epoch gives a different address", async () => {
    const client = createFakeDstackClient({ appId: APP_A });
    const first = await deriveEnclaveAccount(client, ID, FIRST_EPOCH);
    const next = await deriveEnclaveAccount(client, ID, NEXT_EPOCH);

    expect(next.address).not.toBe(first.address);
  });
});

describe("deriveEnclaveIdentity", () => {
  it("matches the full account and carries no key", async () => {
    const client = createFakeDstackClient({ appId: APP_A });
    const identity = await deriveEnclaveIdentity(client, ID, FIRST_EPOCH);
    const account = await deriveEnclaveAccount(client, ID, FIRST_EPOCH);

    expect(identity.address).toBe(account.address);
    expect(identity.publicKey).toBe(account.publicKey);
    expect(identity.epoch).toBe(FIRST_EPOCH);
    expect(identity.signatureChain).toHaveLength(2);
  });
});
