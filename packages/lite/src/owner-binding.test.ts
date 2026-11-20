import { describe, expect, it } from "vitest";
import {
  legacyMasterKey,
  recoverOwnerAddress,
  signOwnerMasterKey,
  streamMasterKey,
} from "@opendatalabs/personal-server-ts-core/keys";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import { hexToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { resolvePsLiteOwner } from "./owner-binding.js";

const MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

const ACCOUNT_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000004" as const;
const OTHER_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000005" as const;

describe("PS Lite owner binding", () => {
  it("preserves legacy master-key signature recovery when no owner address is provided", async () => {
    await expect(
      resolvePsLiteOwner({ ownerSignature: MASTER_KEY_SIGNATURE }),
    ).resolves.toBe(await recoverOwnerAddress(MASTER_KEY_SIGNATURE));
  });

  it("verifies the owner master-key signature when owner address is provided", async () => {
    const account = privateKeyToAccount(ACCOUNT_KEY);
    const signature = await signOwnerMasterKey(account);

    await expect(
      resolvePsLiteOwner({
        ownerAddress: account.address,
        ownerSignature: signature,
      }),
    ).resolves.toBe(account.address);
  });

  it("derives the keys from the same signature that proves ownerAddress", async () => {
    const account = privateKeyToAccount(ACCOUNT_KEY);
    const signature = await signOwnerMasterKey(account);

    // The owner that the ownerAddress path accepts is the owner the signature
    // recovers to, so the keys the runtime derives belong to that owner.
    await expect(
      resolvePsLiteOwner({
        ownerAddress: account.address,
        ownerSignature: signature,
      }),
    ).resolves.toBe(await recoverOwnerAddress(signature));

    // Legacy key: the raw 65 signature bytes (SDK deriveMasterKey, unchanged).
    expect(legacyMasterKey(signature)).toEqual(hexToBytes(signature));
    // Stream key: one key for every encoding of the signature. v = 0/1 and
    // v = 27/28 are the same signature, so they give the same stream key.
    const lowV =
      `${signature.slice(0, -2)}${signature.endsWith("1b") ? "00" : "01"}` as const;
    expect(streamMasterKey(lowV)).toEqual(streamMasterKey(signature));
  });

  it("rejects an owner-binding signature over the SDK owner-binding message", async () => {
    const account = privateKeyToAccount(ACCOUNT_KEY);
    const bindingSignature = await account.signMessage({
      message: buildPersonalServerLiteOwnerBindingMessage(account.address),
    });

    await expect(
      resolvePsLiteOwner({
        ownerAddress: account.address,
        ownerSignature: bindingSignature,
      }),
    ).rejects.toThrow("PS Lite owner signature does not match ownerAddress");
  });

  it("rejects an owner master-key signature for a different owner address", async () => {
    const account = privateKeyToAccount(ACCOUNT_KEY);
    const other = privateKeyToAccount(OTHER_KEY);
    const signature = await signOwnerMasterKey(account);

    await expect(
      resolvePsLiteOwner({
        ownerAddress: other.address,
        ownerSignature: signature,
      }),
    ).rejects.toThrow("PS Lite owner signature does not match ownerAddress");
  });
});
