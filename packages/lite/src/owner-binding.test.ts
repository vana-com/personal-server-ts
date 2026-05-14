import { describe, expect, it } from "vitest";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/browser";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import { privateKeyToAccount } from "viem/accounts";
import { resolvePsLiteOwner } from "./owner-binding.js";

const MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b" as const;

describe("PS Lite owner binding", () => {
  it("preserves legacy master-key signature recovery when no owner address is provided", async () => {
    await expect(
      resolvePsLiteOwner({ ownerSignature: MASTER_KEY_SIGNATURE }),
    ).resolves.toBe(await recoverServerOwner(MASTER_KEY_SIGNATURE));
  });

  it("verifies the SDK PS Lite owner-binding signature when owner address is provided", async () => {
    const account = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000004",
    );
    const signature = await account.signMessage({
      message: buildPersonalServerLiteOwnerBindingMessage(account.address),
    });

    await expect(
      resolvePsLiteOwner({
        ownerAddress: account.address,
        ownerSignature: signature,
      }),
    ).resolves.toBe(account.address);
  });

  it("rejects an owner-binding signature for a different owner address", async () => {
    const account = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000004",
    );
    const other = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000005",
    );
    const signature = await account.signMessage({
      message: buildPersonalServerLiteOwnerBindingMessage(account.address),
    });

    await expect(
      resolvePsLiteOwner({
        ownerAddress: other.address,
        ownerSignature: signature,
      }),
    ).rejects.toThrow("PS Lite owner signature does not match ownerAddress");
  });
});
