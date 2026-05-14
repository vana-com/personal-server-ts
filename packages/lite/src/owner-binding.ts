import { recoverServerOwner } from "@opendatalabs/vana-sdk/browser";
import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
import { getAddress, recoverMessageAddress, type Address } from "viem";

export interface PsLiteOwnerBindingInput {
  ownerAddress?: Address;
  ownerSignature: `0x${string}`;
}

export async function resolvePsLiteOwner(
  input: PsLiteOwnerBindingInput,
): Promise<Address> {
  if (!input.ownerAddress) {
    return recoverServerOwner(input.ownerSignature);
  }

  const expected = getAddress(input.ownerAddress);
  const recovered = await recoverMessageAddress({
    message: buildPersonalServerLiteOwnerBindingMessage(expected),
    signature: input.ownerSignature,
  });
  if (recovered.toLowerCase() !== expected.toLowerCase()) {
    throw new Error("PS Lite owner signature does not match ownerAddress");
  }
  return expected;
}
