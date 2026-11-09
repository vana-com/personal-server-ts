import { recoverOwnerAddress } from "@opendatalabs/personal-server-ts-core/keys";
import { getAddress, type Address } from "viem";

export interface PsLiteOwnerBindingInput {
  ownerAddress?: Address;
  /**
   * The owner's master-key signature (personal_sign of the owner master-key
   * message). The same signature seeds the legacy and stream keys, so an
   * ownerAddress check must verify this signature, not a different message.
   */
  ownerSignature: `0x${string}`;
}

export async function resolvePsLiteOwner(
  input: PsLiteOwnerBindingInput,
): Promise<Address> {
  const recovered = await recoverOwnerAddress(input.ownerSignature);
  if (!input.ownerAddress) {
    return recovered;
  }

  const expected = getAddress(input.ownerAddress);
  if (recovered.toLowerCase() !== expected.toLowerCase()) {
    throw new Error("PS Lite owner signature does not match ownerAddress");
  }
  return expected;
}
