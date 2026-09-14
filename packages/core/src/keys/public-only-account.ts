import { isAddressEqual, type Address, type Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { ServerSigningUnavailableError } from "../errors/catalog.js";
import type { ServerAccount } from "./server-account.js";

const KEY_MISMATCH_MESSAGE = "Public key does not match server address";

export interface PublicOnlyAccountInput {
  address: Address;
  publicKey: Hex;
}

export function createPublicOnlyAccount(
  input: PublicOnlyAccountInput,
): ServerAccount {
  const derivedAddress = publicKeyToAddress(input.publicKey);
  if (!isAddressEqual(derivedAddress, input.address)) {
    throw new Error(KEY_MISMATCH_MESSAGE);
  }

  return {
    address: input.address,
    publicKey: input.publicKey,
    async signTypedData(): Promise<Hex> {
      throw new ServerSigningUnavailableError();
    },
    async signMessage(): Promise<Hex> {
      throw new ServerSigningUnavailableError();
    },
  };
}
