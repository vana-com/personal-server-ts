/**
 * The owner-key module: the only non-test source that turns the owner's
 * wallet signature into key material or into an owner address.
 *
 * Every runtime (Node server, PS-Lite, enclave, workers) imports these
 * functions. A guard test (`owner-key-single-owner.test.ts`) fails if any other
 * non-test source imports the primitives wrapped here, or writes the message.
 *
 * The owner signature is a personal_sign of `OWNER_MASTER_KEY_MESSAGE`. It
 * yields two keys:
 * - the legacy master key, the 65 raw signature bytes (`legacyMasterKey`). It
 *   seals the legacy scope keys, the PS-Lite identity and the MCP state.
 *   Do not change it: existing data depends on it.
 * - the stream master key, the same signature in one normal form (low s,
 *   v = 27/28), so every encoding of one signature gives one key
 *   (`streamMasterKey`). Every stream-sync key derives from it.
 */

import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { streamMasterKeyFromSignature } from "@opendatalabs/personal-server-ts-stream-sync";
import { recoverMessageAddress, type Address, type Hex } from "viem";

/** The message the owner signs (personal_sign). Same string as the SDK's MASTER_KEY_MESSAGE. */
export const OWNER_MASTER_KEY_MESSAGE = "vana-master-key-v1" as const;

export interface OwnerMessageSigner {
  signMessage(input: { message: string }): Promise<Hex> | Hex;
}

/** Sign the owner master-key message. Use this instead of a literal message. */
export async function signOwnerMasterKey(
  signer: OwnerMessageSigner,
): Promise<Hex> {
  return signer.signMessage({ message: OWNER_MASTER_KEY_MESSAGE });
}

/** The owner address that produced a master-key signature. */
export function recoverOwnerAddress(masterKeySignature: Hex): Promise<Address> {
  return recoverMessageAddress({
    message: OWNER_MASTER_KEY_MESSAGE,
    signature: masterKeySignature,
  });
}

/** The legacy master key: the raw 65 signature bytes. Unchanged from the SDK. */
export function legacyMasterKey(masterKeySignature: Hex): Uint8Array {
  return deriveMasterKey(masterKeySignature);
}

/**
 * The stream-sync master key. Accepts the signature as bytes or hex. Throws
 * `InvalidArgumentError` on a malformed signature.
 */
export function streamMasterKey(
  masterKeySignature: Uint8Array | string,
): Uint8Array {
  return streamMasterKeyFromSignature(masterKeySignature);
}
