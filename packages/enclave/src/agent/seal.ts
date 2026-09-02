import { createHash } from "node:crypto";
import type {
  MASTER_SIGNATURE_DELIVERY_VERSION,
  MasterSignatureDelivery,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { getAddress, hexToBytes, recoverMessageAddress, toHex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { FIRST_EPOCH, userPsId } from "../identity/paths.js";
import { deriveEnclaveAccount } from "../identity/wallet.js";
import { seal } from "../sealing/envelope.js";
import { decryptEcies } from "./ecies.js";
import {
  DeliveryInvalid,
  EnclaveAddressMismatch,
  EpochRetired,
  OwnerMismatch,
  StaleDelivery,
} from "./errors.js";
import type { SealRequestBody, SealResult } from "./types.js";

/** = SDK crypto/keys/derive.ts MASTER_KEY_MESSAGE. */
export const MASTER_KEY_MESSAGE = "vana-master-key-v1";

const MAX_DELIVERY_AGE_SECONDS = 600;
const SIGNATURE_BYTES = 65;
const HASH_ALGORITHM = "sha256";
const DELIVERY_VERSION =
  "vana.ps-enclave.delivery.v1" satisfies typeof MASTER_SIGNATURE_DELIVERY_VERSION;

export async function sealDelivery(
  client: DstackClient,
  request: SealRequestBody,
): Promise<SealResult> {
  const minEpoch = request.minEpoch ?? FIRST_EPOCH;
  // V1 has no store: retired means below the minimum epoch supplied by Gateway.
  if (request.epoch < minEpoch) {
    throw new EpochRetired();
  }

  const id = userPsId(request.chainId, request.ownerAddress);
  const account = await deriveEnclaveAccount(client, id, request.epoch);
  if (getAddress(account.address) !== getAddress(request.enclaveAddress)) {
    account.privateKey = "0x";
    throw new EnclaveAddressMismatch();
  }

  const privateKey = hexToBytes(account.privateKey);
  account.privateKey = "0x";
  let plaintext: Uint8Array;
  try {
    plaintext = decryptEcies(privateKey, hexToBytes(request.ciphertext));
  } catch {
    throw new DeliveryInvalid();
  } finally {
    privateKey.fill(0);
  }

  let delivery: MasterSignatureDelivery;
  try {
    delivery = JSON.parse(
      new TextDecoder().decode(plaintext),
    ) as unknown as MasterSignatureDelivery;
  } catch {
    plaintext.fill(0);
    throw new DeliveryInvalid();
  }
  plaintext.fill(0);

  validateDelivery(delivery, request, id, account.address);
  if (getAddress(delivery.ownerAddress) !== getAddress(request.ownerAddress)) {
    throw new OwnerMismatch();
  }

  let recoveredOwner: `0x${string}`;
  try {
    recoveredOwner = await recoverMessageAddress({
      message: MASTER_KEY_MESSAGE,
      signature: delivery.masterSignature,
    });
  } catch {
    throw new DeliveryInvalid();
  }

  if (getAddress(recoveredOwner) !== getAddress(request.ownerAddress)) {
    throw new OwnerMismatch();
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = hexToBytes(delivery.masterSignature);
  } catch {
    throw new DeliveryInvalid();
  }
  if (signatureBytes.length !== SIGNATURE_BYTES) {
    signatureBytes.fill(0);
    throw new DeliveryInvalid();
  }

  try {
    const envelope = await seal(client, id, request.epoch, signatureBytes);
    const secretHash = toHex(
      createHash(HASH_ALGORITHM)
        .update(hexToBytes(request.ciphertext))
        .digest(),
    );

    return { envelope, secretHash };
  } finally {
    signatureBytes.fill(0);
  }
}

function validateDelivery(
  delivery: MasterSignatureDelivery,
  request: SealRequestBody,
  id: `0x${string}`,
  accountAddress: `0x${string}`,
): void {
  try {
    getAddress(delivery.ownerAddress);
    if (
      delivery.v !== DELIVERY_VERSION ||
      delivery.userPsId !== id ||
      delivery.epoch !== request.epoch ||
      getAddress(delivery.enclaveAddress) !== getAddress(accountAddress) ||
      !Number.isInteger(delivery.issuedAt) ||
      typeof delivery.masterSignature !== "string"
    ) {
      throw new DeliveryInvalid();
    }
  } catch (error) {
    if (error instanceof DeliveryInvalid) {
      throw error;
    }
    throw new DeliveryInvalid();
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - delivery.issuedAt) > MAX_DELIVERY_AGE_SECONDS) {
    throw new StaleDelivery();
  }
}
