import { secp256k1 } from "@noble/curves/secp256k1";
import {
  concat,
  hexToBytes,
  keccak256,
  recoverPublicKey,
  toBytes,
  toHex,
  type Hex,
} from "viem";
import type { DstackClient } from "../dstack/client.js";
import { userPsId, WALLET_PURPOSE } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import type {
  ENCLAVE_IDENTITY_EVIDENCE_VERSION,
  EnclaveIdentityEvidence,
} from "@opendatalabs/vana-sdk/protocol/identity";
import type { IdentityRequestBody } from "./types.js";

const KMS_ISSUED_PREFIX = "dstack-kms-issued";
const PREIMAGE_SEPARATOR = ":";
const COMPRESSED = true;
const HEX_PREFIX = "0x";
const EVIDENCE_VERSION = 1 satisfies typeof ENCLAVE_IDENTITY_EVIDENCE_VERSION;

export async function buildEvidence(
  client: DstackClient,
  request: IdentityRequestBody,
): Promise<EnclaveIdentityEvidence> {
  const id = userPsId(request.chainId, request.ownerAddress);
  const identity = await deriveEnclaveIdentity(client, id, request.epoch);
  const info = await client.info();
  const reportData = hexToBytes(keccak256(concat([id, identity.address])));
  // dstack accepts 32-byte report_data here and zero-pads it to 64 bytes.
  const attestation = await client.quote(reportData);
  const signatureChain = identity.signatureChain.map((link) => toHex(link));
  const appRoot = await recoverAppRoot(identity.publicKey, signatureChain[0]);
  const kmsRoot = await recoverKmsRoot(info.appId, appRoot, signatureChain[1]);

  return {
    v: EVIDENCE_VERSION,
    userPsId: id,
    chainId: request.chainId,
    ownerAddress: request.ownerAddress,
    epoch: request.epoch,
    address: identity.address,
    publicKey: identity.publicKey,
    appId: normalizeHex(info.appId),
    composeHash: normalizeHex(info.composeHash),
    // The dstack port does not expose osImageHash yet.
    purpose: WALLET_PURPOSE,
    signatureChain: [signatureChain[0], signatureChain[1]],
    quote: toHex(attestation.quote),
    ...(attestation.eventLog === undefined
      ? {}
      : { eventLog: attestation.eventLog }),
    kmsRootFingerprint: keccak256(kmsRoot).toLowerCase() as Hex,
  };
}

async function recoverAppRoot(publicKey: Hex, signature: Hex): Promise<Hex> {
  const compressed = secp256k1.ProjectivePoint.fromHex(
    hexToBytes(publicKey),
  ).toRawBytes(COMPRESSED);
  // SDK appRootPreimage currently uses the uncompressed key; dstack uses compressed.
  // TODO(verify-against-dstack-vector): pin this preimage to a captured CVM chain.
  const hash = keccak256(
    toBytes(
      `${WALLET_PURPOSE}${PREIMAGE_SEPARATOR}${toHex(compressed).slice(2)}`,
    ),
  );

  return recoverPublicKey({ hash, signature });
}

async function recoverKmsRoot(
  appId: string,
  appRoot: Hex,
  signature: Hex,
): Promise<Hex> {
  const compressed = secp256k1.ProjectivePoint.fromHex(
    hexToBytes(appRoot),
  ).toRawBytes(COMPRESSED);
  // TODO(verify-against-dstack-vector): pin this preimage to a captured CVM chain.
  const hash = keccak256(
    concat([
      toBytes(`${KMS_ISSUED_PREFIX}${PREIMAGE_SEPARATOR}${appId}`),
      compressed,
    ]),
  );

  return recoverPublicKey({ hash, signature });
}

function normalizeHex(value: string): Hex {
  const bare = value.startsWith(HEX_PREFIX)
    ? value.slice(HEX_PREFIX.length)
    : value;

  return `${HEX_PREFIX}${bare.toLowerCase()}`;
}
