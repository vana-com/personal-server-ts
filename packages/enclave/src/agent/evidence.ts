import { concat, hexToBytes, keccak256, toHex, type Hex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { userPsId, WALLET_PURPOSE } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import type {
  ENCLAVE_IDENTITY_EVIDENCE_VERSION,
  EnclaveIdentityEvidence,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { recoverAppRoot, recoverKmsRoot } from "./chain.js";
import type { IdentityRequestBody } from "./types.js";

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
  const appRoot = await recoverAppRoot(
    WALLET_PURPOSE,
    identity.publicKey,
    signatureChain[0],
  );
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
    ...(info.osImageHash === undefined
      ? {}
      : { osImageHash: normalizeHex(info.osImageHash) }),
    purpose: WALLET_PURPOSE,
    signatureChain: [signatureChain[0], signatureChain[1]],
    quote: toHex(attestation.quote),
    ...(attestation.eventLog === undefined
      ? {}
      : { eventLog: attestation.eventLog }),
    // Fingerprint hashes the uncompressed KMS root; Gateway uses 0x04..., while SDK anchors accept either form.
    kmsRootFingerprint: keccak256(kmsRoot).toLowerCase() as Hex,
  };
}

function normalizeHex(value: string): Hex {
  const bare = value.startsWith(HEX_PREFIX)
    ? value.slice(HEX_PREFIX.length)
    : value;

  return `${HEX_PREFIX}${bare.toLowerCase()}`;
}
