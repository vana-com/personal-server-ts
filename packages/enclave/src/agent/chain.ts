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

const KMS_ISSUED_PREFIX = "dstack-kms-issued";
const PREIMAGE_SEPARATOR = ":";
const COMPRESSED = true;

// dstack guest-agent rpc_service.rs:612-628 and kms/src/crypto.rs:23-40.

export async function recoverAppRoot(
  purpose: string,
  publicKey: Hex,
  signature: Hex,
): Promise<Hex> {
  const compressed = secp256k1.ProjectivePoint.fromHex(
    hexToBytes(publicKey),
  ).toRawBytes(COMPRESSED);
  const hash = keccak256(
    toBytes(`${purpose}${PREIMAGE_SEPARATOR}${toHex(compressed).slice(2)}`),
  );

  return recoverPublicKey({ hash, signature });
}

export async function recoverKmsRoot(
  appId: string,
  appRoot: Hex,
  signature: Hex,
): Promise<Hex> {
  const compressed = secp256k1.ProjectivePoint.fromHex(
    hexToBytes(appRoot),
  ).toRawBytes(COMPRESSED);
  const hash = keccak256(
    concat([
      toBytes(`${KMS_ISSUED_PREFIX}${PREIMAGE_SEPARATOR}`),
      hexToBytes(normalizeHex(appId)),
      compressed,
    ]),
  );

  return recoverPublicKey({ hash, signature });
}

function normalizeHex(value: string): Hex {
  return `0x${value.replace(/^0x/, "").toLowerCase()}`;
}
