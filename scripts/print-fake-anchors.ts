import { secp256k1 } from "@noble/curves/secp256k1";
import { pathToFileURL } from "node:url";
import { toHex } from "viem";
import { fakeKmsRootPublicKey } from "../packages/enclave/src/dstack/fake.js";

export const DEFAULT_FAKE_APP_ID = "0xe2e0000000000000000000000000000000000001";

export function fakeGatewayAnchors(): {
  kmsRootPubkey: `0x${string}`;
  appId: `0x${string}`;
} {
  const kmsRootPubkey = toHex(
    secp256k1.ProjectivePoint.fromHex(fakeKmsRootPublicKey()).toRawBytes(false),
  );

  return { kmsRootPubkey, appId: DEFAULT_FAKE_APP_ID };
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const anchors = fakeGatewayAnchors();
  console.log(`ENCLAVE_KMS_ROOT_PUBKEY=${anchors.kmsRootPubkey}`);
  console.log(`ENCLAVE_APP_ID_ALLOWLIST=${anchors.appId}`);
}
