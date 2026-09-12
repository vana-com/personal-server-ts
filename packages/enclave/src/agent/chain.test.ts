import { secp256k1 } from "@noble/curves/secp256k1";
import { hexToBytes, toHex, type Hex } from "viem";
import { recoverAppRoot, recoverKmsRoot } from "./chain.js";

const APP_ID = "205730c6547ad5884e8eddba3ace7406efb1260d";
const PURPOSE = "wallet";
const PUBLIC_KEY =
  "0x026d004dca2082e5cf067b34142f8d99568116c330f93671d1761abb2e155c01ea";
const SIGNATURE_CHAIN_0 =
  "0x310fcdedac7f5a8c665072fb694946fd45d30df61d1eb30ae9dd94e0c586fc212021059c11952fa40ae57f91a36f13617a0cf30496db52af8599289c3c5ff48c00";
const SIGNATURE_CHAIN_1 =
  "0x394d8e0863b49b8459c11515f8f6a10f34a543b607faaeac00b121d8d321366a1ec91b1bb889904fe064425eeee05e4e7ad4292da3b2f034b3897adf6a87bb6c00";
const APP_ROOT_PUBLIC_KEY =
  "0x02724f8036ee1ca252ab10adbd511540273813973f5e6a2321645320d498af4464";
const KMS_ROOT_PUBLIC_KEY =
  "0x0334c76e0c3f52ec64cbf9bbf5c910c272330166fd656c0a86bb330963e46910e1";

describe("dstack signature chain", () => {
  it("recovers the Phala KMS root from the live CVM vector", async () => {
    const appRoot = await recoverAppRoot(
      PURPOSE,
      PUBLIC_KEY,
      SIGNATURE_CHAIN_0,
    );

    expect(compress(appRoot)).toBe(APP_ROOT_PUBLIC_KEY);
    const kmsRoot = await recoverKmsRoot(APP_ID, appRoot, SIGNATURE_CHAIN_1);
    expect(compress(kmsRoot)).toBe(KMS_ROOT_PUBLIC_KEY);
  });
});

function compress(publicKey: Hex): Hex {
  return toHex(
    secp256k1.ProjectivePoint.fromHex(hexToBytes(publicKey)).toRawBytes(true),
  );
}
