/**
 * Sign a ServerRegistration EIP-712 message with VANA_WEB_PRIVATE_KEY using the
 * SDK's own helper (buildPersonalServerRegistrationSignature) and recover the
 * signer to verify it matches ownerAddress.
 *
 *   tsx --env-file-if-exists=.env.local scripts/sign-server-registration.ts
 *
 * Note: the personal server's ServerSigner does NOT sign server registration —
 * that's signed by the OWNER, not the server account — so the canonical
 * function is the SDK's buildPersonalServerRegistrationSignature.
 *
 * The private key is read from the environment only and is never logged.
 */
import { privateKeyToAccount } from "viem/accounts";
import { recoverTypedDataAddress } from "viem";
import {
  buildPersonalServerRegistrationSignature,
  SERVER_REGISTRATION_TYPES,
} from "@opendatalabs/vana-sdk/node";

const raw = process.env.VANA_WEB_PRIVATE_KEY;
if (!raw) {
  console.error("VANA_WEB_PRIVATE_KEY is not set (.env.local).");
  process.exit(1);
}
const privateKey = (raw.startsWith("0x") ? raw : `0x${raw}`) as `0x${string}`;

const CHAIN_ID = 14800;
const VERIFYING_CONTRACT =
  "0xCae2CE0e9caa6643ed28186cF57bd40Bd9E17Eab" as `0x${string}`;
const SERVER_ADDRESS =
  "0xbc9d699143d7d8FBe73B139e2E7A0b6bb6cE4Fb3" as `0x${string}`;
const SERVER_PUBLIC_KEY =
  "0x045f13392e4d40571b6b0495f598cb042eeb420a1913b4a775331a331f2a3d77a72e4d9e1961f242291adad51aca3594ae7f7b86af0919c8a8c26561dcf55848ff";
const SERVER_URL = "https://2f9451be782407302f5f3f71.34.16.49.200.sslip.io";

async function main(): Promise<void> {
  const account = privateKeyToAccount(privateKey);

  // SDK helper: owner = signer.address; it builds the ServerRegistration typed
  // data and signs it via signer.signTypedData.
  const { signature, signerAddress, typedData } =
    await buildPersonalServerRegistrationSignature({
      signer: account,
      serverAddress: SERVER_ADDRESS,
      serverPublicKey: SERVER_PUBLIC_KEY,
      serverUrl: SERVER_URL,
      chainId: CHAIN_ID,
      verifyingContract: VERIFYING_CONTRACT,
    });

  const recovered = await recoverTypedDataAddress({
    domain: typedData.domain,
    types: SERVER_REGISTRATION_TYPES,
    primaryType: "ServerRegistration",
    message: typedData.message,
    signature,
  });

  console.log("typed data:", JSON.stringify(typedData, null, 2));
  console.log("signer (owner) address:", signerAddress);
  console.log("signature:             ", signature);
  console.log("recovered signer:      ", recovered);
  console.log(
    "recovered === owner:   ",
    recovered.toLowerCase() === signerAddress.toLowerCase(),
  );
}

main().catch((err) => {
  console.error("failed:", err);
  process.exit(1);
});
