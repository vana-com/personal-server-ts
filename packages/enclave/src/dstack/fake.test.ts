import { describe, expect, it } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256, recoverPublicKey, toHex } from "viem";
import { SIGNATURE_CHAIN_LINK_BYTES } from "./client.js";
import { createFakeDstackClient, fakeKmsRootPublicKey } from "./fake.js";

const APP = "0000000000000000000000000000000000000001";
const OTHER_APP = "0000000000000000000000000000000000000002";
const PATH = "users/x/wallet/ethereum/secp256k1/v1";
const COMPRESSED = true;

// Same recipe a real verifier runs over the agent's chain.
async function recoverCompressed(
  message: Uint8Array,
  link: Uint8Array,
): Promise<string> {
  expect(link).toHaveLength(SIGNATURE_CHAIN_LINK_BYTES);
  const uncompressed = await recoverPublicKey({
    hash: keccak256(message),
    signature: toHex(link),
  });
  const point = secp256k1.ProjectivePoint.fromHex(uncompressed.slice(2));

  return Buffer.from(point.toRawBytes(COMPRESSED)).toString("hex");
}

describe("fake dstack client", () => {
  it("derives from (appId, path) only; purpose does not change the key", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const a = await client.deriveKey(PATH, "purpose-a");
    const b = await client.deriveKey(PATH, "purpose-b");

    expect(Buffer.from(b.key)).toEqual(Buffer.from(a.key));
    expect(Buffer.from(b.signatureChain[0])).not.toEqual(
      Buffer.from(a.signatureChain[0]),
    );
  });

  it("changes the key with path and with appId", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const base = await client.deriveKey(PATH, "p");
    const otherPath = await client.deriveKey(`${PATH}-other`, "p");
    const otherApp = await createFakeDstackClient({
      appId: OTHER_APP,
    }).deriveKey(PATH, "p");

    expect(Buffer.from(otherPath.key)).not.toEqual(Buffer.from(base.key));
    expect(Buffer.from(otherApp.key)).not.toEqual(Buffer.from(base.key));
  });

  it("signature chain verifies: link 0 by the app root, link 1 by the KMS root", async () => {
    const purpose = "vana.ps-enclave.wallet.v1";
    const { key, signatureChain } = await createFakeDstackClient({
      appId: APP,
    }).deriveKey(PATH, purpose);
    const pubkeyHex = Buffer.from(
      secp256k1.getPublicKey(key, COMPRESSED),
    ).toString("hex");

    const appRootHex = await recoverCompressed(
      Buffer.from(`${purpose}:${pubkeyHex}`, "utf8"),
      signatureChain[0],
    );
    const kmsRootHex = await recoverCompressed(
      Buffer.concat([
        Buffer.from("dstack-kms-issued:", "utf8"),
        Buffer.from(APP, "hex"),
        Buffer.from(appRootHex, "hex"),
      ]),
      signatureChain[1],
    );

    expect(kmsRootHex).toBe(
      Buffer.from(fakeKmsRootPublicKey()).toString("hex"),
    );
  });

  it("rejects a non-hex appId", () => {
    expect(() => createFakeDstackClient({ appId: "app-a" })).toThrow(
      "fake dstack appId must be 40 lowercase hex characters",
    );
  });
});
