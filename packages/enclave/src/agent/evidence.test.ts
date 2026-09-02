import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak256 } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  createFakeDstackClient,
  fakeKmsRootPublicKey,
} from "../dstack/fake.js";
import { buildEvidence } from "./evidence.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const CHAIN_ID = 14_800;

describe("buildEvidence", () => {
  it("builds complete deterministic identity evidence", async () => {
    const first = await buildEvidence(
      createFakeDstackClient({ appId: "identity-app" }),
      { ownerAddress: OWNER, chainId: CHAIN_ID, epoch: 1 },
    );
    const second = await buildEvidence(
      createFakeDstackClient({ appId: "identity-app" }),
      { ownerAddress: OWNER, chainId: CHAIN_ID, epoch: 1 },
    );
    const kmsRoot = secp256k1.ProjectivePoint.fromHex(
      fakeKmsRootPublicKey(),
    ).toRawBytes(false);

    expect(first).toEqual(second);
    expect(first).toMatchObject({
      v: 1,
      chainId: CHAIN_ID,
      ownerAddress: OWNER,
      epoch: 1,
      purpose: "vana.ps-enclave.wallet.v1",
    });
    expect(first.appId).toMatch(/^0x/);
    expect(first.composeHash).toMatch(/^0x/);
    expect(first.publicKey).toHaveLength(2 + 65 * 2);
    expect(first.signatureChain).toHaveLength(2);
    expect(first.signatureChain[0]).toHaveLength(2 + 65 * 2);
    expect(first.signatureChain[1]).toHaveLength(2 + 65 * 2);
    expect(first.quote.length).toBeGreaterThan(2);
    expect(first.kmsRootFingerprint).toBe(keccak256(kmsRoot));
    expect(publicKeyToAddress(first.publicKey)).toBe(first.address);
  });

  it("derives a different address for another epoch", async () => {
    const client = createFakeDstackClient({ appId: "identity-app" });
    const first = await buildEvidence(client, {
      ownerAddress: OWNER,
      chainId: CHAIN_ID,
      epoch: 1,
    });
    const second = await buildEvidence(client, {
      ownerAddress: OWNER,
      chainId: CHAIN_ID,
      epoch: 2,
    });

    expect(second.address).not.toBe(first.address);
  });
});
