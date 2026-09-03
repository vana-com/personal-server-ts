import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import { verifyEnclaveIdentityEvidence } from "@opendatalabs/vana-sdk/protocol/identity";
import { concat, hexToBytes, keccak256, toHex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import {
  createFakeDstackClient,
  fakeKmsRootPublicKey,
} from "../dstack/fake.js";
import { buildEvidence } from "./evidence.js";
import { recoverAppRoot, recoverKmsRoot } from "./chain.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const CHAIN_ID = 14_800;
const FAKE_APP_ID = "0000000000000000000000000000000000000001";
const HEX_HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const SHA256 = "sha256";

describe("buildEvidence", () => {
  it("builds complete deterministic identity evidence", async () => {
    const first = await buildEvidence(
      createFakeDstackClient({ appId: FAKE_APP_ID }),
      { ownerAddress: OWNER, chainId: CHAIN_ID, epoch: 1 },
    );
    const second = await buildEvidence(
      createFakeDstackClient({ appId: FAKE_APP_ID }),
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
    expect(first.osImageHash).toMatch(HEX_HASH_PATTERN);
    expect(first.publicKey).toHaveLength(2 + 65 * 2);
    expect(first.signatureChain).toHaveLength(2);
    expect(first.signatureChain[0]).toHaveLength(2 + 65 * 2);
    expect(first.signatureChain[1]).toHaveLength(2 + 65 * 2);
    expect(first.quote.length).toBeGreaterThan(2);
    expect(first.kmsRootFingerprint).toBe(keccak256(kmsRoot));
    expect(publicKeyToAddress(first.publicKey)).toBe(first.address);
    await expect(
      verifyEnclaveIdentityEvidence(
        first,
        {
          kmsRootPubkey: toHex(kmsRoot),
          appIds: [`0x${FAKE_APP_ID}`],
        },
        { ownerAddress: OWNER, chainId: CHAIN_ID, epoch: 1 },
      ),
    ).resolves.toBeUndefined();

    const reportData = hexToBytes(
      keccak256(concat([first.userPsId, first.address])),
    );
    const expectedQuote = createHash(SHA256)
      .update(FAKE_APP_ID, "utf8")
      .update(reportData)
      .digest();
    expect(first.quote).toBe(toHex(expectedQuote));

    const appRoot = await recoverAppRoot(
      first.purpose,
      first.publicKey,
      first.signatureChain[0],
    );
    const recoveredKmsRoot = await recoverKmsRoot(
      first.appId,
      appRoot,
      first.signatureChain[1],
    );
    const compressedKmsRoot = secp256k1.ProjectivePoint.fromHex(
      hexToBytes(recoveredKmsRoot),
    ).toRawBytes(true);

    expect(toHex(compressedKmsRoot)).toBe(toHex(fakeKmsRootPublicKey()));
  });

  it("derives a different address for another epoch", async () => {
    const client = createFakeDstackClient({ appId: FAKE_APP_ID });
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
