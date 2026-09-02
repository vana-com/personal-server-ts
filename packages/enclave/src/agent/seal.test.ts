import {
  MASTER_KEY_MESSAGE as SDK_MASTER_KEY_MESSAGE,
  NodeECIESProvider,
  recoverServerOwner,
  serializeECIES,
} from "@opendatalabs/vana-sdk/node";
import {
  MASTER_SIGNATURE_DELIVERY_VERSION,
  type MasterSignatureDelivery,
} from "@opendatalabs/vana-sdk/protocol/identity";
import { keccak256, sha256, toBytes, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createFakeDstackClient } from "../dstack/fake.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal } from "../sealing/envelope.js";
import {
  DeliveryInvalid,
  EnclaveAddressMismatch,
  EpochRetired,
  OwnerMismatch,
  StaleDelivery,
} from "./errors.js";
import { MASTER_KEY_MESSAGE, sealDelivery } from "./seal.js";
import type { SealRequestBody } from "./types.js";

const CHAIN_ID = 14_800;
const EPOCH = 2;
const FAKE_APP_ID = "0000000000000000000000000000000000000002";

function owner(label: string) {
  return privateKeyToAccount(keccak256(toBytes(`enclave-agent-test:${label}`)));
}

async function fixture(
  label = "owner",
  overrides: Partial<MasterSignatureDelivery> = {},
): Promise<{
  client: ReturnType<typeof createFakeDstackClient>;
  delivery: MasterSignatureDelivery;
  request: SealRequestBody;
  signature: `0x${string}`;
}> {
  const client = createFakeDstackClient({ appId: FAKE_APP_ID });
  const ownerAccount = owner(label);
  const id = userPsId(CHAIN_ID, ownerAccount.address);
  const identity = await deriveEnclaveIdentity(client, id, EPOCH);
  const signature = await ownerAccount.signMessage({
    message: SDK_MASTER_KEY_MESSAGE,
  });
  const delivery: MasterSignatureDelivery = {
    v: MASTER_SIGNATURE_DELIVERY_VERSION,
    userPsId: id,
    epoch: EPOCH,
    enclaveAddress: identity.address,
    ownerAddress: ownerAccount.address,
    masterSignature: signature,
    issuedAt: Math.floor(Date.now() / 1000),
    ...overrides,
  };
  const provider = new NodeECIESProvider();
  const encrypted = await provider.encrypt(
    toBytes(identity.publicKey),
    new TextEncoder().encode(JSON.stringify(delivery)),
  );
  const ciphertext = `0x${serializeECIES(encrypted)}` as const;

  return {
    client,
    delivery,
    signature,
    request: {
      ownerAddress: ownerAccount.address,
      chainId: CHAIN_ID,
      epoch: EPOCH,
      enclaveAddress: identity.address,
      ciphertext,
    },
  };
}

describe("sealDelivery", () => {
  it("decrypts SDK ECIES and seals the owner signature", async () => {
    const { client, request, signature } = await fixture();

    expect(await recoverServerOwner(signature)).toBe(request.ownerAddress);
    const result = await sealDelivery(client, request);
    const recovered = await unseal(
      client,
      userPsId(CHAIN_ID, request.ownerAddress),
      EPOCH,
      result.envelope,
    );

    expect(toHex(recovered)).toBe(signature);
    expect(result.secretHash).toBe(sha256(request.ciphertext));
  });

  it("rejects a signature from the wrong owner", async () => {
    const other = owner("other");
    const signature = await other.signMessage({ message: MASTER_KEY_MESSAGE });
    const { client, request } = await fixture("owner", {
      masterSignature: signature,
    });

    await expect(sealDelivery(client, request)).rejects.toBeInstanceOf(
      OwnerMismatch,
    );
  });

  it("rejects an ownerAddress that differs from the request", async () => {
    const { client, request } = await fixture("owner", {
      ownerAddress: owner("other-delivery-owner").address,
    });

    await expect(sealDelivery(client, request)).rejects.toBeInstanceOf(
      OwnerMismatch,
    );
  });

  it("rejects a retired epoch", async () => {
    const { client, request } = await fixture();

    await expect(
      sealDelivery(client, { ...request, minEpoch: EPOCH + 1 }),
    ).rejects.toBeInstanceOf(EpochRetired);
  });

  it("rejects a delivery older than 600 seconds", async () => {
    const { client, request } = await fixture("owner", {
      issuedAt: Math.floor(Date.now() / 1000) - 601,
    });

    await expect(sealDelivery(client, request)).rejects.toBeInstanceOf(
      StaleDelivery,
    );
  });

  it("rejects an enclave address mismatch", async () => {
    const { client, request } = await fixture();

    await expect(
      sealDelivery(client, {
        ...request,
        enclaveAddress: owner("not-enclave").address,
      }),
    ).rejects.toBeInstanceOf(EnclaveAddressMismatch);
  });

  it("rejects a userPsId mismatch inside the delivery", async () => {
    const { client, request } = await fixture("owner", {
      userPsId: keccak256(toBytes("wrong-user")),
    });

    await expect(sealDelivery(client, request)).rejects.toBeInstanceOf(
      DeliveryInvalid,
    );
  });

  it("rejects the wrong delivery version", async () => {
    const { client, request } = await fixture("owner", {
      v: "wrong" as typeof MASTER_SIGNATURE_DELIVERY_VERSION,
    });

    await expect(sealDelivery(client, request)).rejects.toBeInstanceOf(
      DeliveryInvalid,
    );
  });

  it("rejects garbage ciphertext", async () => {
    const { client, request } = await fixture();

    await expect(
      sealDelivery(client, { ...request, ciphertext: toHex(toBytes("bad")) }),
    ).rejects.toBeInstanceOf(DeliveryInvalid);
  });

  it("keeps the master-key message byte-compatible with the SDK", () => {
    expect(MASTER_KEY_MESSAGE).toBe(SDK_MASTER_KEY_MESSAGE);
  });
});
