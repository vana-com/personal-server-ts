import { describe, expect, it } from "vitest";
import {
  encodeAbiParameters,
  getAddress,
  keccak256,
  recoverTypedDataAddress,
  toBytes,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  dataPointId,
  RECORD_DATA_ACCESS_TYPES,
  signAccessReceipt,
} from "./access-receipt.js";

const OWNER = getAddress("0x1000000000000000000000000000000000000001");
const BUILDER = getAddress("0x2000000000000000000000000000000000000002");
const DATA_REGISTRY = getAddress("0x8f1eFCdff3d0d5BB535e32620721c7EBed151867");
const CHAIN_ID = 14_800;
const SCOPE = "spotify.profile";
const enclave = privateKeyToAccount(
  keccak256(toBytes("access-receipt:enclave")),
);

/** The dstack-derived wallet, in the shape the agent hands to the signer. */
const account = {
  signTypedData: (params: Parameters<typeof enclave.signTypedData>[0]) =>
    enclave.signTypedData(params),
} as never;

function fixedRandom(byte: number) {
  return (size: number) => new Uint8Array(size).fill(byte);
}

describe("job access receipt", () => {
  it("derives the data point id the registry derives", () => {
    // Mirrors DataRegistryV2._dataPointId: no domain separator, uniqueness is
    // purely (owner, scope).
    const expected = keccak256(
      encodeAbiParameters(
        [
          { name: "ownerAddress", type: "address" },
          { name: "scope", type: "string" },
        ],
        [OWNER, SCOPE],
      ),
    );
    expect(dataPointId(OWNER, SCOPE)).toBe(expected);
  });

  it("separates the same scope under different owners", () => {
    const other = getAddress("0x3000000000000000000000000000000000000003");
    expect(dataPointId(OWNER, SCOPE)).not.toBe(dataPointId(other, SCOPE));
  });

  // The Gateway verifies this signer against the enclave address on the owner's
  // identity row, and the contract against the owner's registered servers.
  it("signs a receipt that recovers to the enclave wallet", async () => {
    const receipt = await signAccessReceipt(
      account,
      {
        owner: OWNER,
        scope: SCOPE,
        version: 4n,
        accessor: BUILDER,
        chainId: CHAIN_ID,
        dataRegistry: DATA_REGISTRY,
      },
      fixedRandom(0x7e),
    );

    const signer = await recoverTypedDataAddress({
      domain: {
        name: "Vana Data Portability",
        version: "1",
        chainId: CHAIN_ID,
        verifyingContract: DATA_REGISTRY,
      },
      types: RECORD_DATA_ACCESS_TYPES as never,
      primaryType: "RecordDataAccess",
      message: {
        ownerAddress: OWNER,
        scope: SCOPE,
        version: 4n,
        accessor: BUILDER,
        recordId: receipt.recordId,
      },
      signature: receipt.signature,
    });

    expect(signer).toBe(enclave.address);
    expect(receipt).toMatchObject({
      dataPointId: dataPointId(OWNER, SCOPE),
      version: "4",
      accessor: BUILDER,
    });
  });

  // Every field is bound: a signature made for one read cannot be presented as
  // a receipt for another.
  it("binds the signature to the version and the accessor", async () => {
    const base = {
      owner: OWNER,
      scope: SCOPE,
      version: 4n,
      accessor: BUILDER,
      chainId: CHAIN_ID,
      dataRegistry: DATA_REGISTRY,
    };
    const signed = await signAccessReceipt(account, base, fixedRandom(0x7e));

    for (const claimed of [
      { ...base, version: 5n },
      {
        ...base,
        accessor: getAddress(
          "0x4000000000000000000000000000000000000004",
        ) as Address,
      },
    ]) {
      const signer = await recoverTypedDataAddress({
        domain: {
          name: "Vana Data Portability",
          version: "1",
          chainId: CHAIN_ID,
          verifyingContract: DATA_REGISTRY,
        },
        types: RECORD_DATA_ACCESS_TYPES as never,
        primaryType: "RecordDataAccess",
        message: {
          ownerAddress: claimed.owner,
          scope: claimed.scope,
          version: claimed.version,
          accessor: claimed.accessor,
          recordId: signed.recordId,
        },
        signature: signed.signature,
      });
      expect(signer).not.toBe(enclave.address);
    }
  });

  // The registry pins recordId in _usedRecordIds, so a repeated id would make
  // the second settlement revert. Fresh randomness per event, like the legacy
  // 402 challenge mints.
  it("mints a fresh record id per receipt", async () => {
    const input = {
      owner: OWNER,
      scope: SCOPE,
      version: 4n,
      accessor: BUILDER,
      chainId: CHAIN_ID,
      dataRegistry: DATA_REGISTRY,
    };
    const first = await signAccessReceipt(account, input, fixedRandom(0x01));
    const second = await signAccessReceipt(account, input, fixedRandom(0x02));
    expect(first.recordId).not.toBe(second.recordId);
    expect(first.recordId).toHaveLength(66);
  });
});
