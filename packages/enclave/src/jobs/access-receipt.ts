/**
 * The delivery receipt that lets a job read be charged.
 *
 * A legacy Personal Server signs a `RecordDataAccess` EIP-712 into its 402
 * challenge, and the Gateway later pushes it on chain with the payout. An
 * enclave job has no challenge, so the receipt is minted here instead: the node
 * agent signs it with the owner's enclave wallet — the address registration put
 * on chain as their server, which is what `recordDataAccess` verifies.
 *
 * The sandbox is not involved and cannot be. It holds no signing key by design,
 * and every field below is something the agent already knows from the claim:
 * the owner, the scope, the version the Gateway pinned, and the builder the
 * result is sealed to. Nothing the sandbox says can change what gets signed, so
 * this adds no surface inside the user's TCB.
 */

import {
  encodeAbiParameters,
  getAddress,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import type { ServerAccount } from "../identity/wallet.js";

/** Mirrors `DataRegistryV2._dataPointId`: keccak256(abi.encode(owner, scope)). */
export function dataPointId(owner: Address, scope: string): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { name: "ownerAddress", type: "address" },
        { name: "scope", type: "string" },
      ],
      [getAddress(owner), scope],
    ),
  );
}

export const RECORD_DATA_ACCESS_TYPES = {
  RecordDataAccess: [
    { name: "ownerAddress", type: "address" },
    { name: "scope", type: "string" },
    { name: "version", type: "uint256" },
    { name: "accessor", type: "address" },
    { name: "recordId", type: "bytes32" },
  ],
};

const RECORD_ID_BYTES = 32;

/** What the Gateway binds to the payment row and later submits on chain. */
export interface JobAccessRecord {
  dataPointId: Hex;
  /** uint256 decimal — the version this read served. */
  version: string;
  accessor: Address;
  /** 32 random bytes; the contract pins them against replay. */
  recordId: Hex;
  signature: Hex;
}

export interface ReceiptInput {
  owner: Address;
  scope: string;
  /** The version the Gateway pinned at admission. */
  version: bigint;
  /** The builder the result was sealed to. */
  accessor: Address;
  chainId: number;
  dataRegistry: Address;
}

/**
 * Sign the receipt for a read this node just served.
 *
 * `recordId` is fresh randomness per event, matching what the legacy challenge
 * mints: the registry pins it in `_usedRecordIds`, so a receipt cannot be
 * replayed for a second payout.
 */
export async function signAccessReceipt(
  account: Pick<ServerAccount, "signTypedData">,
  input: ReceiptInput,
  randomBytes: (size: number) => Uint8Array,
): Promise<JobAccessRecord> {
  const owner = getAddress(input.owner);
  const accessor = getAddress(input.accessor);
  const recordId =
    `0x${Buffer.from(randomBytes(RECORD_ID_BYTES)).toString("hex")}` as Hex;

  const signature = await account.signTypedData({
    domain: {
      name: "Vana Data Portability",
      version: "1",
      chainId: input.chainId,
      verifyingContract: getAddress(input.dataRegistry),
    },
    types: { ...RECORD_DATA_ACCESS_TYPES },
    primaryType: "RecordDataAccess",
    message: {
      ownerAddress: owner,
      scope: input.scope,
      version: input.version,
      accessor,
      recordId,
    },
  });

  return {
    dataPointId: dataPointId(owner, input.scope),
    version: input.version.toString(),
    accessor,
    recordId,
    signature,
  };
}
