import { encodeAbiParameters, keccak256 } from "viem";

/**
 * Deterministic DPv2 data-point id: `keccak256(abi.encode(owner, scope))`,
 * the same primary key DataRegistryV2 and the gateway use. Every version of
 * a scope shares this id; the registry row carries the current version.
 */
export function computeDataPointId(
  ownerAddress: string,
  scope: string,
): `0x${string}` {
  // ABI-encoding an address is checksum-insensitive (same bytes either way),
  // but viem rejects mixed-case strings that fail checksum validation;
  // normalize so config-sourced owner strings can't trip it.
  return keccak256(
    encodeAbiParameters(
      [
        { name: "ownerAddress", type: "address" },
        { name: "scope", type: "string" },
      ],
      [ownerAddress.toLowerCase() as `0x${string}`, scope],
    ),
  );
}
