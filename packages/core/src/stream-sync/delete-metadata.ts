import { keccak256, stringToHex } from "viem";

/** Row-only delete marker, in a separate domain from ordinary publication metadata. */
export function deleteMetadataHash(
  scope: string,
  version: number,
): `0x${string}` {
  return keccak256(
    stringToHex(
      JSON.stringify(["vana.stream-sync.delete.v1", scope, String(version)]),
    ),
  );
}
