/**
 * LineageAttestation: the server-signed statement that binds a derivative's
 * lineage to the version it is registered with.
 *
 * The on-chain AddData struct is unchanged and `dataHash` (keccak256 of the
 * plaintext envelope, `$lineage` included) already commits to the lineage.
 * The gateway cannot open that commitment, so the plaintext source list it
 * stores next to the registration needs its own proof of authorship: the
 * AddData signature is public in every gateway attestation, so without one
 * anybody could replay a registration as a same-version refresh carrying a
 * different lineage. The attestation is EIP-712 under the DataRegistry
 * domain (same as AddData), signed by the owner or a registered server,
 * and bound to the exact version and dataHash so it cannot be moved to
 * another registration either.
 */

export const LINEAGE_ATTESTATION_TYPES = {
  LineageAttestation: [
    { name: "ownerAddress", type: "address" },
    { name: "scope", type: "string" },
    { name: "expectedVersion", type: "uint256" },
    { name: "dataHash", type: "bytes32" },
    { name: "sources", type: "bytes32[]" },
  ],
} as const;

export interface LineageAttestationMessage {
  ownerAddress: `0x${string}`;
  scope: string;
  expectedVersion: bigint;
  dataHash: `0x${string}`;
  /** Lowercase source data point ids in the registered order. */
  sources: readonly `0x${string}`[];
}
