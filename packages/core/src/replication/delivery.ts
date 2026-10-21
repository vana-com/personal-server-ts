import { keccak256 } from "viem";
import {
  replicaRegistrationState,
  replicaChainCommitment,
  type ReplicaTransportPort,
} from "./dpv2.js";
import {
  decodeReplicaFragment,
  replicaMetadataHash,
  type PreparedFragment,
} from "./transport.js";

export class ReplicaFragmentSizeError extends Error {
  readonly code = "unsupported_size";
}

/** Shared immutable-slot reconciliation. Persist exact bytes before calling. */
export async function publishReplicaFragment(
  transport: ReplicaTransportPort,
  owner: string,
  part: PreparedFragment,
) {
  const expected = {
    owner,
    scope: part.scope,
    dataHash: part.dataHash,
    metadataHash: part.metadataHash,
  };
  let status = replicaRegistrationState(
    await transport.evidence(part.scope),
    expected,
  );
  if (status === "absent") {
    await transport.put(part);
    await transport.register(part);
    status = replicaRegistrationState(
      await transport.evidence(part.scope),
      expected,
    );
  }
  return status;
}

/** The finalized commitment is authoritative even if Gateway and bytes agree. */
export async function downloadReplicaFragment(
  transport: ReplicaTransportPort,
  owner: string,
  scope: string,
  maxBlobBytes: number,
) {
  const evidence = await transport.evidence(scope);
  const status = replicaRegistrationState(evidence, { owner, scope });
  if (status !== "confirmed") return { status } as const;
  const encrypted = await transport.get(scope);
  if (encrypted.length > maxBlobBytes)
    throw new ReplicaFragmentSizeError(
      "replica ciphertext exceeds storage cap",
    );
  const plaintext = await transport.decrypt(scope, encrypted);
  const fragment = decodeReplicaFragment(plaintext, scope, owner);
  const dataHash = keccak256(plaintext);
  const metadataHash = replicaMetadataHash(
    scope,
    fragment.collectedAt,
    encrypted.length,
  );
  if (
    replicaChainCommitment(dataHash, metadataHash).toLowerCase() !==
      evidence.chain!.commitment.toLowerCase() ||
    dataHash !== evidence.head!.dataHash ||
    metadataHash !== evidence.head!.metadataHash
  )
    throw new Error("replica commitment mismatch");
  return { status, fragment } as const;
}
