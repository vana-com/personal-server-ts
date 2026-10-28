import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import {
  canonicalJson,
  replicaOperationSchema,
  type ReplicaOperation,
} from "./envelope.js";

import { compareRevisions } from "./revision.js";

export type CompletionOperation = Extract<
  ReplicaOperation,
  { kind: "stream-complete" }
>;

/** `sha256:<hex>` of an operation's canonical JSON, as completion dependencies pin it. */
export function operationDigest(operation: ReplicaOperation): string {
  return `sha256:${bytesToHex(sha256(new TextEncoder().encode(canonicalJson(operation))))}`;
}

/**
 * Dependency coverage only: every dependency has exactly one retained variant
 * and it has the pinned digest. `variantDigests` returns the distinct digests
 * of every retained variant of an operation id, across all connections. The
 * rest of availability is `completionAvailability` in `visibility-engine.ts`.
 */
export function completionDependenciesCovered(
  completion: CompletionOperation,
  variantDigests: (writerId: string, operationId: string) => readonly string[],
): boolean {
  if (completion.dependencies.length === 0) return false;
  return completion.dependencies.every((dependency) => {
    const digests = variantDigests(dependency.writerId, dependency.operationId);
    return digests.length === 1 && digests[0] === dependency.digest;
  });
}

/** Dependency coverage over a list of imported operations. */
export async function hasCompletionDependencies(
  completion: CompletionOperation,
  imported: readonly ReplicaOperation[],
): Promise<boolean> {
  replicaOperationSchema.parse(completion);
  if (completion.dependencies.length === 0) return false;
  const byId = new Map<string, Set<string>>();
  for (const operation of imported) {
    replicaOperationSchema.parse(operation);
    const key = canonicalJson([
      operation.revision.writerId,
      operation.revision.operationId,
    ]);
    byId.set(key, (byId.get(key) ?? new Set()).add(operationDigest(operation)));
  }
  return completionDependenciesCovered(completion, (writerId, operationId) => [
    ...(byId.get(canonicalJson([writerId, operationId])) ?? []),
  ]);
}

/** Select current receipt state for ONE validated stream/generation; this is not an availability check. */
export function selectStreamCompletion(
  operations: readonly Extract<
    ReplicaOperation,
    { kind: "stream-complete" | "stream-invalidate" }
  >[],
): CompletionOperation | null {
  let identity: string | undefined;
  let winner: (typeof operations)[number] | undefined;
  const byId = new Map<string, string>();
  for (const operation of operations) {
    replicaOperationSchema.parse(operation);
    const key = canonicalJson([
      operation.owner,
      operation.sourceId,
      operation.connectionId,
      operation.methodId,
      operation.generation,
      operation.declaration,
    ]);
    if (identity !== undefined && identity !== key)
      throw new Error("mixed completion identities");
    identity = key;
    const id = canonicalJson([
      operation.revision.writerId,
      operation.revision.operationId,
    ]);
    const encoded = canonicalJson(operation);
    if (byId.has(id) && byId.get(id) !== encoded) return null;
    byId.set(id, encoded);
    if (!winner || compareRevisions(operation.revision, winner.revision) > 0)
      winner = operation;
  }
  return winner?.kind === "stream-complete" ? winner : null;
}
