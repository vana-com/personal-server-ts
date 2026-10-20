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

/** Dependency coverage only. The receiver must also check lifecycle, merge conflicts and snapshot digest. */
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
    const variants = byId.get(key) ?? new Set<string>();
    variants.add(canonicalJson(operation));
    byId.set(key, variants);
  }
  for (const dependency of completion.dependencies) {
    const variants = byId.get(
      canonicalJson([dependency.writerId, dependency.operationId]),
    );
    if (!variants || variants.size !== 1) return false;
    const bytes = new TextEncoder().encode([...variants][0]);
    const digest = new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", bytes),
    );
    const actual = `sha256:${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
    if (actual !== dependency.digest) return false;
  }
  return true;
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
