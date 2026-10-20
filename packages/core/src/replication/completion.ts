import {
  canonicalJson,
  replicaOperationSchema,
  type ReplicaOperation,
} from "./envelope.js";

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
