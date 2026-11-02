/**
 * The rule a rebaseline re-issues canonical state by, shared by every host.
 * A new writer identity re-captures the current state under its own writer
 * before it publishes, so a peer that missed the old writer's batches still
 * converges. Each host walks its own canonical state; this module names a
 * state's effect and the order and binding its copy keeps.
 *
 * Only the operation the merge chose explains a state. A higher operation
 * with the same effect may be one the merge rejected or keeps pending;
 * copying its order or binding would publish a baseline that a peer with
 * this device's trust refuses.
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { canonicalJson, type ReplicaOperation } from "./envelope.js";

type WithoutRevision<T> = T extends ReplicaOperation
  ? Omit<T, "revision">
  : never;
type Declared = Extract<ReplicaOperation, { declaration: unknown }>;

/** `upsert:<hex>` of a record body, as `replicaOperationEffect` names it. */
export function replicaUpsertEffect(data: unknown): string {
  return `upsert:${bytesToHex(sha256(new TextEncoder().encode(canonicalJson(data))))}`;
}

/** What a record or completion operation leaves in the canonical state. */
export function replicaOperationEffect(
  op: WithoutRevision<ReplicaOperation> | ReplicaOperation,
): string {
  if (op.kind === "upsert") return replicaUpsertEffect(op.data);
  if (op.kind === "stream-complete") return `complete:${op.snapshotSha256}`;
  return op.kind;
}

/**
 * The revision and declaration a copy of `source` keeps: its counter, that
 * operation (or its own origin) as origin, and its declaration, so after a
 * rebinding the copy validates exactly where the original did.
 */
export function reissuedFrom(source: Declared) {
  const { counter, writerId, operationId, origin } = source.revision;
  return {
    revision: { counter, origin: origin ?? { writerId, operationId } },
    declaration: source.declaration,
  };
}
