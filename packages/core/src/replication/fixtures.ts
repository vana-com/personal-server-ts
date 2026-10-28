/** Executable profile vectors shared with future receiver and Lite consumers. */
import type {
  DeclarationBinding,
  ReplicaOperation,
  RecordOperation,
} from "./envelope.js";

export const binding: DeclarationBinding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1.0.0",
  stream: "messages",
  semantics: "mutable_state",
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
export const identity = {
  owner: "owner-a",
  sourceId: "https://example.test/source",
  connectionId: "connection-a",
  methodId: "export",
  generation: 1 as const,
};
export const registration: ReplicaOperation = {
  ...identity,
  kind: "connection-register",
  revision: { counter: 1, writerId: "device-a", operationId: "register" },
};
export function upsert(
  operationId: string,
  counter: number,
  text = operationId,
  writerId = "device-a",
): RecordOperation & { kind: "upsert" } {
  return {
    ...identity,
    kind: "upsert",
    declaration: binding,
    recordKey: "same-key",
    emittedAt: "2026-10-20T00:00:00Z",
    data: { id: "same-key", text },
    blobs: [],
    revision: { counter, writerId, operationId },
  };
}
export const mutableVectors: readonly RecordOperation[] = [
  upsert("a", 2, "offline A"),
  upsert("b", 2, "offline B", "device-b"),
  {
    ...identity,
    kind: "delete",
    declaration: binding,
    recordKey: "same-key",
    emittedAt: "2026-10-20T00:00:00Z",
    deletedAt: "2026-10-20T00:00:00Z",
    revision: { counter: 3, writerId: "device-a", operationId: "delete" },
  },
  upsert("resurrect", 4),
];
