import type {
  DeclarationBinding,
  ReplicaOperation,
  RecordOperation,
} from "./envelope.js";

export const T0 = Date.parse("2026-10-21T00:00:00Z");
export const binding: DeclarationBinding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1.0.0",
  stream: "messages",
  semantics: "mutable_state",
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
  reobservable: true,
  completeScanDeletes: true,
};
export const identity = {
  owner: "owner-a",
  sourceId: "https://example.test/source",
  connectionId: "connection-a",
  methodId: "export",
  upstreamAccount: { issuer: "https://github.com", subject: "gh:1001" },
  generation: 1 as const,
  batchId: "batch-default",
  frontier: {} as Record<string, { wallMs: number; logical: number }>,
};
export const registration: ReplicaOperation = {
  ...identity,
  kind: "connection-register",
  revision: {
    wallMs: T0,
    logical: 0,
    writerId: "device-a",
    operationId: "register",
  },
};
export function upsert(
  operationId: string,
  logical: number,
  text = operationId,
  writerId = "device-a",
  wallMs = T0,
): RecordOperation & { kind: "upsert" } {
  return {
    ...identity,
    kind: "upsert",
    declaration: binding,
    recordKey: "same-key",
    emittedAt: new Date(wallMs).toISOString(),
    contentHash: `sha256:${"d".repeat(64)}`,
    data: { id: "same-key", text },
    blobs: [],
    revision: { wallMs, logical, writerId, operationId },
  };
}
export const mutableVectors: readonly RecordOperation[] = [
  upsert("a", 2, "offline A"),
  upsert("b", 2, "offline B", "device-b"),
  {
    ...identity,
    kind: "source-delete",
    declaration: binding,
    recordKey: "same-key",
    emittedAt: new Date(T0).toISOString(),
    contentHash: `sha256:${"d".repeat(64)}`,
    origin: "source-event",
    revision: {
      wallMs: T0 + 2 * 86_400_000,
      logical: 3,
      writerId: "device-a",
      operationId: "delete",
    },
  },
  upsert("resurrect", 4, "resurrected", "device-a", T0 + 4 * 86_400_000),
];
