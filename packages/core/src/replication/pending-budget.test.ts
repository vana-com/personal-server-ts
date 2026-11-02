import { describe, expect, it } from "vitest";
import { replicaOperationSchema } from "./envelope.js";
import {
  REPLICA_PENDING_BUDGET_DEFAULTS,
  ReplicaPendingCapacityError,
  assertReplicaPendingCapacity,
  replicaPendingOperationBytes,
  validateReplicaPendingBudgetLimits,
} from "./pending-budget.js";

describe("replica pending budget", () => {
  it("uses a million-operation default and validates tiny test limits", () => {
    expect(REPLICA_PENDING_BUDGET_DEFAULTS).toEqual({
      operations: 1_000_000,
      logicalBytes: 1024 ** 3,
    });
    expect(
      validateReplicaPendingBudgetLimits({ operations: 2, logicalBytes: 9 }),
    ).toEqual({
      operations: 2,
      logicalBytes: 9,
    });
    expect(() =>
      validateReplicaPendingBudgetLimits({ operations: -1, logicalBytes: 0 }),
    ).toThrow(RangeError);
    expect(() =>
      validateReplicaPendingBudgetLimits({
        operations: Number.MAX_SAFE_INTEGER + 1,
        logicalBytes: 0,
      }),
    ).toThrow(RangeError);
  });

  it("counts UTF-8 canonical operation bytes and exposes a retryable refusal", () => {
    const operation = replicaOperationSchema.parse({
      owner: "0x0000000000000000000000000000000000000001",
      sourceId: "source",
      connectionId: "connection",
      methodId: "method",
      generation: 1,
      declaration: {
        stream: "messages",
        semantics: "mutable_state",
        primaryKey: ["id"],
        digest: `sha256:${"a".repeat(64)}`,
        version: "1",
        schemaDigest: `sha256:${"b".repeat(64)}`,
      },
      recordKey: '["é🧪"]',
      kind: "upsert",
      emittedAt: "2026-01-01T00:00:00.000Z",
      data: { id: "é🧪" },
      blobs: [],
      revision: { counter: 1, writerId: "writer", operationId: "operation" },
    });
    const canonical = JSON.stringify(operation);
    const bytes = replicaPendingOperationBytes(operation);
    expect(bytes).toBe(new TextEncoder().encode(canonical).length);
    expect(() =>
      assertReplicaPendingCapacity({
        limits: { operations: 1, logicalBytes: bytes },
        used: { operations: 0, logicalBytes: 0 },
        requested: { operations: 1, logicalBytes: bytes },
      }),
    ).not.toThrow();
    expect(() =>
      assertReplicaPendingCapacity({
        limits: { operations: 1, logicalBytes: bytes },
        used: { operations: 0, logicalBytes: 0 },
        requested: { operations: 1, logicalBytes: bytes + 1 },
      }),
    ).toThrow(ReplicaPendingCapacityError);
    const error = new ReplicaPendingCapacityError("logicalBytes", 12, 1, 12);
    expect(error).toMatchObject({
      code: "replica_pending_capacity",
      retryable: true,
      limit: "logicalBytes",
    });
  });
});
