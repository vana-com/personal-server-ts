import { describe, expect, it } from "vitest";
import { planReplicaMerge } from "./merge-plan.js";
import {
  binding,
  identity,
  mutableVectors,
  registration,
  upsert,
} from "./fixtures.js";
import type { ReplicaOperation } from "./envelope.js";

const context = {
  owner: identity.owner,
  declarations: [
    {
      sourceId: identity.sourceId,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.text === "string",
    },
  ],
};
function* permutations<T>(items: readonly T[]): Generator<T[]> {
  if (!items.length) {
    yield [];
    return;
  }
  for (let i = 0; i < items.length; i++) {
    for (const tail of permutations(items.filter((_, index) => index !== i)))
      yield [items[i], ...tail];
  }
}
function assertPermutations(operations: ReplicaOperation[]) {
  const expected = planReplicaMerge(context, operations);
  for (const order of permutations(operations)) {
    expect(
      planReplicaMerge(context, [
        ...order,
        ...order.slice().reverse(),
        ...order,
      ]),
    ).toEqual(expected);
  }
  return expected;
}

describe("replica merge vectors", () => {
  it("retains losing mutable values and permits later resurrection in every order", () => {
    const result = assertPermutations([registration, ...mutableVectors]);
    expect(result.records[0].winner?.revision.operationId).toBe("resurrect");
    expect(result.records[0].losers).toEqual(mutableVectors.slice(0, 3));
    const deleted = assertPermutations([
      registration,
      ...mutableVectors.slice(0, 3),
    ]);
    expect(deleted.records[0].winner?.kind).toBe("delete");
    const concurrent = assertPermutations([
      registration,
      ...mutableVectors.slice(0, 2),
    ]);
    expect(concurrent.records[0].winner?.revision.operationId).toBe("b");
  });
});

it("quarantines append-only conflicts in all orders; ordinary later writes cannot repair", () => {
  const appendBinding = { ...binding, semantics: "append_only" as const };
  const appendContext = {
    ...context,
    declarations: [{ ...context.declarations[0], binding: appendBinding }],
  };
  const a = { ...upsert("a", 2), declaration: appendBinding };
  const b = { ...upsert("b", 3), declaration: appendBinding };
  const repairAttempt = {
    ...upsert("repair", 9, "a"),
    declaration: appendBinding,
  };
  const expected = planReplicaMerge(appendContext, [
    registration,
    a,
    b,
    repairAttempt,
  ]);
  for (const order of permutations([registration, a, b, repairAttempt])) {
    expect(planReplicaMerge(appendContext, [...order, ...order])).toEqual(
      expected,
    );
  }
  expect(expected.records[0]).toMatchObject({
    winner: null,
    quarantined: true,
  });
  expect(expected.conflicts[0].reason).toBe("append_only_content_conflict");
  expect(expected.records[0].losers).toEqual([a, b, repairAttempt]);
  expect(expected.conflicts[0].operations).toHaveLength(3);
  expect(expected.conflicts[0].operations).toEqual(
    expect.arrayContaining([a, b, repairAttempt]),
  );
  const same = {
    ...a,
    emittedAt: "later",
    revision: { ...a.revision, counter: 5, operationId: "same" },
  };
  expect(
    planReplicaMerge(appendContext, [registration, a, same]).conflicts,
  ).toEqual([]);
  const other = {
    ...a,
    recordKey: "other",
    data: { id: "other", text: "ok" },
    revision: { ...a.revision, operationId: "other" },
  };
  expect(
    planReplicaMerge(appendContext, [registration, a, b, other]).records.find(
      (r) => r.identity.recordKey === "other",
    )?.winner,
  ).toEqual(other);
  const deletion = { ...mutableVectors[2], declaration: appendBinding };
  expect(
    planReplicaMerge(appendContext, [registration, deletion]).rejected[0]
      .reason,
  ).toBe("append_only_delete");
});

it("keeps independent device-source instances distinct even with identical keys", () => {
  const deviceB = { ...upsert("b", 2), connectionId: "independent-device" };
  const registerB = {
    ...registration,
    connectionId: deviceB.connectionId,
    revision: { ...registration.revision, operationId: "register-b" },
  };
  expect(
    assertPermutations([registration, registerB, upsert("a", 2), deviceB])
      .records,
  ).toHaveLength(2);
});

it("requires registration and complete generation evidence; reset suppresses old records", () => {
  const reset: ReplicaOperation = {
    ...identity,
    kind: "connection-reset",
    generation: 2,
    previousGeneration: 1,
    revision: { counter: 4, writerId: "device-a", operationId: "reset" },
  };
  const fresh = { ...upsert("fresh", 5), generation: 2 };
  const result = assertPermutations([
    registration,
    reset,
    upsert("old-but-higher-counter", 99),
    fresh,
  ]);
  expect(result.records[0].winner).toEqual(fresh);
  expect(result.suppressed[0].reason).toBe("old_generation");
  expect(planReplicaMerge(context, [fresh]).pending[0].reason).toBe(
    "missing_connection_registration",
  );
  expect(
    planReplicaMerge(context, [registration, fresh]).pending[0].reason,
  ).toBe("missing_generation_reset");
  const gap = { ...reset, generation: 3, previousGeneration: 2 };
  expect(
    planReplicaMerge(context, [registration, gap, fresh]).pending[0].reason,
  ).toBe("missing_generation_reset");
  expect(
    planReplicaMerge(context, [registration, { ...reset, generation: 3 }])
      .conflicts[0].reason,
  ).toBe("invalid_generation_reset");
});

it("deleted connections dominate even later generations and high-counter writes", () => {
  const deletion: ReplicaOperation = {
    ...identity,
    kind: "connection-delete",
    revision: {
      counter: 2,
      writerId: "device-b",
      operationId: "connection-delete",
    },
  };
  const reset: ReplicaOperation = {
    ...identity,
    kind: "connection-reset",
    generation: 2,
    previousGeneration: 1,
    revision: {
      counter: 3,
      writerId: "device-a",
      operationId: "reset-after-delete",
    },
  };
  const result = assertPermutations([
    registration,
    deletion,
    reset,
    { ...upsert("late", 999), generation: 2 },
  ]);
  expect(result.records).toEqual([]);
  expect(result.suppressed[0].reason).toBe("connection_deleted");
  const recreated = {
    ...upsert("new-id", 1000),
    connectionId: "new-connection",
  };
  const newRegistration = {
    ...registration,
    connectionId: recreated.connectionId,
    revision: { ...registration.revision, operationId: "new-registration" },
  };
  expect(
    planReplicaMerge(context, [
      registration,
      deletion,
      recreated,
      newRegistration,
    ]).records[0].winner,
  ).toEqual(recreated);
});

it("fails closed for incompatible method, source and declaration evidence", () => {
  const wrongMethod = { ...upsert("wrong-method", 9), methodId: "other" };
  expect(
    assertPermutations([registration, upsert("a", 2), wrongMethod]).records,
  ).toEqual([]);
  const otherSource = {
    ...registration,
    sourceId: "other",
    revision: { ...registration.revision, operationId: "other-source" },
  };
  expect(
    assertPermutations([registration, upsert("a", 2), otherSource]).records,
  ).toEqual([]);
  const alternate = { ...binding, version: "2" };
  const otherDeclaration = {
    ...upsert("new-declaration", 3),
    declaration: alternate,
  };
  const both = {
    ...context,
    declarations: [
      ...context.declarations,
      { ...context.declarations[0], binding: alternate },
    ],
  };
  expect(
    planReplicaMerge(both, [registration, upsert("a", 2), otherDeclaration])
      .records[0].quarantined,
  ).toBe(true);
  const unknown = planReplicaMerge(context, [registration, otherDeclaration]);
  expect(unknown.pending[0].reason).toBe("missing_declaration");
});

it("rejects wrong owner, invalid schema and primary key, and never orders by emitted time", () => {
  const wrongOwner = { ...upsert("intruder", 100), owner: "other-owner" };
  const result = assertPermutations([
    registration,
    upsert("valid", 2),
    wrongOwner,
  ]);
  expect(result.rejected[0].reason).toBe("wrong_owner");
  expect(result.records[0].winner?.revision.operationId).toBe("valid");
  for (const data of [
    { id: "mismatch", text: "x" },
    { id: "same-key", text: 1 },
    { text: "missing key" },
  ]) {
    expect(
      planReplicaMerge(context, [
        registration,
        { ...upsert("invalid", 4), data },
      ]).rejected[0].reason,
    ).toBe("invalid_record_data");
  }
  const earlier = {
    ...upsert("later-revision", 3),
    emittedAt: "1900-01-01T00:00:00Z",
  };
  expect(
    assertPermutations([registration, upsert("future-time", 2), earlier])
      .records[0].winner,
  ).toEqual(earlier);
});

it("quarantines operation id equivocation rather than choosing first arrival", () => {
  const a = upsert("same-id", 2);
  const b = { ...a, data: { id: "same-key", text: "altered" } };
  const result = assertPermutations([registration, a, b]);
  expect(result.records).toEqual([]);
  expect(
    result.conflicts.some(
      (issue) => issue.reason === "operation_id_equivocation",
    ),
  ).toBe(true);
});

it("uses operation id as the last tie-break and ignores duplicate counts", () => {
  const a = upsert("a", 2);
  const z = upsert("z", 2);
  expect(assertPermutations([registration, a, z]).records[0].winner).toEqual(z);
  expect(
    planReplicaMerge(context, [registration, a, a]).records[0].losers,
  ).toEqual([]);
});

it("preserves a valid empty canonical record key", () => {
  const empty = {
    ...upsert("empty", 2),
    recordKey: "",
    data: { id: "", text: "empty key" },
  };
  expect(
    planReplicaMerge(context, [registration, empty]).records[0].winner,
  ).toEqual(empty);
});
