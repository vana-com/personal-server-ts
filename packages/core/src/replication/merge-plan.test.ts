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

  it("retains __proto__ data and detects distinct operation variants", () => {
    const data = (value: string) =>
      JSON.parse(
        `{"id":"same-key","text":"ok","__proto__":{"value":${JSON.stringify(value)},"nested":{"__proto__":${JSON.stringify(value)}}}}`,
      ) as Record<string, unknown>;
    const first = { ...upsert("same-id", 2), data: data("first") };
    const second = { ...upsert("same-id", 2), data: data("second") };

    const result = planReplicaMerge(context, [registration, first, second]);
    const equivocation = result.conflicts.find(
      (issue) => issue.reason === "operation_id_equivocation",
    );
    expect(equivocation).toBeDefined();
    expect(
      equivocation?.operations.flatMap((operation) =>
        operation.kind === "upsert" ? [operation.data["__proto__"].value] : [],
      ),
    ).toEqual(["first", "second"]);
    const firstVariant = equivocation?.operations.find(
      (operation) =>
        operation.kind === "upsert" &&
        operation.data["__proto__"].value === "first",
    );
    expect(firstVariant?.kind).toBe("upsert");
    if (firstVariant?.kind !== "upsert") throw new Error("missing variant");
    expect(Object.hasOwn(firstVariant.data, "__proto__")).toBe(true);
    expect(
      Object.hasOwn(firstVariant.data["__proto__"].nested, "__proto__"),
    ).toBe(true);
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
  // Another shape (here the primary key) makes the same key name two records.
  const reshaped = { ...binding, version: "2", primaryKey: ["text"] };
  const otherDeclaration = {
    ...upsert("new-declaration", 3),
    declaration: reshaped,
    recordKey: "same-key",
    data: { id: "x", text: "same-key" },
  };
  const both = {
    ...context,
    declarations: [
      ...context.declarations,
      { ...context.declarations[0], binding: reshaped },
    ],
  };
  const conflict = planReplicaMerge(both, [
    registration,
    upsert("a", 2),
    otherDeclaration,
  ]);
  expect(conflict.records[0].quarantined).toBe(true);
  expect(conflict.conflicts[0].reason).toBe("incompatible_record_declaration");
  // Not retained, but a retained stream has another shape: never applies.
  const incompatible = planReplicaMerge(context, [
    registration,
    otherDeclaration,
  ]);
  expect(incompatible.records).toEqual([]);
  expect(incompatible.pending[0].reason).toBe("incompatible_declaration");
  // A stream with no retained binding at all waits for its declaration.
  const undeclared = {
    ...otherDeclaration,
    declaration: { ...reshaped, stream: "other-stream" },
  };
  const unknown = planReplicaMerge(context, [registration, undeclared]);
  expect(unknown.pending[0].reason).toBe("missing_declaration");
});

it("applies a carried version of a retained stream by key, without its schema", () => {
  // A peer still holds an older version this device never retained: same
  // stream, semantics and key, another digest, version and schema.
  const carried = {
    ...binding,
    digest: `sha256:${"e".repeat(64)}`,
    version: "0.9.0",
    schemaDigest: `sha256:${"f".repeat(64)}`,
  };
  const strict = {
    ...context,
    declarations: context.declarations.map((entry) => ({
      ...entry,
      validateData: () => false,
    })),
  };
  const old = (operationId: string, counter: number, data = {}) => ({
    ...upsert(operationId, counter, operationId, "device-b"),
    declaration: carried,
    data: { id: "same-key", text: operationId, ...data },
  });
  // The retained schema would reject this data; the carried version's schema
  // is unknown, so the key alone decides.
  const applied = planReplicaMerge(strict, [registration, old("older", 2)]);
  expect(applied.pending).toEqual([]);
  expect(applied.records[0].winner).toEqual(old("older", 2));
  // A key that does not match the data is still rejected.
  const wrongKey = { ...old("bad-key", 3), recordKey: "other-key" };
  expect(
    planReplicaMerge(strict, [registration, wrongKey]).rejected[0].reason,
  ).toBe("invalid_record_data");
  // It merges by revision with the retained version, and a delete under the
  // carried version stays a delete.
  const merged = assertPermutations([
    registration,
    old("older", 2),
    upsert("newer", 3),
  ]);
  expect(merged.records[0].winner).toEqual(upsert("newer", 3));
  const removal: ReplicaOperation = {
    ...identity,
    kind: "delete",
    declaration: carried,
    recordKey: "same-key",
    emittedAt: "2026-10-20T00:00:00Z",
    deletedAt: "2026-10-20T00:00:00Z",
    revision: { counter: 4, writerId: "device-b", operationId: "removed" },
  };
  const deleted = assertPermutations([
    registration,
    upsert("newer", 3),
    removal,
  ]);
  expect(deleted.records[0].winner?.kind).toBe("delete");
});

it("merges versions of one declared stream by revision, each valid under its own schema", () => {
  // A rebinding: the same stream, semantics and key under a new version and
  // schema. Neither version's writes quarantine the other's.
  const upgraded = {
    ...binding,
    digest: `sha256:${"c".repeat(64)}`,
    version: "2.0.0",
    schemaDigest: `sha256:${"d".repeat(64)}`,
  };
  const versions = {
    ...context,
    declarations: [
      ...context.declarations,
      {
        sourceId: identity.sourceId,
        binding: upgraded,
        // The new schema requires a field the old data lacks.
        validateData: (data: Record<string, unknown>) =>
          typeof data.text === "string" && typeof data.lang === "string",
      },
    ],
  };
  const v2 = (operationId: string, counter: number, writerId = "device-a") => ({
    ...upsert(operationId, counter, operationId, writerId),
    declaration: upgraded,
    data: { id: "same-key", text: operationId, lang: "en" },
  });
  const assertVersions = (operations: ReplicaOperation[]) => {
    const expected = planReplicaMerge(versions, operations);
    for (const order of permutations(operations))
      expect(planReplicaMerge(versions, [...order, ...order])).toEqual(
        expected,
      );
    return expected;
  };
  // A device still on 1.0.0 wrote last: its value wins over the upgraded one.
  const older = assertVersions([
    registration,
    v2("upgraded", 2),
    upsert("not-upgraded", 3, "not-upgraded", "device-b"),
  ]);
  expect(older.conflicts).toEqual([]);
  expect(older.records[0].quarantined).toBe(false);
  expect(older.records[0].winner?.revision.operationId).toBe("not-upgraded");
  expect(older.records[0].losers.map((op) => op.revision.operationId)).toEqual([
    "upgraded",
  ]);
  // The upgraded write is newer: it wins; the 1.0.0 value is retained.
  const newer = assertVersions([
    registration,
    upsert("a", 2),
    v2("upgraded", 3, "device-b"),
  ]);
  expect(newer.records[0].winner?.declaration).toEqual(upgraded);
  // Old data is not checked against the new schema, nor new data against old.
  expect(newer.rejected).toEqual([]);
  // A delete under one version and a later upsert under the other: the
  // ordinary resurrection rule, nothing version specific.
  const deleted = assertVersions([
    registration,
    v2("upgraded", 2),
    { ...mutableVectors[2], revision: { ...mutableVectors[2].revision } },
  ]);
  expect(deleted.records[0].winner?.kind).toBe("delete");
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
