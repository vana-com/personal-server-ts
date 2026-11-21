/** Shared, executable Node/Lite prefix gate; never imported by runtime exports. */
import { describe, expect, it } from "vitest";
import { canonicalJson, type ReplicaOperation } from "./envelope.js";
import { registration, T0, upsert } from "./fixtures.js";
import { planReplicaMerge } from "./merge-plan.js";
import type { createBoundedReplicaReducer } from "./record-reducer.js";

import {
  conformanceContext,
  conformanceBudget as budget,
  conformanceEnabled as enabled,
  reducerVectors as vectors,
} from "./reducer-vectors.js";
const a = upsert("a", 10_000, "old", "A", T0);
const b = upsert("b", 1, "new", "B", T0 + 600_000);

function deliveryOrders(operations: ReplicaOperation[]): ReplicaOperation[][] {
  const rotate = operations.slice(1).concat(operations.slice(0, 1));
  const interleave = operations
    .filter((_, i) => i % 2)
    .concat(operations.filter((_, i) => !(i % 2)));
  return [
    operations,
    [...operations].reverse(),
    rotate,
    interleave,
    operations.flatMap((op) => [op, op]),
    [...operations, ...operations].reverse(),
  ];
}

export function defineReducerConformance(
  label: string,
  factory: typeof createBoundedReplicaReducer,
) {
  describe(`${label}: full retained set at EVERY delivery prefix`, () => {
    for (const vector of vectors)
      it(vector.name, () => {
        const expectedFinal = planReplicaMerge(
          conformanceContext,
          vector.operations,
        );
        for (const order of deliveryOrders(vector.operations)) {
          const reducer = factory(conformanceContext, enabled);
          const prefix: ReplicaOperation[] = [];
          for (const operation of order) {
            prefix.push(operation);
            const outcome = reducer.push([operation]);
            expect(outcome.status).toBe("accepted");
            expect(reducer.plan).toEqual(
              planReplicaMerge(conformanceContext, prefix),
            );
            expect(reducer.operationCount).toBe(
              new Set(prefix.map(canonicalJson)).size,
            );
          }
          expect(reducer.plan).toEqual(expectedFinal);
        }
      });
    it("is default off without reading or admitting evidence", () => {
      const reducer = factory(conformanceContext, { budget });
      expect(reducer.push([registration])).toEqual({
        status: "refused",
        reason: "replication_disabled",
      });
      expect(reducer.plan).toBeUndefined();
      expect(reducer.operationCount).toBe(0);
      expect(reducer.canonicalBytes).toBe(0);
    });
    it("refuses a whole count-overflow transaction without acknowledging a partial set", () => {
      const reducer = factory(conformanceContext, {
        ...enabled,
        budget: { ...budget, maxOperations: 2 },
      });
      reducer.push([registration]);
      const before = reducer.plan;
      expect(reducer.push([a, b])).toEqual({
        status: "refused",
        reason: "operation_capacity",
      });
      expect(reducer.operationCount).toBe(1);
      expect(reducer.plan).toEqual(before);
      expect(reducer.push([registration]).status).toBe("accepted");
    });
    it("counts UTF-8 bytes and refuses without retaining incoming variants", () => {
      const size = new TextEncoder().encode(
        canonicalJson(registration),
      ).byteLength;
      const reducer = factory(conformanceContext, {
        ...enabled,
        budget: { ...budget, maxCanonicalBytes: size },
      });
      expect(reducer.push([registration]).status).toBe("accepted");
      expect(reducer.canonicalBytes).toBe(size);
      expect(reducer.push([upsert("unicode", 1, "é😀")])).toEqual({
        status: "refused",
        reason: "byte_capacity",
      });
      expect(reducer.retainedOperations()).toEqual([registration]);
    });
    it("keeps malformed and externally mutated evidence from changing accepted state", () => {
      const reducer = factory(conformanceContext, enabled);
      const mutable = structuredClone(a);
      reducer.push([registration, mutable]);
      const before = reducer.plan;
      mutable.data.text = "caller mutation";
      expect(reducer.plan).toEqual(before);
      expect(reducer.push([{ ...b, generation: 0 }])).toEqual({
        status: "refused",
        reason: "invalid_evidence",
      });
      const evidence = reducer.retainedOperations();
      evidence.length = 0;
      expect(reducer.operationCount).toBe(2);
      expect(reducer.plan).toEqual(before);
    });
    it("reprojects late finality and rolls back failed context changes", () => {
      const reducer = factory(
        { ...conformanceContext, finalizedAt: () => undefined },
        enabled,
      );
      const operations = [
        registration,
        { ...a, batchId: "a" },
        { ...b, batchId: "b" },
      ];
      reducer.push(operations);
      const finalized = {
        ...conformanceContext,
        finalizedAt: (batch: string) => (batch === "b" ? T0 - 1 : T0),
      };
      expect(reducer.reproject(finalized).status).toBe("accepted");
      expect(reducer.plan).toEqual(planReplicaMerge(finalized, operations));
      const before = reducer.plan;
      expect(
        reducer.reproject({
          ...finalized,
          finalizedAt: () => {
            throw new Error("not verified");
          },
        }).status,
      ).toBe("refused");
      expect(reducer.plan).toEqual(before);
    });
  });
}
