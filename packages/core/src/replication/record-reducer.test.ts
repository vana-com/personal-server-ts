import { describe, expect, it } from "vitest";
import { createReplicaRecordReducer } from "./record-reducer.js";
import { planReplicaMerge, type MergeContext } from "./merge-plan.js";
import {
  binding,
  identity,
  registration,
  mutableVectors,
  upsert,
} from "./fixtures.js";
import type { ReplicaOperation, RecordOperation } from "./envelope.js";

const visible = (
  record: ReturnType<typeof planReplicaMerge>["records"][number] | undefined,
) =>
  record
    ? {
        identity: record.identity,
        current: record.current,
        quarantined: record.quarantined,
      }
    : undefined;
for (const semantics of ["mutable_state", "append_only"] as const)
  describe(`${semantics} bounded record reducer`, () => {
    it("matches the complete shared planner across deterministic permutations", () => {
      const declaration = { ...binding, semantics };
      const alternate = {
        ...declaration,
        version: "2",
        digest: `sha256:${"c".repeat(64)}`,
      };
      const context: MergeContext = {
        owner: identity.owner,
        declarations: [declaration, alternate].map((binding) => ({
          sourceId: identity.sourceId,
          binding,
          validateData: (data) => typeof data.id === "string",
        })),
      };
      const records: RecordOperation[] = mutableVectors.map((op) => ({
        ...op,
        declaration,
      }));
      records.push({ ...upsert("alternate", 3), declaration: alternate });
      records.push({
        ...upsert("invalid", 20),
        data: { wrong: "key" },
        declaration,
      });
      records.push({ ...upsert("future", 21), generation: 2, declaration });
      const lifecycles: ReplicaOperation[][] = [
        [],
        [registration],
        [
          registration,
          {
            ...identity,
            kind: "connection-reset",
            generation: 2,
            previousGeneration: 1,
            revision: { logical: 7, writerId: "writer", operationId: "reset2" },
          },
        ],
        [
          registration,
          {
            ...identity,
            kind: "connection-reset",
            generation: 3,
            previousGeneration: 2,
            revision: { logical: 7, writerId: "writer", operationId: "reset3" },
          },
        ],
        [
          registration,
          {
            ...identity,
            kind: "connection-delete",
            revision: { logical: 9, writerId: "writer", operationId: "delete" },
          },
        ],
      ];
      let random = 17;
      for (let round = 0; round < 100; round++) {
        const ordered = [...records];
        for (let i = ordered.length - 1; i > 0; i--) {
          random = (Math.imul(random, 1664525) + 1013904223) >>> 0;
          const j = random % (i + 1);
          [ordered[i], ordered[j]] = [ordered[j], ordered[i]];
        }
        const lifecycle = lifecycles[round % lifecycles.length];
        const reducer = createReplicaRecordReducer(context, lifecycle);
        for (const operation of ordered) {
          reducer.push(operation);
          reducer.push(operation);
        }
        expect(visible(reducer.record)).toEqual(
          visible(
            planReplicaMerge(context, [...lifecycle, ...ordered]).records[0],
          ),
        );
      }
    }, 30000);
  });
