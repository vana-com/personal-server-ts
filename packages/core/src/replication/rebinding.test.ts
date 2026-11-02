import { describe, expect, it } from "vitest";
import { planReplicaRebinding, type ReplicaBindingEntry } from "./rebinding.js";

const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const v1: ReplicaBindingEntry = { sourceId: "s", binding };
const v2: ReplicaBindingEntry = {
  sourceId: "s",
  binding: {
    ...binding,
    digest: `sha256:${"c".repeat(64)}`,
    version: "2",
    schemaDigest: `sha256:${"d".repeat(64)}`,
  },
};
const other: ReplicaBindingEntry = { sourceId: "t", binding };

describe("planReplicaRebinding", () => {
  it("keeps the generation for the same bindings in any order", () => {
    expect(planReplicaRebinding([v1, other], [v1, other], [other, v1])).toEqual(
      { tag: "unchanged" },
    );
  });

  it("rebinds a declaration upgrade and retires the old version", () => {
    expect(planReplicaRebinding([v1], [v1], [v2])).toEqual({
      tag: "rebind",
      added: [v2],
      retired: [v1],
    });
  });

  it("rebinds an added connector", () => {
    expect(planReplicaRebinding([v1], [v1], [v1, other])).toEqual({
      tag: "rebind",
      added: [other],
      retired: [],
    });
  });

  it("returning to a retained version adds nothing new", () => {
    expect(planReplicaRebinding([v2], [v1, v2], [v1])).toEqual({
      tag: "rebind",
      added: [],
      retired: [v2],
    });
  });

  it("refuses a changed shape against any retained version", () => {
    const reshaped = (patch: Partial<typeof binding>): ReplicaBindingEntry => ({
      sourceId: "s",
      binding: { ...v2.binding, version: "3", ...patch },
    });
    for (const next of [
      reshaped({ primaryKey: ["text"] }),
      reshaped({ semantics: "append_only" }),
    ])
      expect(planReplicaRebinding([v2], [v1, v2], [next])).toEqual({
        tag: "refused",
        reason:
          "replication rebinding refused: s stream messages changed its semantics or primary key",
      });
    // The shape of a stream retired by a generation still counts.
    expect(
      planReplicaRebinding(
        [other],
        [v1, other],
        [other, reshaped({ primaryKey: ["k"] })],
      ),
    ).toMatchObject({ tag: "refused" });
  });

  it("treats the same stream name of another source as another stream", () => {
    const elsewhere: ReplicaBindingEntry = {
      sourceId: "t",
      binding: { ...binding, primaryKey: ["text"] },
    };
    expect(planReplicaRebinding([v1], [v1], [v1, elsewhere])).toMatchObject({
      tag: "rebind",
    });
  });
});
