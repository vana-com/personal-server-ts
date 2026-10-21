import { expect, it } from "vitest";
import { replicaStateVisible } from "./visibility-policy.js";

const cases = [
  {
    owner: "confirmed-only",
    grant: "confirmed-only",
    ownerStates: [true, false, false],
    grantStates: [true, false, false],
  },
  {
    owner: "include-pending",
    grant: "confirmed-only",
    ownerStates: [true, true, false],
    grantStates: [true, false, false],
  },
  {
    owner: "confirmed-only",
    grant: "include-pending",
    ownerStates: [true, false, false],
    grantStates: [true, true, false],
  },
  {
    owner: "include-pending",
    grant: "include-pending",
    ownerStates: [true, true, false],
    grantStates: [true, true, false],
  },
] as const;
for (const policy of cases)
  for (const reader of ["owner", "grant"] as const)
    for (const [index, state] of (
      ["confirmed", "pending", "quarantined"] as const
    ).entries())
      it(`${policy.owner}/${policy.grant}: ${reader} ${state}`, () => {
        expect(replicaStateVisible(state, reader, policy)).toBe(
          (reader === "owner" ? policy.ownerStates : policy.grantStates)[index],
        );
      });
it("defaults grants to confirmed-only and owners to pending preview", () => {
  expect(replicaStateVisible("pending")).toBe(false);
  expect(replicaStateVisible("pending", "owner")).toBe(true);
});

for (const policy of cases)
  for (const reader of ["owner", "grant"] as const)
    for (const origin of ["local", "received"] as const)
      it(`${policy.owner}/${policy.grant}: conflicted ${reader} ${origin}`, () => {
        expect(replicaStateVisible("conflicted", reader, policy, origin)).toBe(
          reader === "owner" && origin === "local",
        );
      });

it("does not infer local provenance for a conflicted record", () => {
  expect(replicaStateVisible("conflicted", "owner")).toBe(false);
});

for (const policy of cases)
  for (const reader of ["owner", "grant"] as const)
    it(`${policy.owner}/${policy.grant}: corruption quarantine hides local ${reader} rows`, () => {
      expect(replicaStateVisible("quarantined", reader, policy, "local")).toBe(
        false,
      );
    });

for (const policy of cases)
  for (const reader of ["owner", "grant"] as const)
    for (const reason of [
      "copy_conflict",
      "finalized_conflict",
      "corruption",
    ] as const)
      it(`${policy.owner}/${policy.grant}: ${reader} quarantine ${reason}`, () => {
        expect(
          replicaStateVisible(
            "quarantined",
            reader,
            policy,
            "received",
            reason,
          ),
        ).toBe(reader === "owner" && reason !== "corruption");
      });

it("maps copy quarantine reasons to distinct owner markers", async () => {
  const policy = await import("./visibility-policy.js");
  expect(policy.replicaCopyConflictMetadata("copy_conflict")).toEqual({
    visibility: "conflicted",
    status: "copy conflict",
  });
  expect(policy.replicaCopyConflictMetadata("finalized_conflict")).toEqual({
    visibility: "conflicted",
    status: "integrity conflict",
  });
});
