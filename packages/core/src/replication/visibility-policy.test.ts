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
