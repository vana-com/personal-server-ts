import { describe, expect, it } from "vitest";
import { createInMemoryPdppGrantBindingStore } from "./pdpp-binding-store.js";
import {
  writerExposureFromBindings,
  writerHasPdppExposure,
} from "./writer-exposure.js";

const BUILDER = "0x00000000000000000000000000000000000000Ab" as const;

function binding(grantee: string, id: string) {
  return {
    pdppGrantId: id,
    permission: {
      chainId: 14800,
      contractAddress: "0x0000000000000000000000000000000000000001" as const,
      permissionId: `perm-${id}`,
    },
    ownerAddress: "0x0000000000000000000000000000000000000002" as const,
    granteeAddress: grantee as `0x${string}`,
    pdppClientId: "client",
    granteeId: "builder-id",
    grantVersion: "1",
    boundAt: "2026-09-01T00:00:00.000Z",
  };
}

describe("writerHasPdppExposure", () => {
  it("is true for any retained binding, whatever its grant's current state, case-insensitively", async () => {
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(binding(BUILDER.toLowerCase(), "g1"));
    const policy = writerExposureFromBindings(store);
    expect(await writerHasPdppExposure(policy, BUILDER)).toBe(true);
    expect(
      await writerHasPdppExposure(
        policy,
        "0x00000000000000000000000000000000000000cd",
      ),
    ).toBe(false);
  });

  it("fails closed: no policy and a failing lookup are exposed; only pdpp-disabled is not", async () => {
    expect(await writerHasPdppExposure(undefined, BUILDER)).toBe(true);
    expect(
      await writerHasPdppExposure(
        {
          kind: "lookup",
          hasExposure: async () => {
            throw new Error("down");
          },
        },
        BUILDER,
      ),
    ).toBe(true);
    expect(
      await writerHasPdppExposure({ kind: "pdpp-disabled" }, BUILDER),
    ).toBe(false);
  });
});
