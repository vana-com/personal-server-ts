import { describe, expect, it } from "vitest";
import {
  REPLICA_LIVE_COPY_FACTOR,
  REPLICA_MAX_BLOB_BYTES,
  REPLICA_MAX_FRAGMENTS,
  REPLICA_MAX_TOTAL_BYTES,
  ReplicaByteBudget,
  admit,
} from "./limits.js";

const identity = {
  repositoryId: "repo-a",
  owner: "owner-a",
  manifestDigest: "sha256:manifest",
};

describe("replication admission limits", () => {
  it("admits a declared batch without reserving it and accounts one read at a time", () => {
    const budget = new ReplicaByteBudget(100);
    const admission = admit(
      { totalBytes: 10, fragments: [{ bytes: 10 }, { bytes: 15 }] },
      budget,
      identity,
    );

    expect(admission).not.toHaveProperty("kind");
    if ("kind" in admission) throw new Error("expected admission");
    expect(budget.reserved).toBe(0);
    const firstRead = admission.reserveObject(20);
    expect(firstRead).not.toHaveProperty("kind");
    if (typeof firstRead !== "function")
      throw new Error("expected first object reservation");
    expect(budget.reserved).toBe(20 * REPLICA_LIVE_COPY_FACTOR);
    const secondRead = admission.reserveObject(10);
    expect(secondRead).toMatchObject({ kind: "resource_busy" });
    firstRead();
    firstRead();
    expect(budget.reserved).toBe(0);
    const afterRelease = admission.reserveObject(10);
    expect(afterRelease).not.toHaveProperty("kind");
    if (typeof afterRelease === "function") afterRelease();
    expect(budget.reserved).toBe(0);
  });

  it("rejects declared totals beyond static limits before reserving", () => {
    const budget = new ReplicaByteBudget(Number.MAX_SAFE_INTEGER);
    expect(
      admit(
        { totalBytes: REPLICA_MAX_TOTAL_BYTES + 1, fragments: [{ bytes: 1 }] },
        budget,
        identity,
      ),
    ).toMatchObject({ kind: "resource_unsupported", limit: "total_bytes" });
    expect(
      admit(
        { totalBytes: 1, fragments: [{ bytes: REPLICA_MAX_BLOB_BYTES + 1 }] },
        budget,
        identity,
      ),
    ).toMatchObject({
      kind: "resource_unsupported",
      limit: "fragment_ciphertext_bytes",
    });
    expect(
      admit(
        {
          totalBytes: 1,
          fragments: Array.from({ length: REPLICA_MAX_FRAGMENTS + 1 }, () => ({
            bytes: 1,
          })),
        },
        budget,
        identity,
      ),
    ).toMatchObject({ kind: "resource_unsupported" });
    expect(budget.reserved).toBe(0);
  });

  it("R6 returns resource_busy when concurrent admissions exceed one process budget", () => {
    const budget = new ReplicaByteBudget(60);
    const first = admit(
      { totalBytes: 10, fragments: [{ bytes: 10 }] },
      budget,
      identity,
    );
    const second = admit(
      { totalBytes: 10, fragments: [{ bytes: 11 }] },
      budget,
      { ...identity, manifestDigest: "sha256:other" },
    );

    expect(first).not.toHaveProperty("kind");
    expect(second).not.toHaveProperty("kind");
    if ("kind" in first || "kind" in second)
      throw new Error("expected both manifests admitted");
    const firstRead = first.reserveObject(10);
    const secondRead = second.reserveObject(11);
    expect(firstRead).not.toHaveProperty("kind");
    expect(secondRead).toMatchObject({ kind: "resource_busy" });
    expect(budget.reserved).toBe(10 * REPLICA_LIVE_COPY_FACTOR);
    if (typeof firstRead === "function") firstRead();
    expect(budget.reserved).toBe(0);
  });
});
