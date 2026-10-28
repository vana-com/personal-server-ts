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
  it("reserves declared ciphertext copies and releases once", () => {
    const budget = new ReplicaByteBudget(100);
    const admission = admit(
      { totalBytes: 10, fragments: [{ bytes: 10 }, { bytes: 15 }] },
      budget,
      identity,
    );

    expect(admission).not.toHaveProperty("kind");
    if ("kind" in admission) throw new Error("expected admission");
    expect(admission.reservedBytes).toBe(25 * REPLICA_LIVE_COPY_FACTOR);
    expect(budget.reserved).toBe(admission.reservedBytes);
    admission.release();
    admission.release();
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
    const budget = new ReplicaByteBudget(80);
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
    expect(second).toMatchObject({ kind: "resource_busy" });
    expect(budget.reserved).toBe(10 * REPLICA_LIVE_COPY_FACTOR);
    if (!("kind" in first)) first.release();
    expect(budget.reserved).toBe(0);
  });
});
