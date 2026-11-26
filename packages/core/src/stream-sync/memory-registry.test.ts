// The in-memory registry serves the gateway's batch contract: one
// all-or-nothing request. A batch that fails a condition on its own writes
// leaves no trace, and a request that runs beside it is not disturbed.
import { expect, it } from "vitest";
import { MemoryStreamSyncRegistry } from "./memory-registry.js";
import type { SignedBatchRow } from "./ports.js";

const OWNER = "0x0000000000000000000000000000000000000001";
const hash = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as const;
const row = (scope: string, n: number): SignedBatchRow => ({
  scope,
  dataHash: hash(n),
  metadataHash: hash(n + 100),
  expectedVersion: "1",
  signature: hash(n + 200),
});

it("a batch whose post-write condition fails is not seen, and does not drop a concurrent write", async () => {
  const registry = new MemoryStreamSyncRegistry();
  // The batch holds at its post-write condition on "a".
  let release!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  let paused!: () => void;
  const reached = new Promise<void>((resolve) => (paused = resolve));
  let armed = true;
  registry.beforeRead = async (scope) => {
    if (scope !== "a" || !armed) return;
    armed = false;
    paused();
    await held;
  };
  const batch = registry.postBatch({
    ownerAddress: OWNER,
    rows: [row("a", 1)],
    // After the write "a" is at version 1: this condition fails.
    requires: [{ scope: "a", expectedVersion: "2", notDeleted: false }],
  });
  await reached;

  // A reader does not see a head that the batch would roll back.
  expect(await registry.read("a")).toEqual({ found: false });
  // An unrelated write commits while the batch holds.
  expect(
    await registry.post({
      ownerAddress: OWNER,
      scope: "b",
      dataHash: hash(2),
      metadataHash: hash(102),
      expectedVersion: "1",
      signature: hash(202),
    }),
  ).toEqual({ kind: "committed" });
  release();

  const result = await batch;
  expect(result.kind).toBe("precondition_failed");
  expect(await registry.read("a")).toEqual({ found: false });
  expect((await registry.read("b")).found).toBe(true);
  // The unrelated write's change entry is kept; the batch left none.
  expect(registry.log).toEqual([{ scope: "b", version: 1, dataHash: hash(2) }]);
});
