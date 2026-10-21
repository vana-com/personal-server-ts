import { expect, it, vi } from "vitest";
import { createReplicaFinalityHints } from "./finality.js";
it("observes only the finalized tag as a scheduling hint", async () => {
  const getBlock = vi.fn(async () => ({ number: 123n }));
  const hints = createReplicaFinalityHints({ rpc: { getBlock } });
  expect(await hints.head()).toBe(123n);
  expect(getBlock).toHaveBeenCalledWith({ blockTag: "finalized" });
});
it("propagates unavailable or malformed heads rather than inventing a wake height", async () => {
  const rpc = {
    getBlock: vi.fn(async (): Promise<{ number: bigint | null }> => ({
      number: null,
    })),
  };
  const hints = createReplicaFinalityHints({ rpc });
  await expect(hints.head()).rejects.toThrow("missing finalized");
  rpc.getBlock.mockRejectedValueOnce(new Error("offline"));
  await expect(hints.head()).rejects.toThrow("offline");
});
