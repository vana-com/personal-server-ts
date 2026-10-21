import { expect, it } from "vitest";
import { createLiteReplicaWorker } from "./replication.js";

it("does no persistence or network work unless explicitly enabled", async () => {
  const unexpected = () => {
    throw new Error("flag-off side effect");
  };
  const worker = createLiteReplicaWorker({
    persistence: {
      transaction: unexpected,
      stageBlob: unexpected,
      readBlob: unexpected,
    },
    store: {} as never,
    expected: unexpected,
    credential: undefined,
    transport: new Proxy({}, { get: unexpected }) as never,
  });
  await expect(worker.cycle()).resolves.toBeUndefined();
});
