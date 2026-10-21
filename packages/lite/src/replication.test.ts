import { expect, it } from "vitest";
import { createLiteReplicaWorker } from "./replication.js";
import { createFakeCanonicalPersistence } from "./test-support/canonical-persistence.js";

it("retries later retained-connection pages when their dependency becomes valid", async () => {
  const persistence = createFakeCanonicalPersistence();
  const retryCursors: (string | undefined)[] = [];
  let laterDependencyReconciled = false;
  const store = {
    acknowledgeOutbox: async () => {},
    readOutboxPage: async () => ({ entries: [] }),
    readBlob: async function* () {},
    retry: async ({ after }: { after?: string }) => {
      retryCursors.push(after);
      // Model 101 retained connections: the first native page ends at 100.
      if (after === undefined) return { after: "retained-100" };
      if (after === "retained-100") {
        laterDependencyReconciled = true;
        return { after: undefined };
      }
      throw new Error("unexpected retained-connection cursor");
    },
  } as never;
  const worker = createLiteReplicaWorker({
    enabled: true,
    persistence: persistence.port,
    store,
    expected: () => ({ owner: "owner" }) as never,
    credential: "owner credential",
    transport: {
      list: async () => ({ scopes: [], cursor: null }),
      encrypt: async () => new Uint8Array(),
      decrypt: async () => new Uint8Array(),
    } as never,
  });

  await worker.cycle();
  await worker.cycle();
  await worker.cycle();

  expect(retryCursors).toEqual([undefined, "retained-100", undefined]);
  expect(laterDependencyReconciled).toBe(true);
});

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
