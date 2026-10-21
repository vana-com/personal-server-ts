import { afterEach, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { summarizeAdditions } from "@opendatalabs/personal-server-ts-core/additions";
import { createPsLiteSyncManager } from "./sync.js";
import { createIndexedDbPsLiteStateStore } from "./state.js";
import { createMemoryPsLiteStorage } from "./test-support/memory.js";
import type { AdditionsWorkerPort } from "./additions-session.js";

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
it.each([
  { deadline: undefined, delay: 11_000, coverage: "behind", upload: false },
  { deadline: 120_000, delay: 11_000, coverage: "complete", upload: false },
  { deadline: 120_000, delay: 121_000, coverage: "behind", upload: false },
  { deadline: 120_000, delay: 11_000, coverage: null, upload: true },
])(
  "keeps recovery bounded with deadline $deadline and work $delay (upload=$upload)",
  async ({ deadline, delay, coverage, upload }) => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    vi.stubGlobal("navigator", {
      locks: {
        request: async (_name: string, _options: unknown, run: () => unknown) =>
          run(),
      },
    });
    const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const signature = await owner.signMessage({
      message: "vana-master-key-v1",
    });
    const query = {
      timezone: "UTC",
      days: 1,
      now: new Date("2026-10-20T00:00:00Z"),
    };
    const result = await summarizeAdditions({
      ...query,
      ledgers: [],
      coverage: "complete",
    });
    let resultTimer: ReturnType<typeof setTimeout>;
    const terminated = vi.fn(() => clearTimeout(resultTimer));
    const worker: AdditionsWorkerPort = {
      onmessage: null,
      onerror: null,
      terminate: terminated,
      postMessage() {
        resultTimer = setTimeout(
          () =>
            worker.onmessage?.({
              data: { kind: "result", result },
            } as MessageEvent),
          delay,
        );
      },
    };
    const { additions, syncManager } = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({}),
      storage: createMemoryPsLiteStorage(),
      stateStore: createIndexedDbPsLiteStateStore({
        dbName: crypto.randomUUID(),
      }),
      ownerSignature: signature,
      serverAccount: owner,
      ownerSyncSigner: {
        address: owner.address,
        signMessage: async () => signature,
        signMessageBounded: async () => signature,
        signAddData: async () => signature,
        signAddDataBounded: async () => signature,
        signLineageAttestation: async () => signature,
      },
      additionsWorkerFactory: () => worker,
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
      },
      additionsTimeBudgetMs: deadline,
    });
    await syncManager.stop();
    expect(additions).toBeDefined();
    vi.useFakeTimers({
      toFake: [
        "setTimeout",
        "clearTimeout",
        "setInterval",
        "clearInterval",
        "performance",
      ],
    });
    const pending = upload
      ? additions!.recordUpload({ scope: "test.records" })
      : additions!.summarize(query);
    await vi.advanceTimersByTimeAsync(
      Math.min(
        delay,
        upload ? Math.min(deadline ?? 10_000, 10_000) : (deadline ?? 10_000),
      ),
    );
    expect(terminated).toHaveBeenCalled();
    expect((await pending)?.coverage ?? null).toBe(coverage);
  },
);

it.each([
  ...[0, -1, 1.5, 120_001, Infinity, NaN].map((value) => ({
    field: "additionsTimeBudgetMs",
    value,
  })),
  ...[0, -1, 1.5, 32 * 1024 * 1024 + 1, Infinity, NaN].map((value) => ({
    field: "additionsByteBudget",
    value,
  })),
])(
  "rejects invalid $field=$value before starting work",
  async ({ field, value }) => {
    const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
    await expect(
      createPsLiteSyncManager({
        config: ServerConfigSchema.parse({}),
        storage: createMemoryPsLiteStorage(),
        stateStore: createIndexedDbPsLiteStateStore({
          dbName: crypto.randomUUID(),
        }),
        ownerSignature: await owner.signMessage({
          message: "vana-master-key-v1",
        }),
        serverAccount: owner,
        [field]: value,
      }),
    ).rejects.toThrow(RangeError);
  },
);

it.each([undefined, false])(
  "allows metrics without starting sync (autoStartSync=%s)",
  async (autoStartSync) => {
    vi.stubGlobal("indexedDB", new IDBFactory());
    const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
    const signature = await owner.signMessage({
      message: "vana-master-key-v1",
    });
    const feed = vi.fn(async () => ({ dataPoints: [], cursor: null }));
    vi.useFakeTimers({
      toFake: [
        "setTimeout",
        "clearTimeout",
        "setInterval",
        "clearInterval",
        "performance",
      ],
    });
    const { syncManager, additions } = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({}),
      storage: createMemoryPsLiteStorage(),
      stateStore: createIndexedDbPsLiteStateStore({
        dbName: crypto.randomUUID(),
      }),
      ownerSignature: signature,
      serverAccount: owner,
      ownerSyncSigner: {
        address: owner.address,
        signMessage: async () => signature,
        signMessageBounded: async () => signature,
        signAddData: async () => signature,
        signAddDataBounded: async () => signature,
        signLineageAttestation: async () => signature,
      },
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: feed,
      },
      ...{ autoStartSync },
    });
    try {
      expect(additions).toBeDefined();
      await vi.advanceTimersByTimeAsync(120_000);
      const running = syncManager.running;
      await syncManager.stop();
      expect(running).toBe(autoStartSync !== false);
      if (autoStartSync === false) expect(feed).not.toHaveBeenCalled();
      else expect(feed).toHaveBeenCalled();
    } finally {
      await syncManager.stop();
    }
  },
);
