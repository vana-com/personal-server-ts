import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import type { UploadWorkerDeps } from "./upload.js";
import { uploadAll } from "./upload.js";
import { createUploadStateTracker } from "../upload-state.js";
import {
  CRASHED_UPLOAD_REASON,
  createMemoryUploadAttemptStore,
  createUploadAttemptLedger,
  type UploadAttemptStore,
} from "../upload-attempts.js";
import type { IndexEntry } from "../../storage/index/types.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type {
  DataFileEnvelope,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";

vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const DATA_POINT_ID = `0x${"de".repeat(32)}`;

function makeEntry(n: number, overrides?: Partial<IndexEntry>): IndexEntry {
  const collectedAt = `2026-11-07T10:0${n}:00Z`;
  return {
    id: n,
    fileId: null,
    schemaId: null,
    path: `scope.${n}/${collectedAt}.json`,
    scope: `scope.${n}`,
    collectedAt,
    createdAt: collectedAt,
    sizeBytes: 1024,
    version: 1,
    dataPointId: null,
    ...overrides,
  };
}

/** The part of a host that survives a process death: the index rows. */
function makeIndex(initial: IndexEntry[]) {
  const rows = [...initial];
  /** Paths whose body read never settles: the process dies there. */
  const dies = new Set<string>();
  const reads: string[] = [];
  const storage: Partial<DataStoragePort> = {
    findUnsynced: vi.fn(() => rows.filter((row) => row.dataPointId === null)),
    updateDataPointId: vi.fn((path: string, id: string | null) => {
      const row = rows.find((r) => r.path === path);
      if (row) row.dataPointId = id;
      return true;
    }),
    updateEntryVersion: vi.fn().mockReturnValue(true),
    readEnvelope: vi.fn((scope: string, collectedAt: string) => {
      const row = rows.find(
        (r) => r.scope === scope && r.collectedAt === collectedAt,
      )!;
      reads.push(row.path);
      if (dies.has(row.path)) return new Promise<DataFileEnvelope>(() => {});
      return Promise.resolve({
        version: "1.0",
        scope,
        collectedAt,
        data: { ok: true },
      } as DataFileEnvelope);
    }),
  };
  return { rows, dies, reads, storage };
}

/** One process lifetime: fresh deps, tracker and (via `store`) ledger. */
function boot(
  index: ReturnType<typeof makeIndex>,
  store: UploadAttemptStore,
  overrides: Partial<UploadWorkerDeps> = {},
) {
  const registerDataPoint = vi
    .fn()
    .mockResolvedValue({ dataPointId: DATA_POINT_ID, expectedVersion: "1" });
  const uploadState = createUploadStateTracker();
  const deps: UploadWorkerDeps = {
    storage: index.storage as DataStoragePort,
    storageAdapter: {
      upload: vi.fn().mockResolvedValue("https://storage.test/blob"),
      urlForKey: (key: string) => `https://storage.test/${key}`,
      exists: vi.fn().mockResolvedValue(true),
    } as unknown as StorageAdapter,
    gateway: {
      getDataPoint: vi.fn().mockResolvedValue(null),
      registerDataPoint,
    } as unknown as GatewayClient,
    signer: {
      signAddData: vi.fn().mockResolvedValue("0xsig"),
      signLineageAttestation: vi.fn().mockResolvedValue("0xsig"),
    } as unknown as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger: {
      info: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
      debug: vi.fn(),
    } as unknown as Logger,
    uploadState,
    uploadAttempts: createUploadAttemptLedger(store, OWNER),
    ...overrides,
  };
  return { deps, uploadState, registerDataPoint };
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  vi.clearAllMocks();
  (deriveScopeKey as ReturnType<typeof vi.fn>).mockReturnValue(
    new Uint8Array(32).fill(0xbb),
  );
  (encryptWithPassword as ReturnType<typeof vi.fn>).mockResolvedValue(
    new Uint8Array([1, 2, 3, 4]),
  );
});

describe("uploadAll — durable attempt markers", () => {
  it("does not pick an entry that killed the process a third time, and uploads the next scope", async () => {
    const a = makeEntry(1);
    const b = makeEntry(2);
    const index = makeIndex([a, b]);
    index.dies.add(a.path);
    const store = createMemoryUploadAttemptStore();

    // Boot 1 and 2: the attempt on A never settles; the process "dies".
    for (let boots = 0; boots < 2; boots++) {
      const { deps } = boot(index, store);
      void uploadAll(deps);
      await flush();
    }
    expect(index.reads.filter((p) => p === a.path)).toHaveLength(2);
    expect(index.reads).not.toContain(b.path);

    // Boot 3: A is quarantined, B uploads.
    const third = boot(index, store);
    const results = await uploadAll(third.deps);

    expect(index.reads.filter((p) => p === a.path)).toHaveLength(2);
    expect(results.map((r) => r.path)).toEqual([b.path]);
    expect(third.uploadState.snapshot().stopped).toEqual([
      expect.objectContaining({
        scope: a.scope,
        path: a.path,
        lastError: CRASHED_UPLOAD_REASON,
      }),
    ]);
  });

  it("settles the marker after a success and after a caught failure, so no crash is counted", async () => {
    const a = makeEntry(1);
    const index = makeIndex([a]);
    const store = createMemoryUploadAttemptStore();

    const first = boot(index, store);
    first.registerDataPoint.mockRejectedValueOnce(new Error("503"));
    await uploadAll(first.deps);
    expect(await store.read()).toEqual([]);

    const second = boot(index, store);
    await uploadAll(second.deps, {
      now: () => new Date(Date.now() + 3_600_000),
    });
    expect(await store.read()).toEqual([]);
  });

  it("uploads normally when new data replaced the quarantined entry version", async () => {
    const a = makeEntry(1);
    const index = makeIndex([a]);
    index.dies.add(a.path);
    const store = createMemoryUploadAttemptStore();
    for (let boots = 0; boots < 2; boots++) {
      void uploadAll(boot(index, store).deps);
      await flush();
    }
    const quarantined = boot(index, store);
    expect(await uploadAll(quarantined.deps)).toEqual([]);

    // New data lands at the same path: a different version and size.
    index.rows[0] = { ...a, version: 2, sizeBytes: 2048 };
    index.dies.clear();
    const next = boot(index, store);
    const results = await uploadAll(next.deps);

    expect(results.map((r) => r.path)).toEqual([a.path]);
    expect(next.uploadState.snapshot().stopped).toEqual([]);
  });

  it("keeps the count and the quarantine when the host is rebuilt", async () => {
    const a = makeEntry(1);
    const index = makeIndex([a]);
    index.dies.add(a.path);
    const store = createMemoryUploadAttemptStore();

    void uploadAll(boot(index, store).deps);
    await flush();
    // One interrupted attempt so far. A rebuilt host sees it and allows one
    // more, never a fresh budget.
    const rebuilt = boot(index, store);
    void uploadAll(rebuilt.deps);
    await flush();
    expect(index.reads).toHaveLength(2);

    for (let rebuilds = 0; rebuilds < 3; rebuilds++) {
      const again = boot(index, store);
      await uploadAll(again.deps);
      expect(again.uploadState.snapshot().stopped).toHaveLength(1);
    }
    expect(index.reads).toHaveLength(2);
  });

  it("lets the owner retry a quarantined entry", async () => {
    const a = makeEntry(1);
    const index = makeIndex([a]);
    index.dies.add(a.path);
    const store = createMemoryUploadAttemptStore();
    for (let boots = 0; boots < 2; boots++) {
      void uploadAll(boot(index, store).deps);
      await flush();
    }
    const host = boot(index, store);
    await uploadAll(host.deps);
    expect(host.uploadState.snapshot().stopped).toHaveLength(1);

    index.dies.clear();
    await host.deps.uploadAttempts!.release();
    host.uploadState.clearScope(a.scope);
    const results = await uploadAll(host.deps);
    expect(results.map((r) => r.path)).toEqual([a.path]);
  });

  describe("attempt deadline", () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    it("aborts a never-settling upload at the deadline, records a caught failure and moves on", async () => {
      const a = makeEntry(1);
      const b = makeEntry(2);
      const index = makeIndex([a, b]);
      index.dies.add(a.path);
      const store = createMemoryUploadAttemptStore();
      const { deps, uploadState } = boot(index, store);

      const run = uploadAll(deps, { attemptDeadlineMs: 5_000 });
      await vi.advanceTimersByTimeAsync(5_000);
      const results = await run;

      expect(results.map((r) => r.path)).toEqual([b.path]);
      expect(uploadState.snapshot().retrying).toEqual([
        expect.objectContaining({
          path: a.path,
          failures: 1,
          lastError: expect.stringMatching(/deadline/i),
        }),
      ]);
      // A caught failure settles the marker: it is not a crash.
      expect(await store.read()).toEqual([]);
    });
  });
});

describe("attempt ledger — paged scans", () => {
  it("keeps markers for rows a partial scan did not reach, and drops those it covered", async () => {
    const store = createMemoryUploadAttemptStore();
    const ledger = createUploadAttemptLedger(store, OWNER);
    const early = makeEntry(1);
    const late = makeEntry(9);
    await ledger.begin(early);
    await ledger.begin(late);

    // The scan covered ids 0..5 and listed neither row.
    await ledger.reconcile([], { afterId: 0, throughId: 5 });

    expect((await store.read())?.map((r) => r.path)).toEqual([late.path]);
  });
});
