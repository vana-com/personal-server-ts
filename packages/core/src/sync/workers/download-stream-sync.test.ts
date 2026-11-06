import { describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { Logger } from "../../logger/index.js";
import type { DataPointFeedRecord } from "../../ports/index.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { createMemoryStreamSyncReadFiles } from "../../stream-sync-read/memory-files.js";
import { createStreamSyncReadKeys } from "../../stream-sync-read/keys.js";
import { StreamSyncReadService } from "../../stream-sync-read/service.js";
import { downloadAll, downloadOne, downloadScopes } from "./download.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const NS = "0123456789abcdef";
const DELETED_AT = "2026-11-01T00:00:00Z";

function row(
  scope: string,
  overrides: Partial<DataPointFeedRecord> = {},
): DataPointFeedRecord {
  return {
    id: `0x${scope.length.toString(16).padStart(64, "0")}`,
    ownerAddress: OWNER,
    scope,
    dataHash: `0x${"11".repeat(32)}`,
    metadataHash: `0x${"22".repeat(32)}`,
    expectedVersion: "2",
    addedAt: "2026-11-01T00:00:00Z",
    deletedAt: null,
    ...overrides,
  };
}

// Every physical shape the registry can hold: stream and control rows, the
// identity-less namespace, and tombstones of each.
const PHYSICAL = [
  row(`pdpp.acme~${NS}.items`),
  row(`pdpp.acme~${NS}`),
  row("pdpp.acme~.items"),
  row("pdpp.acme~"),
  row(`pdpp.acme~${NS}.gone`, { deletedAt: DELETED_AT }),
  row(`pdpp.acme~${NS}`, { deletedAt: DELETED_AT, expectedVersion: "3" }),
];

function deps(rows: DataPointFeedRecord[]) {
  const storage = createMemoryDataStorage();
  const download = vi.fn(async () => {
    throw new Error("no legacy blob may be fetched");
  });
  const cursor = {
    read: vi.fn(async () => null),
    write: vi.fn(async () => undefined),
  };
  const scopeDeletions = {
    markDeleted: vi.fn(),
    markLive: vi.fn(),
    noteFeedSynced: vi.fn(),
    knownDeletion: vi.fn(() => null),
    feedAgeMs: vi.fn(() => null),
    resolve: vi.fn(),
    maxStalenessMs: 0,
  };
  const logger = {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  };
  return {
    storage,
    download,
    cursor,
    scopeDeletions,
    logger,
    deps: {
      storage,
      storageAdapter: {
        urlForKey: (key: string) => `https://storage.test/${key}`,
        download,
        exists: vi.fn(async () => false),
      } as unknown as StorageAdapter,
      gateway: {} as GatewayClient,
      cursor,
      masterKey: new Uint8Array(65).fill(7),
      serverOwner: OWNER,
      logger: logger as unknown as Logger,
      scopeDeletions,
      dataPointFeed: {
        listDataPointsByOwner: vi.fn(async () => ({
          dataPoints: rows,
          cursor: "next",
        })),
        getDataPoint: vi.fn(
          async ({ scope }: { scope: string }) =>
            rows.find((r) => r.scope === scope) ?? null,
        ),
      },
    },
  };
}

describe("download worker routing of stream-sync rows", () => {
  it("routes physical rows away from every legacy step without blocking the cursor", async () => {
    const t = deps(PHYSICAL);
    await expect(downloadAll(t.deps)).resolves.toEqual([]);
    expect(t.download).not.toHaveBeenCalled();
    expect(t.scopeDeletions.markDeleted).not.toHaveBeenCalled();
    expect(t.scopeDeletions.markLive).not.toHaveBeenCalled();
    expect(t.logger.error).not.toHaveBeenCalled();
    expect(t.cursor.write).toHaveBeenCalledWith("next");
    expect(t.storage.listVersions("pdpp.acme", { limit: 10 })).toEqual([]);
  });

  it("skips physical names in downloadOne and downloadScopes", async () => {
    const t = deps(PHYSICAL);
    await expect(downloadOne(t.deps, PHYSICAL[0]!)).resolves.toBeNull();
    await expect(
      downloadScopes(
        t.deps,
        PHYSICAL.map((r) => r.scope),
      ),
    ).resolves.toEqual([]);
    expect(t.download).not.toHaveBeenCalled();
  });

  it("hands every listed physical row to the stream-sync read side before the cursor moves", async () => {
    const t = deps([
      ...PHYSICAL,
      row("instagram.profile", { deletedAt: DELETED_AT }),
    ]);
    const service = await StreamSyncReadService.open({
      files: createMemoryStreamSyncReadFiles(),
      blobs: { get: async () => null },
      keys: await createStreamSyncReadKeys(new Uint8Array(65).fill(7)),
      logger: { info() {}, warn() {}, error() {} },
    });
    const observe = vi.spyOn(service, "observe");
    let observedBeforeCursor = false;
    t.cursor.write.mockImplementation(async () => {
      observedBeforeCursor = observe.mock.calls.length === 1;
    });
    await downloadAll({ ...t.deps, streamSync: service });
    expect(observe).toHaveBeenCalledWith(PHYSICAL, {
      fromStart: true,
      lastPage: false,
    });
    expect(observedBeforeCursor).toBe(true);
    // The legacy row still reaches the legacy deletion memory.
    expect(t.scopeDeletions.markDeleted).toHaveBeenCalledTimes(1);
    expect(t.scopeDeletions.markDeleted.mock.calls[0]![0]).toBe(
      "instagram.profile",
    );
    expect(service.status().connections.map((c) => [c.ns, c.control])).toEqual([
      ["", "foreign"],
      [NS, "deleted"],
    ]);
  });
});
