import { describe, it, expect, vi } from "vitest";

import {
  RETIRE_LEGACY_SCOPES_PER_CYCLE,
  retireLegacyScopes,
} from "./retire-legacy.js";
import { deleteScope } from "./delete.js";
import type { DeleteScopeResult } from "./delete.js";
import type { Logger } from "../../logger/index.js";
import type { DeleteDataPort, DataStoragePort } from "../../ports/index.js";
import { createMemoryPendingBlobDeletionStore } from "../pending-blob-deletions.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

function logger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
    error: vi.fn(),
  } as unknown as Logger & { info: ReturnType<typeof vi.fn> };
}

const entryFor = (scope: string) => ({
  id: 1,
  fileId: null,
  schemaId: null,
  path: `${scope}/x.json`,
  scope,
  collectedAt: "2026-11-01T00:00:00.000Z",
  createdAt: "2026-11-01T00:00:00.000Z",
  sizeBytes: 1,
  version: 1,
  dataPointId: "0xdp",
});

/** One device's local legacy storage. */
function deviceStorage(local: Set<string>): DataStoragePort {
  return {
    listScopes: ({ limit = 100, offset = 0 }) => {
      const all = [...local].sort();
      return {
        total: all.length,
        scopes: all.slice(offset, offset + limit).map((scope) => ({
          scope,
          latestCollectedAt: "2026-11-01T00:00:00.000Z",
          versionCount: 1,
        })),
      };
    },
    listVersions: (scope: string) =>
      local.has(scope) ? [entryFor(scope)] : [],
    deleteVersion: async (scope: string) => local.delete(scope),
  } as unknown as DataStoragePort;
}

/** A gateway shared by every device of the account. */
function gateway(remote: Set<string>) {
  const tombstones: string[] = [];
  const deleteData: DeleteDataPort = {
    async tombstone(scope) {
      tombstones.push(scope);
      const live = remote.delete(scope);
      return live
        ? {
            status: "tombstoned",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          }
        : {
            status: "already-deleted",
            dataPointId: "0x1",
            version: "2",
            deletedAt: "2026-11-02T00:00:00.000Z",
          };
    },
    // A second deleter finds the keys already gone: missing is success.
    async deleteBlobVersions(_scope, versions) {
      return { deleted: [], missing: versions, failed: [] };
    },
  };
  return { deleteData, tombstones };
}

function world(scopes: string[]) {
  const local = new Set(scopes);
  const remote = new Set(scopes);
  return {
    local,
    remote,
    storage: deviceStorage(local),
    ...gateway(remote),
  };
}

function run(
  w: ReturnType<typeof world>,
  complete: (scope: string) => boolean,
  log = logger(),
) {
  return retireLegacyScopes({
    storage: w.storage,
    viewIsComplete: complete,
    deleteScope: (scope) =>
      deleteScope(
        {
          storage: w.storage,
          serverOwner: OWNER,
          deleteData: w.deleteData,
          pendingBlobDeletions: createMemoryPendingBlobDeletionStore(),
          logger: logger(), // deleteScope's own logs are not under test here
        },
        scope,
      ),
    logger: log,
  });
}

describe("retireLegacyScopes", () => {
  it("deletes the legacy files, remote and local, of complete scopes only", async () => {
    const w = world(["acme.items", "acme.orders", "beta.things"]);
    const result = await run(w, (s) => s !== "acme.orders");
    expect(result).toEqual({ considered: 3, deleted: 2, kept: 1 });
    expect([...w.local]).toEqual(["acme.orders"]);
    expect([...w.remote]).toEqual(["acme.orders"]);
  });

  it("keeps every legacy file when no view is complete", async () => {
    const w = world(["acme.items", "acme.orders"]);
    const result = await run(w, () => false);
    expect(result.deleted).toBe(0);
    expect(w.tombstones).toEqual([]);
    expect([...w.local].sort()).toEqual(["acme.items", "acme.orders"]);
  });

  it("is idempotent: a second pass finds nothing to do", async () => {
    const w = world(["acme.items"]);
    await run(w, () => true);
    const again = await run(w, () => true);
    expect(again).toEqual({ considered: 0, deleted: 0, kept: 0 });
    expect(w.tombstones).toEqual(["acme.items"]);
  });

  it("two devices deleting at the same time both succeed", async () => {
    const w = world(["acme.items", "acme.orders"]);
    const localB = new Set(w.local);
    const b = { ...w, local: localB, storage: deviceStorage(localB) };
    const [ra, rb] = await Promise.all([
      run(w, () => true),
      run(b, () => true),
    ]);
    expect(ra.deleted).toBe(2);
    expect(rb.deleted).toBe(2);
    expect(w.local.size).toBe(0);
    expect(localB.size).toBe(0);
    expect(w.remote.size).toBe(0);
  });

  it("never touches stream-sync or reserved names", async () => {
    const w = world([
      "acme.items",
      "pdpp.acme~0123456789abcdef.items",
      "pdpp.acme~0123456789abcdef",
      "vana.system.keys",
    ]);
    const asked: string[] = [];
    await run(w, (s) => (asked.push(s), true));
    expect(asked).toEqual(["acme.items"]);
    expect(w.tombstones).toEqual(["acme.items"]);
    expect(w.local.has("pdpp.acme~0123456789abcdef.items")).toBe(true);
    expect(w.local.has("pdpp.acme~0123456789abcdef")).toBe(true);
    expect(w.local.has("vana.system.keys")).toBe(true);
  });

  it("keeps the local copy when the gateway delete fails, and retries later", async () => {
    const w = world(["acme.items"]);
    let fail = true;
    const original = w.deleteData.tombstone.bind(w.deleteData);
    w.deleteData.tombstone = async (scope, fence) => {
      if (fail) throw new Error("gateway down");
      return original(scope, fence);
    };
    const first = await run(w, () => true);
    expect(first.deleted).toBe(0);
    expect(w.local.has("acme.items")).toBe(true);
    fail = false;
    expect((await run(w, () => true)).deleted).toBe(1);
    expect(w.local.size).toBe(0);
  });

  it("limits the scopes deleted per cycle", async () => {
    const names = Array.from(
      { length: RETIRE_LEGACY_SCOPES_PER_CYCLE + 3 },
      (_, i) => `acme.s${i}`,
    );
    const w = world(names);
    const result = await run(w, () => true);
    expect(result.deleted).toBe(RETIRE_LEGACY_SCOPES_PER_CYCLE);
    expect(w.local.size).toBe(3);
  });

  it("logs counts only, never scope names", async () => {
    const w = world(["secret-connector.private-stream"]);
    const log = logger();
    await run(w, () => true, log);
    const lines = JSON.stringify(log.info.mock.calls);
    expect(lines).not.toContain("secret-connector");
  });
});

// Type-level guard that the injected result is the real worker result.
export type _Result = DeleteScopeResult;
