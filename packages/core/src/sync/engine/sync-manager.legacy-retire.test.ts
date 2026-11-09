/**
 * The sync cycle around import and retire. Workers are mocked; the legacy
 * store, the stream read service and the retire host are real (the synthetic
 * fixture). Every remote port is a recorder that fails the test when touched.
 */

import { OWNER } from "../legacy-retire/retire-rig.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { Logger } from "../../logger/index.js";
import type { DeleteDataPort } from "../delete-data-port.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import { createRetireHost } from "../legacy-retire/host.js";
import { LegacyImporter } from "../legacy-retire/import.js";
import { RetireLedger } from "../legacy-retire/ledger.js";
import { buildSyntheticFixture } from "../legacy-retire/synthetic-fixture.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn(async () => []) }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(async () => []),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { createSyncManager } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

/** An object that records every property read or call made on it. */
function recorder(calls: string[], name: string): unknown {
  return new Proxy(function () {}, {
    get: (_t, prop) => {
      calls.push(`${name}.${String(prop)}`);
      return recorder(calls, `${name}.${String(prop)}`);
    },
    apply: () => {
      calls.push(`${name}()`);
      return Promise.resolve({
        status: "already-deleted",
        version: null,
        deletedAt: null,
      });
    },
  });
}

async function cycle(options: {
  deleteEnabled: boolean;
  option: "switched" | "unswitched";
}) {
  const fx = await buildSyntheticFixture();
  const ledger = new RetireLedger(createMemoryStreamSyncFiles(), OWNER);
  const staged: string[] = [];
  const importer = new LegacyImporter({
    source: fx.source,
    sink: {
      // A sink stages the rows it consumes; the receipt counts them.
      stage: async (c, s, rows) => {
        let count = 0;
        for await (const _row of rows) count += Number(_row !== undefined);
        staged.push(`${c}/${s.stream}`);
        return count;
      },
    },
    ledger,
    switched: () => options.option === "switched",
  });
  const host = createRetireHost({
    reader: fx.reader,
    writer: { fullRunSince: async () => true },
    ledger,
  });
  const remote: string[] = [];
  const uploadDeps = {
    storage: fx.storage,
    storageAdapter: recorder(remote, "storageAdapter"),
    gateway: recorder(remote, "gateway") as GatewayClient,
    signer: recorder(remote, "signer"),
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger,
  } as unknown as UploadWorkerDeps;
  const downloadDeps = {
    storage: fx.storage,
    storageAdapter: recorder(remote, "storageAdapter"),
    gateway: recorder(remote, "gateway") as GatewayClient,
    cursor: { read: async () => null, write: async () => undefined },
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger,
  } as unknown as DownloadWorkerDeps;
  const manager = createSyncManager(uploadDeps, downloadDeps, {
    pollInterval: 60_000,
    deleteData: recorder(remote, "deleteData") as DeleteDataPort,
    legacyRetire: () =>
      options.option === "switched"
        ? { importer, host, ledger, deleteEnabled: options.deleteEnabled }
        : null,
  });
  manager.start();
  await vi.advanceTimersByTimeAsync(0);
  const status = manager.getStatus();
  await manager.stop();
  return { fx, remote, staged, status, ledger };
}

describe("sync cycle with legacy import and retire", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("retires local files without any gateway or blob write (LEGACY_NAME_TOMBSTONE)", async () => {
    const { fx, remote, status } = await cycle({
      deleteEnabled: true,
      option: "switched",
    });
    // Files really were deleted by this cycle...
    expect(status.legacyRetire).toMatchObject({ mode: "delete", deleted: 3 });
    expect(fx.storage.entries).toHaveLength(2);
    // ...and nothing reached the gateway, the blob store or the delete port.
    expect(remote).toEqual([]);
  });

  it("imports in the cycle and deletes nothing while the delete flag is off (RETIRE_FLAG_IGNORED)", async () => {
    const { fx, staged, status } = await cycle({
      deleteEnabled: false,
      option: "switched",
    });
    expect(staged).toHaveLength(6);
    expect(status.legacyRetire).toMatchObject({
      mode: "readback-only",
      deleted: 0,
      ready: 3,
    });
    expect(fx.storage.entries).toHaveLength(5);
  });

  it("does nothing for an unswitched account (UNSWITCHED_CHANGED)", async () => {
    const { fx, remote, staged, status, ledger } = await cycle({
      deleteEnabled: true,
      option: "unswitched",
    });
    expect(staged).toEqual([]);
    expect(status.legacyRetire).toBeUndefined();
    expect(fx.storage.entries).toHaveLength(5);
    expect(remote).toEqual([]);
    expect(await ledger.read()).toEqual({
      owner: OWNER,
      abandoned: false,
      excluded: {},
      failures: {},
      importComplete: false,
      imported: {},
      listAttempts: 0,
      readbacks: {},
    });
  });
});
