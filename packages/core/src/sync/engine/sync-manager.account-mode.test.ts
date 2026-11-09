import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { AccountStorageModeValue } from "../../api/account-storage-mode.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn() }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll } from "../workers/download.js";
import { createSyncManager } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;
const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";

/** Every legacy storage read is counted; none is expected for a switched account. */
function build(value: AccountStorageModeValue | undefined) {
  const findUnsynced = vi.fn().mockReturnValue([]);
  const uploadDeps: UploadWorkerDeps = {
    storage: {
      findUnsynced,
      updateFileId: vi.fn(),
    } as unknown as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    signer: {} as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  };
  const downloadDeps = {
    storage: {} as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    cursor: {
      read: vi.fn().mockResolvedValue(null),
      write: vi.fn(),
    },
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  } as unknown as DownloadWorkerDeps;
  const publisher = { cycle: vi.fn(async () => ({})) };
  const canSync = vi.fn(async () => ({ ok: true as const }));
  const manager = createSyncManager(uploadDeps, downloadDeps, {
    pollInterval: 60_000,
    notifyDebounceMs: 10,
    streamSync: { write: true, publisher },
    canSync,
    ...(value === undefined
      ? {}
      : {
          accountStorageMode: { read: () => value },
          serverOwner: OWNER,
        }),
  });
  return { manager, findUnsynced, publisher, canSync };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers();
  (uploadAll as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  (downloadAll as ReturnType<typeof vi.fn>).mockResolvedValue([]);
});
afterEach(() => vi.useRealTimers());

describe("SYNC_TRIGGER_CYCLE_ON_SWITCH: the sync manager follows the account mode", () => {
  it("a switched account's trigger runs no legacy cycle but still publishes streams", async () => {
    const h = build("switched");
    await h.manager.trigger();
    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
    expect(h.findUnsynced).not.toHaveBeenCalled();
    expect(h.canSync).not.toHaveBeenCalled();
    expect(h.publisher.cycle).toHaveBeenCalledTimes(1);
  });

  it("LOOP_TICK_ON_SWITCH: start(), the loop tick and notifyNewData touch no legacy storage", async () => {
    const h = build("switched");
    h.manager.start();
    await vi.advanceTimersByTimeAsync(0);
    h.manager.notifyNewData();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
    expect(h.findUnsynced).not.toHaveBeenCalled();
    expect(h.publisher.cycle.mock.calls.length).toBeGreaterThanOrEqual(3);
    await h.manager.stop();
  });

  it("STATUS_READS_LEGACY_ON_SWITCH: status reports stream_sync and reads no legacy storage", async () => {
    const h = build("switched");
    const before = h.manager.getStatus();
    await h.manager.trigger();
    const after = h.manager.getStatus();
    expect(h.findUnsynced).not.toHaveBeenCalled();
    expect(before.blocked?.reason).toBe("stream_sync");
    expect(after.blocked?.reason).toBe("stream_sync");
    expect(after.pendingFiles).toBe(0);
  });

  it("an unknown mode runs nothing, not even the stream publisher, and says retry", async () => {
    const h = build("unknown");
    await h.manager.trigger();
    expect(uploadAll).not.toHaveBeenCalled();
    expect(downloadAll).not.toHaveBeenCalled();
    expect(h.publisher.cycle).not.toHaveBeenCalled();
    expect(h.manager.getStatus().blocked?.reason).toBe("account_mode_unknown");
    expect(h.findUnsynced).not.toHaveBeenCalled();
  });

  it("hydrateScopes is blocked for a switched account", async () => {
    const h = build("switched");
    await h.manager.hydrateScopes(["instagram.profile"]);
    expect(downloadAll).not.toHaveBeenCalled();
    expect(h.canSync).not.toHaveBeenCalled();
  });

  it.each([["unswitched" as const], [undefined]])(
    "UNSWITCHED_PARITY (%s): the legacy cycle, canSync and the publisher all run",
    async (value) => {
      const h = build(value);
      await h.manager.trigger();
      expect(h.canSync).toHaveBeenCalledTimes(1);
      expect(uploadAll).toHaveBeenCalledTimes(1);
      expect(downloadAll).toHaveBeenCalledTimes(1);
      expect(h.publisher.cycle).toHaveBeenCalledTimes(1);
      expect(h.manager.getStatus().blocked).toBeNull();
      expect(h.findUnsynced).toHaveBeenCalled();
    },
  );
});
