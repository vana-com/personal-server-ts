import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { Logger } from "../../logger/index.js";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(async () => []),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));
vi.mock("@opendatalabs/vana-sdk/browser", () => ({
  deriveScopeKey: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

import { createSyncManager } from "./sync-manager.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const POLL = 60_000;

function manager(canSync: () => Promise<{ ok: true }>) {
  const logger = {
    info: vi.fn(),
    error: vi.fn(),
    warn: vi.fn(),
    debug: vi.fn(),
  } as unknown as Logger;
  const uploadDeps: UploadWorkerDeps = {
    storage: {
      findUnsynced: vi.fn(() => []),
    } as unknown as DataStoragePort,
    storageAdapter: {} as StorageAdapter,
    gateway: {} as GatewayClient,
    signer: {} as ServerSigner,
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  };
  const downloadDeps = {
    storage: {},
    storageAdapter: {},
    gateway: {},
    cursor: { read: vi.fn(), write: vi.fn() },
    masterKey: new Uint8Array(65).fill(0xaa),
    serverOwner: OWNER,
    logger,
  } as unknown as DownloadWorkerDeps;
  return createSyncManager(uploadDeps, downloadDeps, {
    pollInterval: POLL,
    canSync,
  } as never);
}

describe("a manual trigger whose cycle rejects", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("keeps polling: the next poll interval starts a new cycle", async () => {
    let calls = 0;
    let failNext = false;
    const m = manager(async () => {
      calls += 1;
      if (failNext) {
        failNext = false;
        throw new Error("cycle broke");
      }
      return { ok: true };
    });
    m.start();
    await vi.advanceTimersByTimeAsync(0);
    failNext = true;
    await expect(m.trigger()).rejects.toThrow("cycle broke");
    const before = calls;
    await vi.advanceTimersByTimeAsync(POLL);
    expect(calls).toBeGreaterThan(before);
    await m.stop();
  });
});
