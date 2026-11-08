import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { Logger } from "../../logger/index.js";

vi.mock("../workers/upload.js", () => ({ uploadAll: vi.fn(async () => []) }));
vi.mock("../workers/download.js", () => ({
  downloadAll: vi.fn(async () => []),
  downloadScopes: vi.fn(),
}));
vi.mock("../workers/lost-data-points.js", () => ({
  requeueLostDataPoints: vi.fn(async () => ({ requeued: [], failed: [] })),
}));

import { uploadAll } from "../workers/upload.js";
import { downloadAll } from "../workers/download.js";
import { requeueLostDataPoints } from "../workers/lost-data-points.js";
import { createSyncManager } from "./sync-manager.js";

const logger = () =>
  ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  }) as unknown as Logger;

function rig() {
  const storage = {
    findUnsynced: () => [],
    listScopes: () => ({ total: 0, scopes: [] }),
  } as unknown as DataStoragePort;
  const upload = {
    storage,
    serverOwner: "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12",
    logger: logger(),
  } as unknown as UploadWorkerDeps;
  const download = {
    storage,
    cursor: { read: async () => null, write: async () => {} },
    logger: logger(),
  } as unknown as DownloadWorkerDeps;
  return { upload, download };
}

/** A host-shaped switch: `write` reads live state on every access. */
function hostSwitch(state: { on: boolean }) {
  const publish = vi.fn(async () => {});
  return {
    publish,
    streamSync: {
      get write() {
        return state.on;
      },
      publisher: { cycle: publish },
    },
  };
}

describe("sync manager: legacy is read-only history after the switch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("writer on: no legacy upload, no gateway re-registration, the stream publish still runs, downloads continue", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(uploadAll).not.toHaveBeenCalled();
    expect(requeueLostDataPoints).not.toHaveBeenCalled();
    expect(h.publish).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);
  });

  it("writer off: legacy upload and registration run unchanged, nothing publishes", async () => {
    const r = rig();
    const h = hostSwitch({ on: false });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(requeueLostDataPoints).toHaveBeenCalledTimes(1);
    expect(h.publish).not.toHaveBeenCalled();
  });

  it("no stream-sync option at all: legacy upload unchanged", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {});
    await manager.trigger();
    expect(uploadAll).toHaveBeenCalledTimes(1);
  });

  it("switched off mid-run: the next cycle uploads legacy files again", async () => {
    const r = rig();
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(uploadAll).not.toHaveBeenCalled();
    state.on = false;
    await manager.trigger();
    expect(uploadAll).toHaveBeenCalledTimes(1);
    expect(requeueLostDataPoints).toHaveBeenCalledTimes(1);
    expect(h.publish).toHaveBeenCalledTimes(1);
  });

  it("a failing publish is reported and does not start a legacy upload", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    h.publish.mockRejectedValueOnce(new Error("boom"));
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(uploadAll).not.toHaveBeenCalled();
    expect(manager.getStatus().errors.map((e) => e.message)).toContain(
      "Stream sync publish failed: boom",
    );
  });
});
