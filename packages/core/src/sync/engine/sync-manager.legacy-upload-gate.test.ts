import { describe, it, expect, vi, beforeEach } from "vitest";

import type { UploadWorkerDeps } from "../workers/upload.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { DataStoragePort } from "../../ports/index.js";
import type { IndexEntry } from "../../storage/index/types.js";
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

/** The predicate the manager handed to the upload and requeue workers. */
function predicates() {
  const upload = vi.mocked(uploadAll).mock.calls.at(-1)?.[1]?.skipEntry;
  const requeue = vi
    .mocked(requeueLostDataPoints)
    .mock.calls.at(-1)?.[2]?.skipScope;
  return { upload, requeue };
}
const entry = (scope: string) => ({ scope }) as IndexEntry;

const CARRIED = "instagram.profile"; // a legacy binding the stream carries
const MEMORY = "memory.notes.0"; // agent memory: legacy path only
const REPLICA = "pdpp_replica_v1.items"; // replica transport: legacy path only

describe("sync manager: legacy is read-only history after the switch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("writer on: stream-carried scopes are not uploaded or requeued; memory and replica scopes still are; the stream publishes; downloads continue", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect(upload?.(entry(CARRIED))).toBe(true);
    expect(upload?.(entry("pdpp.acme.items"))).toBe(true);
    expect(upload?.(entry(MEMORY))).toBe(false);
    expect(upload?.(entry(REPLICA))).toBe(false);
    expect(requeue?.(CARRIED)).toBe(true);
    expect(requeue?.(MEMORY)).toBe(false);
    expect(requeue?.(REPLICA)).toBe(false);
    expect(h.publish).toHaveBeenCalledTimes(1);
    expect(downloadAll).toHaveBeenCalledTimes(1);
  });

  it("writer off: nothing is skipped, legacy upload and registration run unchanged, nothing publishes", async () => {
    const r = rig();
    const h = hostSwitch({ on: false });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    const { upload, requeue } = predicates();
    for (const scope of [CARRIED, MEMORY, REPLICA]) {
      expect(upload?.(entry(scope))).toBe(false);
      expect(requeue?.(scope)).toBe(false);
    }
    expect(h.publish).not.toHaveBeenCalled();
  });

  it("no stream-sync option at all: legacy upload unchanged", async () => {
    const r = rig();
    const manager = createSyncManager(r.upload, r.download, {});
    await manager.trigger();
    const { upload, requeue } = predicates();
    expect(upload?.(entry(CARRIED)) ?? false).toBe(false);
    expect(requeue?.(CARRIED) ?? false).toBe(false);
  });

  it("switched off mid-run: the next cycle uploads stream-carried scopes again", async () => {
    const r = rig();
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(predicates().upload?.(entry(CARRIED))).toBe(true);
    state.on = false;
    await manager.trigger();
    expect(predicates().upload?.(entry(CARRIED))).toBe(false);
    expect(h.publish).toHaveBeenCalledTimes(1);
  });

  it("the switch is read when the predicate runs, not when the cycle starts", async () => {
    const r = rig();
    const state = { on: true };
    const h = hostSwitch(state);
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    const { upload } = predicates();
    expect(upload?.(entry(CARRIED))).toBe(true);
    state.on = false;
    expect(upload?.(entry(CARRIED))).toBe(false);
  });

  it("a failing publish is reported", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    h.publish.mockRejectedValueOnce(new Error("boom"));
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: h.streamSync,
    });
    await manager.trigger();
    expect(manager.getStatus().errors.map((e) => e.message)).toContain(
      "Stream sync publish failed: boom",
    );
  });

  it("a host may name what its stream carries", async () => {
    const r = rig();
    const h = hostSwitch({ on: true });
    const manager = createSyncManager(r.upload, r.download, {
      streamSync: {
        ...h.streamSync,
        carries: (scope) => scope === "only.this",
      },
    });
    await manager.trigger();
    const { upload } = predicates();
    expect(upload?.(entry("only.this"))).toBe(true);
    expect(upload?.(entry(CARRIED))).toBe(false);
  });
});
