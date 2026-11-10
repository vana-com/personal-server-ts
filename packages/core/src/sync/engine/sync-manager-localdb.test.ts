import { describe, expect, it, vi } from "vitest";
import { createSyncManager } from "./sync-manager.js";
import { downloadAll, downloadScopes } from "../workers/download.js";

describe("database sync hooks", () => {
  it("rechecks Account after canSync, then uses one database cycle without any legacy reads or hydration", async () => {
    let mode: "unswitched" | "switched" | "unknown" = "unswitched";
    const legacy = vi.fn(() => {
      throw new Error("Legacy storage accessed");
    });
    const logger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    };
    const upload = {
      storage: new Proxy({}, { get: () => legacy }),
      logger,
      serverOwner: "0x1234",
    };
    const download = { logger };
    const cycle = vi.fn(async () => {});
    const manager = createSyncManager(upload as never, download as never, {
      accountStorageMode: { read: () => mode },
      localSync: { cycle },
      canSync: async () => {
        mode = "switched";
        return { ok: true };
      },
      hydrateScopes: ["fixture.items"],
    });
    await manager.trigger();
    expect(cycle).toHaveBeenCalledTimes(1);
    await manager.hydrateScopes(["fixture.items"]);
    expect(cycle).toHaveBeenCalledTimes(2);
    expect(manager.getStatus().pendingFiles).toBe(0);
    expect(legacy).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("pauses an unknown Account before touching legacy storage", async () => {
    const legacy = vi.fn(() => {
      throw new Error("Legacy storage accessed");
    });
    const logger = {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    };
    const manager = createSyncManager(
      {
        storage: new Proxy({}, { get: () => legacy }),
        logger,
        serverOwner: "0x1234",
      } as never,
      { logger } as never,
      { accountStorageMode: { read: () => "unknown" } },
    );
    await manager.trigger();
    expect(manager.getStatus().blocked?.reason).toBe("account_mode_unknown");
    expect(legacy).not.toHaveBeenCalled();
    await manager.stop();
  });

  it("the download hooks apply database heads before any legacy sidecar, feed or cursor operation", async () => {
    const apply = vi.fn(async () => {});
    const deps = { localSync: { apply } } as never;
    expect(await downloadAll(deps)).toEqual([]);
    expect(await downloadScopes(deps, ["fixture.items"])).toEqual([]);
    expect(apply).toHaveBeenCalledTimes(2);
  });
});
