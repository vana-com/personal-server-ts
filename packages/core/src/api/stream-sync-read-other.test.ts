import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  handlePersonalServerSyncRequest,
  handleOuraCollectionRequirementsRequest,
} from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import {
  createAccountStorageMode,
  type AccountStorageModeValue,
  type AccountStorageMode,
} from "./account-storage-mode.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { DataStoragePort } from "../ports/index.js";
import type { LegacyScopeViewPort } from "../storage/legacy-scope-view.js";

/**
 * Group D read entry points: `/sync/file`, scope delete (and its lineage
 * cascade) and the Oura requirements read. A switched account touches no
 * legacy store on any of them; an unswitched account behaves as before.
 */

const OWNER = "0x1111111111111111111111111111111111111111";

function modeOf(value: AccountStorageModeValue): AccountStorageMode {
  return { read: () => value };
}

/** Storage and view whose every method throws: any legacy touch is a failure. */
function throwingProxy<T extends object>(label: string, touched: string[]): T {
  return new Proxy({} as T, {
    get(_target, name) {
      if (typeof name === "symbol" || name === "then") return undefined;
      return () => {
        touched.push(`${label}.${String(name)}`);
        throw new Error(`legacy ${label}.${String(name)} touched`);
      };
    },
  });
}

const auth = {
  authorizeOwner: vi.fn(async () => undefined),
  authorizeBuilderList: vi.fn(async () => undefined),
};

describe("LEGACY_ON_SWITCH_OTHER: /sync/file", () => {
  it.each(["switched", "unknown"] as const)(
    "%s account does not trigger the legacy sync engine",
    async (value) => {
      const trigger = vi.fn(async () => undefined);
      const response = await handlePersonalServerSyncRequest(
        new Request("https://ps.test/file/abc", { method: "POST" }),
        {
          auth,
          syncManager: { trigger, getStatus: vi.fn() as never },
          accountStorageMode: modeOf(value),
          serverOwner: OWNER,
        },
      );
      expect(trigger).not.toHaveBeenCalled();
      expect(response.status).toBe(value === "switched" ? 409 : 503);
      const body = (await response.json()) as {
        error: { errorCode: string };
      };
      expect(body.error.errorCode).toBe(
        value === "switched"
          ? "STREAM_SYNC_LEGACY_READ_UNAVAILABLE"
          : "ACCOUNT_MODE_UNKNOWN",
      );
    },
  );

  it("UNSWITCHED_PARITY: an unswitched account still starts the sync", async () => {
    const trigger = vi.fn(async () => undefined);
    const response = await handlePersonalServerSyncRequest(
      new Request("https://ps.test/file/abc", { method: "POST" }),
      {
        auth,
        syncManager: { trigger, getStatus: vi.fn() as never },
        accountStorageMode: modeOf("unswitched"),
        serverOwner: OWNER,
      },
    );
    expect(response.status).toBe(202);
    expect(trigger).toHaveBeenCalledTimes(1);
  });

  it("UNSWITCHED_PARITY: no mode wired behaves as before", async () => {
    const trigger = vi.fn(async () => undefined);
    const response = await handlePersonalServerSyncRequest(
      new Request("https://ps.test/file/abc", { method: "POST" }),
      { auth, syncManager: { trigger, getStatus: vi.fn() as never } },
    );
    expect(response.status).toBe(202);
  });
});

describe("LEGACY_ON_SWITCH_OTHER: delete and lineage cascade", () => {
  function deleteDeps(
    mode: AccountStorageMode,
    touched: string[],
  ): PersonalServerDataApiDeps {
    return {
      storage: throwingProxy<DataStoragePort>("storage", touched),
      auth: auth as never,
      accessLogWriter: { write: vi.fn(async () => undefined) },
      accountStorageMode: mode,
      serverOwner: OWNER,
      legacyScopeView: throwingProxy<LegacyScopeViewPort>("view", touched),
      syncManager: {
        trigger: vi.fn(),
        getStatus: vi.fn(),
        deleteScope: vi.fn(async () => {
          touched.push("syncManager.deleteScope");
          throw new Error("legacy deleteScope touched");
        }),
      } as never,
    } as PersonalServerDataApiDeps;
  }

  it.each([
    ["plain", ""],
    ["lineage cascade", "?cascade=lineage"],
  ])("switched account: %s delete touches no legacy store", async (_n, q) => {
    const touched: string[] = [];
    const response = await handlePersonalServerDataRequest(
      new Request(`https://ps.test/instagram.profile${q}`, {
        method: "DELETE",
      }),
      deleteDeps(modeOf("switched"), touched),
    );
    expect(touched).toEqual([]);
    expect(response.status).toBe(409);
    expect(
      ((await response.json()) as { error: { errorCode: string } }).error
        .errorCode,
    ).toBe("STREAM_SYNC_LEGACY_READ_UNAVAILABLE");
  });

  it("unknown mode refuses with the retryable response and touches nothing", async () => {
    const touched: string[] = [];
    const response = await handlePersonalServerDataRequest(
      new Request("https://ps.test/instagram.profile", { method: "DELETE" }),
      deleteDeps(modeOf("unknown"), touched),
    );
    expect(touched).toEqual([]);
    expect(response.status).toBe(503);
  });

  it("UNSWITCHED_PARITY: an unswitched account's delete still reaches the legacy delete", async () => {
    const touched: string[] = [];
    const deps = deleteDeps(modeOf("unswitched"), touched);
    deps.legacyScopeView = undefined;
    await expect(
      handlePersonalServerDataRequest(
        new Request("https://ps.test/instagram.profile", { method: "DELETE" }),
        deps,
      ),
    ).resolves.toBeDefined();
    expect(touched).toEqual(["syncManager.deleteScope"]);
  });

  it("UNSWITCHED_PARITY: an unswitched lineage cascade is still 501", async () => {
    const response = await handlePersonalServerDataRequest(
      new Request("https://ps.test/instagram.profile?cascade=lineage", {
        method: "DELETE",
      }),
      deleteDeps(modeOf("unswitched"), []),
    );
    expect(response.status).toBe(501);
  });

  it("a mode that latches mid-life refuses the next delete", async () => {
    let on = false;
    const mode = createAccountStorageMode({ owner: OWNER, source: () => on });
    const touched: string[] = [];
    const deps = deleteDeps(mode, touched);
    deps.legacyScopeView = undefined;
    await handlePersonalServerDataRequest(
      new Request("https://ps.test/instagram.profile", { method: "DELETE" }),
      deps,
    );
    expect(touched).toEqual(["syncManager.deleteScope"]);
    touched.length = 0;
    on = true;
    const response = await handlePersonalServerDataRequest(
      new Request("https://ps.test/instagram.profile", { method: "DELETE" }),
      deps,
    );
    expect(response.status).toBe(409);
    expect(touched).toEqual([]);
  });
});

describe("LEGACY_ON_SWITCH_OTHER: Oura collection requirements", () => {
  it.each(["switched", "unknown"] as const)(
    "%s account reads no legacy storage or view",
    async (value) => {
      const touched: string[] = [];
      const response = await handleOuraCollectionRequirementsRequest(
        new Request("https://ps.test/requirements"),
        {
          storage: throwingProxy<DataStoragePort>("storage", touched),
          legacyScopeView: throwingProxy<LegacyScopeViewPort>("view", touched),
          auth,
          accountStorageMode: modeOf(value),
          serverOwner: OWNER,
        },
      );
      expect(touched).toEqual([]);
      expect(response.status).toBe(value === "switched" ? 409 : 503);
    },
  );

  it("UNSWITCHED_PARITY: an unswitched account still derives requirements", async () => {
    const response = await handleOuraCollectionRequirementsRequest(
      new Request("https://ps.test/requirements"),
      {
        storage: createMemoryDataStorage(),
        auth,
        accountStorageMode: modeOf("unswitched"),
        serverOwner: OWNER,
      },
    );
    expect(response.status).toBe(200);
  });
});
