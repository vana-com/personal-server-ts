import { expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

it.each(["switched", "unswitched"] as const)(
  "reports the store that served a %s listing",
  async (mode) => {
    const listScopes = vi.fn(async () => []);
    const read = vi.fn(() => mode);
    const deps = {
      accountStorageMode: { owner: "fixture", read },
      storage: createMemoryDataStorage(),
      streamSyncRead: { listScopes },
      auth: { authorizeBuilderList: vi.fn() },
      accessLogWriter: { write: vi.fn() },
    } as unknown as PersonalServerDataApiDeps;
    const response = await handlePersonalServerDataRequest(
      new Request("https://server.example/?limit=100"),
      deps,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      listingStore: mode === "switched" ? "stream-sync" : "legacy",
      scopes: [],
      total: 0,
    });
    expect(read).toHaveBeenCalledTimes(1);
    expect(listScopes).toHaveBeenCalledTimes(mode === "switched" ? 1 : 0);
  },
);
