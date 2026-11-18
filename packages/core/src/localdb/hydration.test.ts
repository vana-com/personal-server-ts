import { expect, it, vi } from "vitest";
import { createLocalSync } from "./sync.js";
import { connectionQueue } from "./queue.js";
import type { LocalSyncDeps } from "./deps.js";

// An empty database is sufficient here: the meaningful effect is the remote
// listing, which must complete even when there are no connections to import.
function fixture() {
  const listOwnerRows = vi.fn().mockResolvedValue([]);
  const sync = createLocalSync(
    {
      db: {
        query: async () => [],
        batch: async () => {},
        close: async () => {},
      },
      queue: connectionQueue(),
      registry: { listOwnerRows },
      keys: { namespaceHmac: async () => new Uint8Array(32) },
      logger: { info: vi.fn(), warn: vi.fn() },
    } as unknown as LocalSyncDeps,
    { resolveArtifact: () => null },
  );
  return { sync, listOwnerRows };
}

it("does not hydrate an empty database before a full Account download", async () => {
  const { sync, listOwnerRows } = fixture();
  try {
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    await sync.publish();
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    await sync.cycle({ connections: [] });
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    listOwnerRows.mockRejectedValueOnce(new Error("download failed"));
    await expect(sync.cycle()).rejects.toThrow("download failed");
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    await sync.cycle();
    expect((await sync.listing.status()).accountHydrated).toBe(true);
    listOwnerRows.mockRejectedValueOnce(new Error("later sync failed"));
    await expect(sync.cycle()).rejects.toThrow("later sync failed");
    expect((await sync.listing.status()).accountHydrated).toBe(true);
  } finally {
    await sync.close();
  }
});

it("hydrates after a complete download-only apply", async () => {
  const { sync } = fixture();
  try {
    await sync.apply();
    expect((await sync.listing.status()).accountHydrated).toBe(true);
  } finally {
    await sync.close();
  }
});
