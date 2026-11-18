import { expect, it, vi } from "vitest";
import { createGatewayStreamSyncRegistry } from "../stream-sync/registry.js";
import { connectionQueue } from "./queue.js";
import { createLocalSync } from "./sync.js";
import type { LocalSyncDeps } from "./deps.js";

it("does not mark hydration complete while a later registry page is held or fails", async () => {
  let release!: () => void;
  let arrive!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  let fail = true;
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: `0x${"11".repeat(20)}`,
    listPageSize: 1,
    fetch: (async (input: string) => {
      const later = new URL(input).searchParams.has("cursor");
      if (later && fail) {
        arrive();
        await held;
      }
      return new Response(
        JSON.stringify({
          data: { dataPoints: [] },
          pagination: later
            ? fail
              ? {}
              : { hasMore: false }
            : { hasMore: true, nextCursor: "next" },
        }),
      );
    }) as typeof fetch,
  });
  const sync = createLocalSync(
    {
      db: {
        query: async () => [],
        batch: async () => {},
        close: async () => {},
      },
      queue: connectionQueue(),
      registry,
      keys: { namespaceHmac: async () => new Uint8Array(32) },
      logger: { info: vi.fn(), warn: vi.fn() },
    } as unknown as LocalSyncDeps,
    { resolveArtifact: () => null },
  );
  try {
    const applying = sync.apply();
    await arrived;
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    release();
    await expect(applying).rejects.toThrow("gives no cursor");
    expect((await sync.listing.status()).accountHydrated).toBe(false);
    fail = false;
    await sync.apply();
    expect((await sync.listing.status()).accountHydrated).toBe(true);
  } finally {
    release();
    await sync.close();
  }
});
