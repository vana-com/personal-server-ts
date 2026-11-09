import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer as createHttpServer } from "node:http";
import { privateKeyToAccount } from "viem/accounts";
import { describe, it, expect } from "vitest";
import { createServer } from "./bootstrap.js";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";

/** NODE_SYNC_MANAGER_MODE_DROPPED: the sync manager Node builds follows its account mode. */
async function boot(switched: boolean) {
  const calls: string[] = [];
  const gateway = createHttpServer((request, response) => {
    calls.push(new URL(request.url ?? "/", "http://x").pathname);
    response.setHeader("Content-Type", "application/json");
    response.end(
      JSON.stringify({
        data: { dataPoints: [] },
        pagination: { limit: 100, hasMore: false, nextCursor: null },
      }),
    );
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", resolve));
  const address = gateway.address();
  if (!address || typeof address === "string") throw new Error("no port");
  const tempDir = await mkdtemp(join(tmpdir(), "bootstrap-mode-"));
  const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
  const ownerSignature = await owner.signMessage({
    message: "Disposably authorize Node",
  });
  const config = ServerConfigSchema.parse({
    gateway: { url: `http://127.0.0.1:${address.port}` },
    storage: {
      backend: "vana",
      config: { vana: { apiUrl: `http://127.0.0.1:${address.port}` } },
    },
    tunnel: { enabled: false },
    sync: { enabled: true },
    streamSync: { write: switched, refuseLegacyWrites: switched },
    logging: { level: "fatal", pretty: false },
  });
  const ctx = await createServer(config, { rootPath: tempDir, ownerSignature });
  return {
    ctx,
    calls,
    async close() {
      await ctx.cleanup();
      gateway.closeAllConnections();
      await new Promise<void>((resolve) => gateway.close(() => resolve()));
      await rm(tempDir, { recursive: true, force: true });
    },
  };
}

describe("Node bootstrap sync manager and the account mode", () => {
  it("a switched account's sync manager is blocked as stream_sync", async () => {
    const h = await boot(true);
    try {
      expect(h.ctx.syncManager).not.toBeNull();
      await h.ctx.syncManager!.trigger();
      expect(h.ctx.syncManager!.getStatus().blocked?.reason).toBe(
        "stream_sync",
      );
    } finally {
      await h.close();
    }
  }, 30_000);

  it("UNSWITCHED_PARITY: an unswitched account's sync manager is not blocked as stream_sync", async () => {
    const h = await boot(false);
    try {
      expect(h.ctx.syncManager).not.toBeNull();
      await h.ctx.syncManager!.trigger();
      expect(h.ctx.syncManager!.getStatus().blocked?.reason).not.toBe(
        "stream_sync",
      );
    } finally {
      await h.close();
    }
  }, 30_000);
});
