import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import type * as LocalModule from "./localdb/sync.js";
import type { LegacyRetirePipelinePorts } from "@opendatalabs/personal-server-ts-core/localdb";
import { declareAccountMode } from "./account-mode/unswitched-server.test-utils.js";
import { createServer, type ServerContext } from "./bootstrap.js";

let canSync: NonNullable<
  Parameters<typeof SyncModule.createSyncManager>[2]
>["canSync"];
let openLocal: () => Promise<boolean>;
let local: ReturnType<typeof LocalModule.createServerLocalSync>;
let retirementPorts: LegacyRetirePipelinePorts;
vi.mock("@opendatalabs/personal-server-ts-core/sync", async (original) => {
  const actual = await original<typeof SyncModule>();
  return {
    ...actual,
    createSyncManager: (
      ...args: Parameters<typeof actual.createSyncManager>
    ) => {
      canSync = args[2]?.canSync;
      openLocal = args[2]!.localSync!.hasPendingPublication;
      return actual.createSyncManager(...args);
    },
  };
});
vi.mock("./localdb/sync.js", async (original) => {
  const actual = await original<typeof LocalModule>();
  return {
    ...actual,
    createServerLocalSync: (
      ...args: Parameters<typeof actual.createServerLocalSync>
    ) =>
      (local = actual.createServerLocalSync(args[0], {
        ...args[1],
        legacyRetire: () => retirementPorts,
        deleteRetryMs: { first: 5, max: 20 },
      })),
  };
});
let context: ServerContext | undefined;
let root: string;
afterEach(async () => {
  await context?.cleanup();
  if (root) await rm(root, { recursive: true, force: true });
});
it.each([false, true])(
  "an overlapping stale positive lookup after revocation does not let the next retirement effect run (stale=%s)",
  async (stale) => {
    root = await mkdtemp(join(tmpdir(), "retirement-registration-"));
    const getServer = vi.fn().mockResolvedValue(null);
    const capture = vi.fn(async (save, check) => {
      check();
      return save([]);
    });
    const eraseBlob = vi.fn(async () => {
      let release!: (value: { id: string }) => void;
      let background: Promise<void> | undefined;
      if (stale) {
        getServer.mockImplementationOnce(
          () =>
            new Promise((resolve) => {
              release = resolve;
            }),
        );
        background = context!.startBackgroundServices();
        await vi.waitFor(() => expect(release).toBeTypeOf("function"));
      }
      getServer.mockResolvedValue(null);
      await canSync!();
      if (stale) {
        release({ id: "stale-positive" });
        await background;
      }
      return true;
    });
    retirementPorts = {
      mode: () => "switched",
      scopesOf: () => ["github.events"],
      streamsOf: () => [],
      head: async () => ({ state: "deleted", version: "3" }),
      tombstone: vi.fn(),
      eraseBlob,
      finality: {
        tombstoneState: async () => ({
          finalized: "3",
          settling: false,
          rolledBack: null,
        }),
      },
      versions: {
        list: async () => ({
          complete: true,
          versions: [
            { expectedVersion: "1", isTombstone: false, dataHash: "hash" },
            { expectedVersion: "2", isTombstone: false, dataHash: "hash" },
            { expectedVersion: "3", isTombstone: true, dataHash: "hash" },
          ],
        }),
      },
      rows: { capture, erase: vi.fn(), absent: async () => true },
    };
    context = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        sync: { enabled: true },
        logging: { level: "fatal", pretty: false },
      }),
      {
        serverDir: root,
        dataDir: join(root, "data"),
        ownerSignature: await privateKeyToAccount(
          `0x${"11".repeat(32)}`,
        ).signMessage({ message: "Disposable registration fixture" }),
        gatewayClient: { getServer } as never,
      },
    );
    await declareAccountMode(context, "on");
    await openLocal!();
    const sync = local!;
    expect(await canSync!()).toMatchObject({ ok: false });
    await expect(sync.legacyRetirer.request("github")).rejects.toThrow(
      "write authority",
    );
    expect(capture).not.toHaveBeenCalled();
    expect(eraseBlob).not.toHaveBeenCalled();
    getServer.mockResolvedValue({ id: "registered" });
    expect(await canSync!()).toEqual({ ok: true });
    await sync.legacyRetirer.request("github");
    await vi.waitFor(() => expect(eraseBlob).toHaveBeenCalledTimes(1));
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(eraseBlob).toHaveBeenCalledTimes(1);
    expect(retirementPorts.rows.erase).not.toHaveBeenCalled();
  },
);
