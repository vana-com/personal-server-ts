/**
 * Shutdown stops every component, however an earlier stop ended. A rejecting
 * stop used to jump past the sync manager's, leaving its push request and
 * timers live while the index closed under them. Real Node composition; only
 * the stops under test are made to fail.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryModeRecordStore,
  type ImportWaker,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type * as AccountModeModule from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import type * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import { createStreamSyncKeyPorts } from "../../core/src/stream-sync/crypto.js";
import { remoteFixture } from "./localdb/apply-fixture.js";
import { createServer, type ServerContext } from "./bootstrap.js";

const failures = vi.hoisted(() => ({
  wakerStop: null as Error | null,
  managerStop: null as Error | null,
  managerStops: 0,
}));

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync/account-mode",
  async (importOriginal) => {
    const actual = await importOriginal<typeof AccountModeModule>();
    return {
      ...actual,
      createImportWaker: (
        ...args: Parameters<typeof actual.createImportWaker>
      ): ImportWaker => {
        const waker = actual.createImportWaker(...args);
        return {
          ...waker,
          stop: async () => {
            await waker.stop();
            if (failures.wakerStop) throw failures.wakerStop;
          },
        };
      },
    };
  },
);

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncModule>();
    return {
      ...actual,
      createSyncManager: (
        ...args: Parameters<typeof actual.createSyncManager>
      ) => {
        const manager = actual.createSyncManager(args[0], args[1], {
          ...args[2],
          canSync: () => ({ ok: true }),
        });
        const stop = manager.stop.bind(manager);
        manager.stop = async () => {
          failures.managerStops += 1;
          await stop();
          if (failures.managerStop) throw failures.managerStop;
        };
        return manager;
      },
    };
  },
);

const directories: string[] = [];
afterEach(async () => {
  failures.wakerStop = null;
  failures.managerStop = null;
  failures.managerStops = 0;
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

async function world(): Promise<ServerContext> {
  const root = await mkdtemp(join(tmpdir(), "shutdown-"));
  directories.push(root);
  const signature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable shutdown fixture" });
  const remote = await remoteFixture(createStreamSyncKeyPorts(signature));
  vi.stubEnv("PS_ACCESS_TOKEN", "shutdown-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      sync: { enabled: true },
      logging: { level: "fatal", pretty: false },
      streamSync: { write: true },
    }),
    {
      rootPath: root,
      ownerSignature: signature,
      accountModeStore: createMemoryModeRecordStore(),
      streamSyncRegistry: remote.registry,
      streamSyncBlobs: remote.storage,
    },
  );
}

describe("cleanup", () => {
  it("stops the sync manager when an earlier stop rejects, then reports that error", async () => {
    const context = await world();
    expect(context.syncManager?.running).toBe(true);
    failures.wakerStop = new Error("importer would not stop");

    await expect(context.cleanup()).rejects.toThrow("importer would not stop");
    expect(failures.managerStops).toBe(1);
    expect(context.syncManager?.running).toBe(false);
  });

  it("runs every stop and rethrows the first error when several fail", async () => {
    const context = await world();
    failures.wakerStop = new Error("first: importer");
    failures.managerStop = new Error("second: sync manager");

    await expect(context.cleanup()).rejects.toThrow("first: importer");
    expect(failures.managerStops).toBe(1);
    expect(context.syncManager?.running).toBe(false);
  });

  it("a clean shutdown still resolves", async () => {
    const context = await world();
    await expect(context.cleanup()).resolves.toBeUndefined();
    expect(failures.managerStops).toBe(1);
  });
});
