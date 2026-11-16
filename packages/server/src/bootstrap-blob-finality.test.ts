/**
 * A server that can delete data always has the finality port that gates its
 * blob deletes. `deleteData` exists only outside an enclave, where the
 * server-key request signer (the default inventory signer) exists too, so
 * the manager is never handed one without the other.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type * as SyncModule from "@opendatalabs/personal-server-ts-core/sync";
import { createServer, type ServerContext } from "./bootstrap.js";

const managerOptions: Array<Record<string, unknown> | undefined> = [];

vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof SyncModule>();
    return {
      ...actual,
      createSyncManager: (
        ...args: Parameters<typeof actual.createSyncManager>
      ) => {
        managerOptions.push(args[2] as Record<string, unknown> | undefined);
        return actual.createSyncManager(...args);
      },
    };
  },
);

const contexts: ServerContext[] = [];
const directories: string[] = [];
afterEach(async () => {
  for (const context of contexts.splice(0)) await context.cleanup();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
  managerOptions.length = 0;
});

it("hands the sync manager a finality port with every delete port, with no signer injected", async () => {
  const root = await mkdtemp(join(tmpdir(), "blob-finality-"));
  directories.push(root);
  const signature = await privateKeyToAccount(
    `0x${"11".repeat(32)}`,
  ).signMessage({ message: "Disposable blob finality fixture" });
  contexts.push(
    await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        sync: { enabled: true },
        logging: { level: "fatal", pretty: false },
      }),
      {
        serverDir: root,
        dataDir: join(root, "data"),
        ownerSignature: signature,
      },
    ),
  );
  expect(managerOptions).toHaveLength(1);
  const options = managerOptions[0]!;
  expect(options.deleteData).toBeTruthy();
  expect(options.tombstoneFinality).toBeTruthy();
});
