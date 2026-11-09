/**
 * The browser runtime builds one account storage mode and hands it, with the
 * server owner, to the Lite sync manager. A dropped hand-off would leave the
 * manager running the legacy cycle for a switched account.
 */
import "fake-indexeddb/auto";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { signOwnerMasterKey } from "@opendatalabs/personal-server-ts-core/keys";

const captured = vi.hoisted(() => ({
  calls: [] as Array<Record<string, unknown>>,
}));
vi.mock("./sync.js", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    createPsLiteSyncManager: (options: Record<string, unknown>) => {
      captured.calls.push(options);
      return (original.createPsLiteSyncManager as (o: unknown) => unknown)(
        options,
      );
    },
  };
});

import { createIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import { createBearerTokenPsLiteAuth } from "./runtime.js";
import { createIndexedDbStreamSyncFiles } from "./stream-sync-files.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

let ownerAddress: `0x${string}`;
let ownerSignature: `0x${string}`;
beforeAll(async () => {
  const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
  ownerAddress = account.address;
  ownerSignature = await signOwnerMasterKey(account);
});

async function open(streamSync: Record<string, unknown>) {
  vi.stubGlobal("indexedDB", new IDBFactory());
  captured.calls.length = 0;
  await createIndexedDbPsLiteRuntime({
    ownerAddress,
    ownerSignature,
    dbName: `ps-lite-mode-${Math.random()}`,
    storageDbName: `ps-lite-mode-storage-${Math.random()}`,
    gateway: createMockPsLiteGateway(),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
    streamSyncDeclarations: () => null,
    streamSyncFiles: () =>
      createIndexedDbStreamSyncFiles({
        dbName: `mode-files-${Math.random()}`,
        factory: new IDBFactory(),
        keyRange: IDBKeyRange,
      }),
    configDefaults: {
      gateway: { url: "https://gateway.local" },
      sync: { enabled: true },
      streamSync,
    },
  } as never);
  expect(captured.calls).toHaveLength(1);
  return captured.calls[0] as {
    accountStorageMode?: { read(owner?: string): string };
    serverOwner?: string;
  };
}

describe("LITE_BROWSER_MODE_DROPPED: the browser runtime wires the account mode into sync", () => {
  it("passes a mode bound to the server owner that reads switched when the switch is on", async () => {
    const options = await open({ write: true, refuseLegacyWrites: true });
    expect(options.accountStorageMode).toBeDefined();
    expect(options.serverOwner).toBeTruthy();
    expect(options.accountStorageMode?.read(options.serverOwner)).toBe(
      "switched",
    );
  });

  it("reads unswitched when the switch is off", async () => {
    const options = await open({ write: true });
    expect(options.accountStorageMode?.read(options.serverOwner)).toBe(
      "unswitched",
    );
  });
});
