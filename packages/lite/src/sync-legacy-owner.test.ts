/**
 * PS Lite asks the account-mode authority about its owner in lowercase, at
 * both entry points: the retire step and the import step. An owner is
 * checksum-cased where Lite recovers it; an exact-match authority would answer
 * `unknown` for that form and stall the account.
 */

import { privateKeyToAccount } from "viem/accounts";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMemoryStreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { AccountStorageMode } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

const OWNER_KEY = `0x${"13".repeat(32)}` as const;
const owner = privateKeyToAccount(OWNER_KEY);

async function startManager(accountMode: AccountStorageMode) {
  const ownerSignature = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature,
  });
  return createPsLiteSyncManager({
    config: ServerConfigSchema.parse({
      gateway: { url: "https://gateway.local" },
      sync: { enabled: true },
      streamSync: { write: true, read: true },
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: async () => `0x${"22".repeat(65)}`,
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    autoStartSync: false,
    streamSyncFiles: () => createMemoryStreamSyncFiles(),
    streamSyncDeclaredStreams: () => [],
    streamSyncRead: {},
    accountMode,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("PS Lite asks the mode authority for the lowercase owner (OWNER_NOT_LOWERCASED)", () => {
  it("reads switched for an exact-match authority, in the retire step and the import step (LITE_IMPORTER_OWNER_NOT_LOWERCASED)", async () => {
    expect(owner.address).not.toBe(owner.address.toLowerCase()); // checksum-cased
    const asked: string[] = [];
    const accountMode: AccountStorageMode = {
      read: (requestOwner) => {
        asked.push(requestOwner);
        return requestOwner === owner.address.toLowerCase()
          ? "switched"
          : "unknown";
      },
    };
    vi.stubGlobal("fetch", async () => new Response(null, { status: 404 }));
    const manager = await startManager(accountMode);
    try {
      // The retire step: a report exists only if the authority said switched.
      expect(await manager.syncManager.legacyRetireReport()).not.toBeNull();
      // The import step: a cycle runs the importer, which reads the mode.
      asked.length = 0;
      await manager.syncManager.trigger();
      expect(asked.length).toBeGreaterThan(0);
      expect(
        asked.every(
          (requestOwner) => requestOwner === requestOwner.toLowerCase(),
        ),
      ).toBe(true);
    } finally {
      await manager.closeStreamSync();
    }
  });
});
