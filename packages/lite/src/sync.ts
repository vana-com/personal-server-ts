import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  createSyncManager,
  type SyncManager,
} from "@opendatalabs/personal-server-ts-core/sync/manager";
import { createVanaSyncStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { ServerAccount } from "@opendatalabs/personal-server-ts-core/keys";
import {
  createGatewayClient,
  deriveMasterKey,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import type { PsLiteStateStore } from "./state.js";
import { resolvePsLiteOwner } from "./owner-binding.js";

const SYNC_CURSOR_KEY = "sync-cursor-v1";

interface PsLiteSyncCursorState {
  lastProcessedTimestamp: string | null;
}

interface SyncCursor {
  read(): Promise<string | null>;
  write(timestamp: string): Promise<void>;
}

export interface PsLiteSyncOptions {
  config: ServerConfig;
  stateStore: PsLiteStateStore;
  storage: DataStoragePort;
  ownerAddress?: `0x${string}`;
  ownerSignature: `0x${string}`;
  serverAccount: ServerAccount;
  gateway?: GatewayClient;
}

function createBrowserLogger() {
  return {
    info: console.info.bind(console),
    error: console.error.bind(console),
    warn: console.warn.bind(console),
    debug: console.debug.bind(console),
  };
}

export function createPsLiteSyncCursor(
  stateStore: PsLiteStateStore,
): SyncCursor {
  return {
    async read() {
      const state =
        await stateStore.get<PsLiteSyncCursorState>(SYNC_CURSOR_KEY);
      return state?.lastProcessedTimestamp ?? null;
    },
    async write(timestamp) {
      await stateStore.set<PsLiteSyncCursorState>(SYNC_CURSOR_KEY, {
        lastProcessedTimestamp: timestamp,
      });
    },
  };
}

export async function createPsLiteSyncManager(
  options: PsLiteSyncOptions,
): Promise<{ syncManager: SyncManager; serverOwner: `0x${string}` }> {
  const serverOwner = await resolvePsLiteOwner({
    ownerAddress: options.ownerAddress,
    ownerSignature: options.ownerSignature,
  });
  const masterKey = deriveMasterKey(options.ownerSignature);
  const gateway =
    options.gateway ?? createGatewayClient(options.config.gateway.url);
  const storageAdapter = createVanaSyncStorageAdapter({
    config: options.config,
    serverOwner,
    serverAccount: options.serverAccount,
  });
  const signer = createServerSigner(options.serverAccount, {
    chainId: options.config.gateway.chainId,
    contracts: options.config.gateway.contracts,
  });
  const cursor = createPsLiteSyncCursor(options.stateStore);
  const logger = createBrowserLogger();
  const syncManager = createSyncManager(
    {
      storage: options.storage,
      storageAdapter,
      gateway,
      signer,
      masterKey,
      serverOwner,
      logger: logger as never,
    },
    {
      storage: options.storage,
      storageAdapter,
      gateway,
      cursor,
      masterKey,
      serverOwner,
      logger: logger as never,
    },
    {
      async canSync() {
        try {
          const serverInfo = await gateway.getServer(
            options.serverAccount.address,
          );
          if (serverInfo?.id) return { ok: true };
          return {
            ok: false,
            reason: "unregistered",
            message: "Register this Personal Server before syncing.",
          };
        } catch (err) {
          logger.warn("Could not verify server registration for sync", err);
          return {
            ok: false,
            reason: "registration_check_failed",
            message: "Could not verify server registration before syncing.",
          };
        }
      },
    },
  );
  syncManager.start();
  return { syncManager, serverOwner };
}
