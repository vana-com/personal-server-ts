/**
 * `LegacyDeletePorts` over the legacy gateway fake, for tests of the deleter's
 * legacy stage: the real seal and storage, the real gateway delete port and
 * the real `deleteScope` worker, over the fake's gateway and storage.
 */
import {
  legacyScopesOfConnector,
  legacyStreamsOfScope,
} from "../legacy-projection/erase-connector.js";
import { createLegacyWriteSeal } from "../storage/legacy-write-seal.js";
import { deleteScope } from "../sync/workers/delete.js";
import { createGatewayDeleteDataPort } from "../sync/delete-data-port.js";
import { createMemoryPendingBlobDeletionStore } from "../sync/pending-blob-deletions.js";
import {
  legacyHeadFrom,
  modeFrom,
  pendingBlobsFrom,
  type LegacyDeletePorts,
} from "../localdb/legacy-delete.js";
import type { TombstoneFinalityState } from "../ports/index.js";
import { authorityHearing } from "./account-mode.js";
import {
  FAKE_CHAIN_ID,
  FAKE_GATEWAY,
  FAKE_STORAGE,
  type LegacyGatewayFake,
} from "./legacy-gateway-fake.js";
import { createMemoryDataStorage } from "./memory-storage.js";

export async function legacyPortsOver(
  fake: LegacyGatewayFake,
  options: {
    /** `on`: the account switched. `off`: it did not. */
    mode?: "on" | "off";
    /** What the registry says of every tombstone's finality (default: final). */
    finality?:
      TombstoneFinalityState | ((scope: string) => TombstoneFinalityState);
    /** Blob deletes wait for the legacy tombstone's finality (see `deleteScope`). */
    gateBlobsOnFinality?: boolean;
    /**
     * A crash between the gateway tombstone and the blob queue's write: the
     * next N writes to this device's queue throw, after the tombstone landed.
     */
    queueWritesLost?: number;
  } = {},
) {
  const owner = fake.owner;
  const authority = await authorityHearing(owner, options.mode ?? "on");
  const seal = createLegacyWriteSeal({ authority, owner });
  const storage = createMemoryDataStorage({ legacyWriteSeal: seal });
  const memoryQueue = createMemoryPendingBlobDeletionStore();
  let lost = options.queueWritesLost ?? 0;
  const crash = () => {
    if (lost > 0) {
      lost -= 1;
      throw new Error("crashed before the queue was written");
    }
  };
  const pendingBlobDeletions: typeof memoryQueue = {
    ...memoryQueue,
    add: async (...args) => {
      crash();
      return memoryQueue.add(...args);
    },
    ...(memoryQueue.enqueue && {
      enqueue: async (
        ...args: Parameters<NonNullable<typeof memoryQueue.enqueue>>
      ) => {
        crash();
        return memoryQueue.enqueue!(...args);
      },
    }),
  };
  const deleteData = createGatewayDeleteDataPort({
    gatewayUrl: FAKE_GATEWAY,
    dataPointFeed: fake.feed,
    serverOwner: owner as `0x${string}`,
    signer: fake.signer,
    storage: {
      endpoint: FAKE_STORAGE,
      chainId: FAKE_CHAIN_ID,
      signMessage: async () => `0x${"ab".repeat(65)}` as `0x${string}`,
    },
    fetch: fake.fetch,
  });
  const finalityOf = (scope: string) => {
    const f = options.finality;
    return typeof f === "function"
      ? f(scope)
      : (f ?? { finalized: "99", settling: false, rolledBack: null });
  };
  const tombstoneFinality = {
    tombstoneState: async (scope: string) => finalityOf(scope),
  };
  const retired: string[] = [];
  const ports: LegacyDeletePorts = {
    scopesOf: legacyScopesOfConnector,
    streamsOf: legacyStreamsOfScope,
    mode: modeFrom(seal),
    head: legacyHeadFrom(fake.feed, owner),
    retire: async (scope, fence, retireOptions) => {
      retired.push(scope);
      return deleteScope(
        {
          storage,
          serverOwner: owner as `0x${string}`,
          deleteData,
          pendingBlobDeletions,
          ...(options.gateBlobsOnFinality && { tombstoneFinality }),
          dataPointFeed: fake.feed,
          logger: {
            debug() {},
            info() {},
            warn() {},
            error() {},
          } as never,
        },
        scope,
        { fence: { head: fence, pinned: retireOptions?.pinned === true } },
      );
    },
    pendingBlobs: pendingBlobsFrom(pendingBlobDeletions),
    finality: tombstoneFinality,
    versions: fake.inventory,
    objects: deleteData,
  };
  return { ports, seal, storage, authority, retired, pendingBlobDeletions };
}
