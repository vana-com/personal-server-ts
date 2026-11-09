/**
 * The published stream heads, read the way the running server reads them but
 * into memory and with GET requests only.
 *
 * The registry listing is `GET <gateway>/v1/data?user=<owner>&includeDeleted=true`
 * (no credentials). The blobs are `GET <storage>/v1/chains/<id>/blobs/<owner>/…`
 * through the public-read storage adapter, which never signs. The read service
 * is opened on in-memory files and without a writer overlay, so it answers from
 * the published heads alone: this device's own spool and unpublished runs
 * never count, exactly as a readback must have it.
 *
 * What it needs from outside the data folder is the owner's master-key
 * signature (`VANA_MASTER_KEY_SIGNATURE`): it names the owner and decrypts the
 * blobs. The server account key in `key.json` is not read.
 */

import {
  legacyMasterKey,
  recoverOwnerAddress,
} from "@opendatalabs/personal-server-ts-core/keys";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createVanaSyncStorageAdapter,
  resolveVanaStorageEndpoint,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { createGatewayDataPointFeed } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createMemoryStreamSyncReadFiles,
  isPhysicalScope,
  createStorageBlobReader,
  createStreamSyncReadKeys,
  StreamSyncReadService,
} from "@opendatalabs/personal-server-ts-core/stream-sync-read";

export interface PublishedHeadsInput {
  readonly config: ServerConfig;
  /** The owner's master-key signature (hex). Read from the environment. */
  readonly masterKeySignature: `0x${string}`;
  /**
   * The device's own `stream-sync-read/mirror.json`, if the copy has one. The
   * mirror keeps the delete history the registry itself drops once a stream is
   * re-collected; without it a fenced file cannot be explained, so it reads
   * back as a mismatch (the safe side).
   */
  readonly mirrorBytes: Uint8Array | null;
}

export interface PublishedHeads {
  readonly reader: StreamSyncReadService;
  readonly ownerAddress: `0x${string}`;
  readonly hosts: { readonly gateway: string; readonly storage: string };
  readonly listing: {
    readonly pages: number;
    readonly rows: number;
    readonly deviceMirror: boolean;
  };
}

/** Where the read service keeps its registry mirror (mirror.ts `PATH`). */
export const MIRROR_PATH = "mirror.json";

const noop = { info() {}, warn() {}, error() {} };

/** The hosts a run may talk to, from the (copied) config. */
export function allowedHostsOf(config: ServerConfig): {
  gateway: string;
  storage: string;
} {
  return {
    gateway: new URL(config.gateway.url).hostname,
    storage: new URL(resolveVanaStorageEndpoint(config)).hostname,
  };
}

export function parseConfig(raw: unknown): ServerConfig {
  return ServerConfigSchema.parse(raw ?? {});
}

export async function loadPublishedHeads(
  input: PublishedHeadsInput,
): Promise<PublishedHeads> {
  const { config } = input;
  const ownerAddress = await recoverOwnerAddress(input.masterKeySignature);
  const masterKey = legacyMasterKey(input.masterKeySignature);

  const storageAdapter = createVanaSyncStorageAdapter({
    config,
    serverOwner: ownerAddress,
    // Public reads never sign; a call to sign is a bug, not a request.
    serverAccount: {
      address: ownerAddress,
      signMessage: () => Promise.reject(new Error("dry run never signs")),
    },
    reads: "public",
  });
  const files = createMemoryStreamSyncReadFiles();
  if (input.mirrorBytes) await files.write(MIRROR_PATH, input.mirrorBytes);
  const reader = await StreamSyncReadService.open({
    files,
    blobs: createStorageBlobReader(storageAdapter),
    keys: await createStreamSyncReadKeys(masterKey),
    logger: noop,
    durable: false,
  });

  const feed = createGatewayDataPointFeed({ gatewayUrl: config.gateway.url });
  let cursor: string | null = null;
  let pages = 0;
  let rows = 0;
  for (;;) {
    const listed: Awaited<ReturnType<typeof feed.listDataPointsByOwner>> =
      await feed.listDataPointsByOwner(ownerAddress, cursor, {
        includeDeleted: true,
      });
    const physical = listed.dataPoints.filter((p) => isPhysicalScope(p.scope));
    await reader.observe(physical, {
      fromStart: cursor === null,
      lastPage: listed.cursor === null,
    });
    pages += 1;
    rows += physical.length;
    if (listed.cursor === null) break;
    cursor = listed.cursor;
  }
  await reader.importPending();

  return {
    reader,
    ownerAddress,
    hosts: allowedHostsOf(config),
    listing: { pages, rows, deviceMirror: input.mirrorBytes !== null },
  };
}
