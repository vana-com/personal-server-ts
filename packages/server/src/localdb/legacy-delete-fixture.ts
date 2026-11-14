/**
 * The registry state a device that cleaned streams before it landed the
 * control tombstone left behind: one stream row is a delete marker of the
 * active lifetime and the control row is still active. The deleter no longer
 * writes in this order, but an older build, or any delete that stopped between
 * the two writes, did, and every reader still has to place such a row. The
 * row is built the way `delete.ts` builds a stream delete.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import {
  deriveKeyCheck,
  digestHead,
  encodeHead,
  HEAD_FORMAT,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  StreamSyncBlobs,
  StreamSyncKeyPorts,
  StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { endedGenerationDeleteMetadataHash } from "../../../core/src/stream-sync/delete-metadata.js";

export async function postStreamDeleteOnly(input: {
  readonly registry: StreamSyncRegistry;
  readonly blobs: StreamSyncBlobs;
  readonly keys: StreamSyncKeyPorts;
  readonly owner: string;
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly scope: string;
  /** The generation of the active lifetime the delete ends. */
  readonly endedGeneration: number;
}) {
  const row = await input.registry.read(input.scope);
  const version = row.found ? row.version + 1 : 1;
  const head = encodeHead({
    format: HEAD_FORMAT,
    connector: input.connector,
    ns: input.ns,
    stream: input.stream,
    generation: 1,
    keyCheck: await deriveKeyCheck((m) => input.keys.namespaceHmac(m)),
    lastDeleteVersion: version,
    complete: false,
    observedAt: 1000,
    parts: [],
    primaryKey: ["id"],
    profile: { key: null, version: "0.0.0" },
    recordCount: 0,
  });
  const digest = await digestHead(async (b) => keccak_256(b), head);
  await input.blobs.put(
    `${input.scope}/${digest.blobName}`,
    await input.keys.encrypt(input.scope, head),
  );
  await input.registry.post({
    ownerAddress: input.owner as `0x${string}`,
    scope: input.scope,
    dataHash: digest.dataHash,
    metadataHash: endedGenerationDeleteMetadataHash(
      input.scope,
      version,
      input.endedGeneration,
    ),
    expectedVersion: String(version),
    signature: "0x00",
  });
}
