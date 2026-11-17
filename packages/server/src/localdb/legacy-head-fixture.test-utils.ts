/**
 * A per-stream head row as the registry still holds it for data an older build
 * published. No device writes this row any more; the delete path still has to
 * tombstone it (and read its head to place the stream's lifetime), so delete
 * tests plant it directly. Its head lists no parts: delete reads the head's
 * lifetime fields and nothing of its records.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import {
  digestHead,
  encodeHead,
  HEAD_FORMAT,
  streamScope,
  type ControlHashes,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { StreamSyncKeyPorts } from "@opendatalabs/personal-server-ts-core/stream-sync";

export async function legacyHeadRow(input: {
  readonly reads: Map<string, ControlRead>;
  readonly blobs: Map<string, Uint8Array>;
  readonly keys: StreamSyncKeyPorts;
  readonly hashes: ControlHashes;
  readonly keyCheck: string;
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
}) {
  const scope = streamScope(input.connector, input.ns, input.stream);
  const clear = encodeHead({
    format: HEAD_FORMAT,
    connector: input.connector,
    ns: input.ns,
    stream: input.stream,
    generation: 1,
    keyCheck: input.keyCheck,
    lastDeleteVersion: 0,
    complete: true,
    observedAt: 100,
    replacedAt: 100,
    parts: [],
    primaryKey: ["id"],
    profile: { key: null, version: "1" },
    recordCount: 0,
  });
  const { dataHash, blobName } = await digestHead(
    async (b) => keccak_256(b),
    clear,
  );
  input.blobs.set(
    `${scope}/${blobName}`,
    await input.keys.encrypt(scope, clear),
  );
  input.reads.set(scope, {
    found: true,
    version: 1,
    dataHash,
    metadataHash: input.hashes.activeMetadata,
    deleted: false,
  });
  return { scope, blobName, dataHash };
}
