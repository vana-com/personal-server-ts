/**
 * Test-only publisher: encodes stream heads and parts with the package codec
 * and encrypts them as a writer does, so read-side tests and the oracle can
 * seed storage and the registry without the publish driver.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import {
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import {
  controlHashes,
  controlScope,
  deriveKeyCheck,
  deriveNs,
  digestHead,
  encodeHead,
  encodeLine,
  encodeWinners,
  inPrefix,
  NAMESPACE_KEY_LABEL,
  partBlobName,
  pkHash,
  streamScope,
  type Head,
  type HeadPart,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncReadHashes } from "./keys.js";

const { sha256, keccak256 } = streamSyncReadHashes;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export interface TestOwnerKey {
  readonly masterKey: Uint8Array;
  readonly keyCheck: string;
  ns(connector: string, accountId: string): Promise<string>;
  encrypt(scope: string, clear: Uint8Array): Promise<Uint8Array>;
  /** Registry hashes of this key's control rows. */
  control(): Promise<{
    active: { dataHash: string; metadataHash: string };
    tombstone: { dataHash: string; metadataHash: string };
  }>;
}

export async function testOwnerKey(
  input: Uint8Array | Promise<Uint8Array>,
): Promise<TestOwnerKey> {
  const masterKey = await input;
  const kNs = deriveScopeKey(masterKey, NAMESPACE_KEY_LABEL);
  const mac = async (message: Uint8Array) => hmac(nobleSha256, kNs, message);
  const keyCheck = await deriveKeyCheck(mac);
  return {
    masterKey,
    keyCheck,
    ns: (connector, accountId) => deriveNs(mac, connector, accountId),
    encrypt: async (scope, clear) =>
      encryptWithPassword(clear, hex(deriveScopeKey(masterKey, scope))),
    async control() {
      const h = await controlHashes(keccak256, keyCheck);
      return {
        active: { dataHash: h.activeData, metadataHash: h.activeMetadata },
        tombstone: {
          dataHash: h.tombstoneData,
          metadataHash: h.tombstoneMetadata,
        },
      };
    },
  };
}

export interface TestHeadInput {
  readonly key: TestOwnerKey;
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly generation: number;
  readonly primaryKey: readonly string[];
  readonly records: readonly JsonObject[];
  readonly observedAt: number;
  readonly runId?: string;
  readonly complete?: boolean;
  readonly profileKey?: string | null;
  readonly profileVersion?: string;
  /** Bit prefixes of the parts; default one part. Must be prefix-free and cover every key. */
  readonly prefixes?: readonly string[];
  /** Encrypt the head with this key instead (a foreign or wrong key). */
  readonly encryptWith?: TestOwnerKey;
  /** Write a format 3 head that names the complete head it replaced. */
  readonly lastComplete?: { version: number; dataHash: string };
}

export interface TestHead {
  readonly scope: string;
  readonly head: Head;
  readonly headBytes: Uint8Array;
  /** Registry `dataHash` of the head. */
  readonly dataHash: `0x${string}`;
  /** Encrypted blobs by storage key: the head and its parts. */
  readonly blobs: ReadonlyMap<string, Uint8Array>;
}

export async function buildTestHead(input: TestHeadInput): Promise<TestHead> {
  const scope = streamScope(input.connector, input.ns, input.stream);
  const encryptor = input.encryptWith ?? input.key;
  const runId = input.runId ?? "test-run";
  const winners: { pkHash: string; text: string }[] = [];
  for (const record of input.records) {
    winners.push({
      pkHash: await pkHash(sha256, record, input.primaryKey),
      text: encodeLine({ o: input.observedAt, r: runId, v: record }),
    });
  }
  winners.sort((a, b) => (a.pkHash < b.pkHash ? -1 : 1));
  const blobs = new Map<string, Uint8Array>();
  const parts: HeadPart[] = [];
  for (const prefix of input.prefixes ?? [""]) {
    const encoded = await encodeWinners(
      sha256,
      prefix,
      winners.filter((w) => inPrefix(w.pkHash, prefix)),
    );
    if (!encoded) continue;
    parts.push(encoded.entry);
    blobs.set(
      `${scope}/${partBlobName(input.generation, encoded.entry.hash)}`,
      await encryptor.encrypt(scope, encoded.data),
    );
  }
  const head: Head = {
    complete: input.complete ?? true,
    connector: input.connector,
    format: input.lastComplete ? 3 : 1,
    ...(input.lastComplete
      ? { lastDeleteVersion: 0, lastComplete: input.lastComplete }
      : {}),
    generation: input.generation,
    keyCheck: encryptor.keyCheck,
    ns: input.ns,
    observedAt: input.observedAt,
    parts,
    primaryKey: [...input.primaryKey],
    profile: {
      key: input.profileKey === undefined ? input.connector : input.profileKey,
      version: input.profileVersion ?? "1.0.0",
    },
    recordCount: winners.length,
    stream: input.stream,
  };
  const headBytes = encodeHead(head);
  const digest = await digestHead(keccak256, headBytes);
  blobs.set(
    `${scope}/${digest.blobName}`,
    await encryptor.encrypt(scope, headBytes),
  );
  return { scope, head, headBytes, dataHash: digest.dataHash, blobs };
}

export { controlScope };
