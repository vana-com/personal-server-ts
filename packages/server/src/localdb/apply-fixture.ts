/** Encrypted registry fixtures shared by apply and Node composition tests. */
import { sha256 } from "@noble/hashes/sha2";
import { keccak_256 } from "@noble/hashes/sha3";
import {
  canonicalJson,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  digestHead,
  encodeHead,
  frameOfBody,
  partBlobName,
  pkHash,
  streamScope,
  toHex,
  type ControlRead,
  type Head,
  type HeadPart,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type {
  StreamSyncKeyPorts,
  StreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";

const SHA = async (bytes: Uint8Array) => sha256(bytes);
export async function remoteFixture(
  keys: StreamSyncKeyPorts,
  connector = "fixture-source",
  ns = "",
) {
  const keyCheck = await deriveKeyCheck((m) => keys.namespaceHmac(m));
  const hashes = await controlHashes(async (b) => keccak_256(b), keyCheck);
  const reads = new Map<string, ControlRead>();
  const blobs = new Map<string, Uint8Array>();
  const control = controlScope(connector, ns);
  const setControl = (generation: number, deleted = false) =>
    reads.set(control, {
      found: true,
      version: generation,
      dataHash: hashes.activeData,
      metadataHash: hashes.activeMetadata,
      deleted,
    });
  setControl(1);
  const registry: StreamSyncRegistry = {
    read: async (scope) => reads.get(scope) ?? { found: false },
    listControlRows: async () =>
      [...reads]
        .filter(([scope]) => scope === control)
        .map(([scope, read]) => ({ scope, read })),
    listStreamRows: async (key) =>
      [...reads]
        .filter(([scope]) => key === connector && scope !== control)
        .map(([scope, read]) => ({ scope, read })),
    post: async () => {
      throw new Error("unexpected fixture post");
    },
  };
  const storage = {
    get: async (key: string) => blobs.get(key) ?? null,
    exists: async (key: string) => blobs.has(key),
    put: async (key: string, bytes: Uint8Array) => {
      blobs.set(key, bytes);
    },
  };
  async function head(
    stream: string,
    values: readonly JsonObject[],
    options: {
      version?: number;
      generation?: number;
      o?: number;
      /** Format 5: when the replacing run dropped what the source no longer lists. */
      replacedAt?: number;
      f?: number | null;
      format?: Head["format"];
      pieceBytes?: number;
      complete?: boolean;
      primaryKey?: string[];
      profile?: { key: string | null; version: string };
    } = {},
  ) {
    const scope = streamScope(connector, ns, stream);
    const generation = options.generation ?? 1;
    const format = options.format ?? 4;
    const frames = await Promise.all(
      values.map(async (v) => {
        const body = new TextEncoder().encode(canonicalJson(v));
        const k = await pkHash(SHA, v, options.primaryKey ?? ["id"]);
        const envelope = {
          h: toHex(sha256(body)),
          k,
          n: body.length,
          o: options.o ?? 100,
          r: "remote-run",
          ...(format >= 4
            ? { f: options.f === undefined ? 50 : options.f }
            : {}),
        };
        return { k, bytes: frameOfBody(envelope, body) };
      }),
    );
    frames.sort((a, b) => a.k.localeCompare(b.k));
    const parts: HeadPart[] = [];
    for (const frame of frames) {
      const size = options.pieceBytes ?? frame.bytes.length;
      for (let at = 0; at < frame.bytes.length; at += size) {
        const bytes = frame.bytes.slice(at, at + size);
        const hash = toHex(sha256(bytes));
        parts.push({
          prefix: "",
          hash,
          bytes: bytes.length,
          count: at === 0 ? 1 : 0,
        });
        blobs.set(
          `${scope}/${partBlobName(generation, hash)}`,
          await keys.encryptPart(scope, bytes),
        );
      }
    }
    const clear = encodeHead({
      connector,
      ns,
      stream,
      generation,
      format,
      ...(format >= 3 ? { lastDeleteVersion: 0 } : {}),
      keyCheck,
      primaryKey: options.primaryKey ?? ["id"],
      profile: options.profile ?? { key: null, version: "1" },
      complete: options.complete ?? true,
      observedAt: options.o ?? 100,
      ...(format >= 5
        ? { replacedAt: options.replacedAt ?? options.o ?? 100 }
        : {}),
      recordCount: values.length,
      parts,
    });
    const { dataHash, blobName } = await digestHead(
      async (b) => keccak_256(b),
      clear,
    );
    blobs.set(`${scope}/${blobName}`, await keys.encrypt(scope, clear));
    reads.set(scope, {
      found: true,
      version: options.version ?? 1,
      dataHash,
      metadataHash: hashes.activeMetadata,
      deleted: false,
    });
    return { scope, parts, blobName, dataHash };
  }
  return { registry, storage, reads, blobs, head, setControl, hashes, control };
}
