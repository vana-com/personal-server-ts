import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type {
  DataBlockManifest,
  DataScopeBlock,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import {
  DataBlockStorageError,
  encodeDataBlockCursor,
  validateDataBlockCursor,
} from "@opendatalabs/personal-server-ts-core/storage/blocks";
import type { IndexEntry } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { AccessLogEntry } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { AccessLogReader } from "@opendatalabs/personal-server-ts-core/logging/access-reader";
import type { AccessLogWriter } from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { PsLiteTokenStore } from "../runtime.js";
import type {
  PsLiteDataFileStore,
  PsLiteFileStorageKind,
  PsLitePersistedStorageState,
  PsLitePersistenceAdapter,
  PsLiteStorageCapabilities,
} from "../storage.js";
import type { PsLiteStateKey, PsLiteStateStore } from "../state.js";
import {
  createStorageReadMethods,
  previewEnvelopeValue,
  readEnvelopeFromMap,
  sortEntries,
} from "../storage-utils.js";

const TEXT_PAGE_MEDIA_TYPE = "text/plain; charset=utf-8";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

interface PsLiteRuntimeStoreCapabilities {
  capabilities?: {
    tokens?: "memory";
    accessLogs?: "memory";
  };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function createMemoryPsLiteAccessLogStore(): AccessLogReader &
  AccessLogWriter {
  const logs: AccessLogEntry[] = [];
  return {
    capabilities: { accessLogs: "memory" },
    async write(entry) {
      logs.push(entry);
    },
    async read(options) {
      const limit = options?.limit ?? 50;
      const offset = options?.offset ?? 0;
      const sorted = [...logs].sort(
        (a, b) =>
          new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
      );
      return {
        logs: sorted.slice(offset, offset + limit),
        total: sorted.length,
        limit,
        offset,
      };
    },
  } as AccessLogReader & AccessLogWriter & PsLiteRuntimeStoreCapabilities;
}

export function createMemoryPsLiteTokenStore(): PsLiteTokenStore {
  const tokens = new Map<string, string | null>();

  function normalizeExpiresAt(value: string | Date | null | undefined) {
    if (value == null) return null;
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
      throw new Error("Invalid token expiry");
    }
    return date.toISOString();
  }

  function isExpired(expiresAt: string | null | undefined): boolean {
    return expiresAt ? new Date(expiresAt).getTime() <= Date.now() : false;
  }

  return {
    capabilities: { tokens: "memory" },
    async getTokens() {
      return Array.from(tokens.entries())
        .filter(([, expiresAt]) => !isExpired(expiresAt))
        .map(([token]) => token);
    },
    async isValid(token) {
      const expiresAt = tokens.get(token);
      if (expiresAt === undefined) return false;
      if (isExpired(expiresAt)) {
        tokens.delete(token);
        return false;
      }
      return true;
    },
    async addToken(token, options) {
      tokens.set(token, normalizeExpiresAt(options?.expiresAt));
    },
    async removeToken(token) {
      tokens.delete(token);
    },
  } as PsLiteTokenStore & PsLiteRuntimeStoreCapabilities;
}

export function createMemoryPsLiteStorage(): DataStoragePort {
  const entries = new Map<string, IndexEntry>();
  const envelopes = new Map<string, DataFileEnvelope>();
  const blockManifests = new Map<string, DataBlockManifest>();
  const blockPayloads = new Map<string, DataScopeBlock>();
  let nextId = 1;

  function envelopeKey(scope: string, collectedAt: string): string {
    return `${scope}\n${collectedAt}`;
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(
      Array.from(entries.values()).filter((entry) => entry.scope === scope),
    );
  }

  function blockKey(scope: string, collectedAt: string): string {
    return `${scope}\n${collectedAt}`;
  }

  return {
    kind: "browser-indexeddb-opfs",
    capabilities: {
      metadata: "memory",
      files: "memory",
      opfsAvailable: false,
    } satisfies PsLiteStorageCapabilities,
    ...createStorageReadMethods(() => entries.values(), entriesForScope),

    findByFileId(fileId) {
      return Array.from(entries.values()).find(
        (entry) => entry.fileId === fileId,
      );
    },

    findByDataPointId(dataPointId) {
      return Array.from(entries.values()).find(
        (entry) => entry.dataPointId === dataPointId,
      );
    },

    findUnsynced(options) {
      const unsynced = Array.from(entries.values())
        .filter((entry) => entry.dataPointId === null)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      return options?.limit === undefined
        ? unsynced
        : unsynced.slice(0, options.limit);
    },

    async readEnvelope(scope, collectedAt) {
      return readEnvelopeFromMap(envelopes, envelopeKey(scope, collectedAt));
    },

    async readEnvelopePreview(scope, collectedAt, { maxBytes }) {
      const envelope = readEnvelopeFromMap(
        envelopes,
        envelopeKey(scope, collectedAt),
      );
      return previewEnvelopeValue(envelope, maxBytes);
    },

    async writeEnvelope(envelope) {
      envelopes.set(
        envelopeKey(envelope.scope, envelope.collectedAt),
        envelope,
      );
      return {
        path: `${envelope.scope}/${envelope.collectedAt}.json`,
        relativePath: `${envelope.scope}/${envelope.collectedAt}.json`,
        sizeBytes: new TextEncoder().encode(JSON.stringify(envelope)).length,
      };
    },

    async readScopeBlocks(scope, collectedAt, options) {
      const manifest = blockManifests.get(blockKey(scope, collectedAt));
      if (!manifest) {
        throw new DataBlockStorageError(
          "block_manifest_not_found",
          `Block manifest not found for ${scope} at ${collectedAt}`,
        );
      }
      const cursorResult = options.cursor
        ? validateDataBlockCursor(options.cursor, { scope, collectedAt })
        : { ok: true as const, cursor: null };
      if (!cursorResult.ok) {
        throw new DataBlockStorageError(
          "cursor_invalid",
          cursorResult.error.message,
        );
      }

      const maxBytes = Math.max(1, options.maxBytes);
      const startIndex = cursorResult.cursor?.blockIndex ?? 0;
      const startOffset = cursorResult.cursor?.intraBlockOffset ?? 0;
      const blocks: DataScopeBlock[] = [];
      let bytes = 0;
      let nextIndex = startIndex;
      let nextOffset: number | undefined;
      while (nextIndex < manifest.blocks.length) {
        const ref = manifest.blocks[nextIndex];
        if (!ref) {
          nextIndex += 1;
          continue;
        }
        const offset = nextIndex === startIndex ? startOffset : 0;
        if (offset >= ref.sizeBytes) {
          nextIndex += 1;
          continue;
        }
        if (
          blocks.length > 0 &&
          offset === 0 &&
          bytes + ref.sizeBytes > maxBytes
        ) {
          break;
        }
        const block = blockPayloads.get(
          `${blockKey(scope, collectedAt)}\n${ref.id}`,
        );
        if (!block) {
          throw new DataBlockStorageError(
            "block_payload_not_found",
            `Block payload not found for ${scope} at ${collectedAt}: ${ref.id}`,
          );
        }
        const page = pageBlock(block, offset, maxBytes - bytes);
        blocks.push(page.block);
        bytes += page.block.sizeBytes;

        if (page.nextOffset !== undefined) {
          nextOffset = page.nextOffset;
          break;
        }

        nextIndex += 1;
      }
      return {
        scope: manifest.scope,
        collectedAt: manifest.collectedAt,
        ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
        contentKind: manifest.contentKind,
        blocks,
        ...(nextOffset !== undefined || nextIndex < manifest.blocks.length
          ? {
              nextCursor: encodeDataBlockCursor({
                scope,
                collectedAt,
                blockIndex: nextIndex,
                ...(nextOffset === undefined
                  ? {}
                  : { intraBlockOffset: nextOffset }),
              }),
            }
          : {}),
        warnings: manifest.warnings,
      };
    },

    async hasScopeBlocks(scope, collectedAt) {
      return blockManifests.has(blockKey(scope, collectedAt));
    },

    async writeBlockManifest(scope, collectedAt, manifest, blocks) {
      const key = blockKey(scope, collectedAt);
      blockManifests.delete(key);
      for (const payloadKey of blockPayloads.keys()) {
        if (payloadKey.startsWith(`${key}\n`)) {
          blockPayloads.delete(payloadKey);
        }
      }
      for (const block of blocks) {
        blockPayloads.set(`${key}\n${block.id}`, block);
      }
      blockManifests.set(key, manifest);
    },

    insertEntry(entry) {
      const version =
        entry.version ??
        Array.from(entries.values()).reduce(
          (max, e) =>
            e.scope === entry.scope && e.version > max ? e.version : max,
          0,
        ) + 1;
      const indexed: IndexEntry = {
        ...entry,
        schemaId: entry.schemaId ?? null,
        version,
        dataPointId: entry.dataPointId ?? null,
        id: nextId,
        createdAt: new Date().toISOString(),
      };
      nextId += 1;
      entries.set(entry.path, indexed);
      return indexed;
    },

    updateFileId(path, fileId) {
      const entry = entries.get(path);
      if (!entry) return false;
      entries.set(path, { ...entry, fileId });
      return true;
    },

    findLatestVersionByScope(scope) {
      return Array.from(entries.values()).reduce(
        (max, e) => (e.scope === scope && e.version > max ? e.version : max),
        0,
      );
    },

    updateDataPointId(path, dataPointId) {
      const entry = entries.get(path);
      if (!entry) return false;
      entries.set(path, { ...entry, dataPointId });
      return true;
    },

    async deleteScope(scope) {
      let deleted = 0;
      for (const [path, entry] of entries.entries()) {
        if (entry.scope === scope) {
          entries.delete(path);
          envelopes.delete(envelopeKey(entry.scope, entry.collectedAt));
          const key = blockKey(entry.scope, entry.collectedAt);
          blockManifests.delete(key);
          for (const payloadKey of blockPayloads.keys()) {
            if (payloadKey.startsWith(`${key}\n`)) {
              blockPayloads.delete(payloadKey);
            }
          }
          deleted += 1;
        }
      }
      return deleted;
    },

    async deleteByFileId(fileId) {
      for (const [path, entry] of entries.entries()) {
        if (entry.fileId === fileId) {
          entries.delete(path);
          envelopes.delete(envelopeKey(entry.scope, entry.collectedAt));
          const key = blockKey(entry.scope, entry.collectedAt);
          blockManifests.delete(key);
          for (const payloadKey of blockPayloads.keys()) {
            if (payloadKey.startsWith(`${key}\n`)) {
              blockPayloads.delete(payloadKey);
            }
          }
          return true;
        }
      }
      return false;
    },
  } as DataStoragePort & { capabilities: PsLiteStorageCapabilities };
}

export function createMemoryPsLitePersistence(
  seed?: PsLitePersistedStorageState,
): PsLitePersistenceAdapter {
  let state = seed ? clone(seed) : null;
  return {
    async read() {
      return state ? clone(state) : null;
    },
    async write(nextState) {
      state = clone(nextState);
    },
  };
}

export function createMemoryPsLiteDataFileStore(
  kind: PsLiteFileStorageKind = "opfs",
): PsLiteDataFileStore {
  const files = new Map<string, DataFileEnvelope>();
  const blockManifests = new Map<string, DataBlockManifest>();
  const blockPayloads = new Map<string, DataScopeBlock>();
  return {
    kind,
    async readEnvelope(path) {
      return files.get(path) ?? null;
    },
    async readEnvelopePreview(path, { maxBytes }) {
      const envelope = files.get(path);
      if (!envelope) return null;
      return previewEnvelopeValue(envelope, maxBytes);
    },
    async writeEnvelope(path, envelope) {
      files.set(path, envelope);
      return new TextEncoder().encode(JSON.stringify(envelope)).length;
    },
    async deleteEnvelope(path) {
      files.delete(path);
    },
    async readBlockManifest(path) {
      return blockManifests.get(path) ?? null;
    },
    async writeBlockManifest(path, manifest) {
      blockManifests.set(path, manifest);
    },
    async readBlockPayload(path) {
      return blockPayloads.get(path) ?? null;
    },
    async writeBlockPayload(path, block) {
      blockPayloads.set(path, block);
    },
    async deleteBlockTree(pathPrefix) {
      deleteMapPrefix(blockManifests, pathPrefix);
      deleteMapPrefix(blockPayloads, pathPrefix);
    },
  };
}

function deleteMapPrefix<T>(map: Map<string, T>, pathPrefix: string): void {
  const prefix = pathPrefix.endsWith("/") ? pathPrefix : `${pathPrefix}/`;
  for (const path of map.keys()) {
    if (path === pathPrefix || path.startsWith(prefix)) {
      map.delete(path);
    }
  }
}

function pageBlock(
  block: DataScopeBlock,
  offsetBytes: number,
  maxBytes: number,
): { block: DataScopeBlock; nextOffset?: number } {
  const text =
    typeof block.value === "string" ? block.value : JSON.stringify(block.value);
  const bytes = textEncoder.encode(text);
  if (offsetBytes <= 0 && bytes.length <= maxBytes) {
    return { block };
  }

  const start = Math.min(Math.max(0, offsetBytes), bytes.length);
  const end = Math.min(bytes.length, start + Math.max(1, maxBytes));
  const value = textDecoder.decode(bytes.slice(start, end));

  return {
    block: {
      ...block,
      path: `${block.path}[bytes ${start}:${end}]`,
      mediaType: block.mediaType.startsWith("text/")
        ? block.mediaType
        : TEXT_PAGE_MEDIA_TYPE,
      value,
      sizeBytes: end - start,
      truncated: end < bytes.length,
    },
    ...(end < bytes.length ? { nextOffset: end } : {}),
  };
}

export function createMemoryPsLiteStateStore(
  seed?: Partial<Record<PsLiteStateKey, unknown>>,
): PsLiteStateStore {
  const values = new Map<PsLiteStateKey, unknown>(
    Object.entries(seed ?? {}) as Array<[PsLiteStateKey, unknown]>,
  );
  return {
    async get<T>(key: PsLiteStateKey) {
      return values.has(key) ? clone(values.get(key) as T) : null;
    },
    async set<T>(key: PsLiteStateKey, value: T) {
      values.set(key, clone(value));
    },
    async delete(key) {
      values.delete(key);
    },
  };
}
