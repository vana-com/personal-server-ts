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

    findUnsynced(options) {
      const unsynced = Array.from(entries.values())
        .filter((entry) => entry.fileId === null)
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
      const blocks: DataScopeBlock[] = [];
      let bytes = 0;
      for (let index = startIndex; index < manifest.blocks.length; index += 1) {
        const ref = manifest.blocks[index];
        if (!ref) continue;
        if (blocks.length > 0 && bytes + ref.sizeBytes > maxBytes) {
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
        blocks.push(block);
        bytes += ref.sizeBytes;
      }
      const nextIndex = startIndex + blocks.length;
      return {
        scope: manifest.scope,
        collectedAt: manifest.collectedAt,
        ...(manifest.schemaId ? { schemaId: manifest.schemaId } : {}),
        contentKind: manifest.contentKind,
        blocks,
        ...(nextIndex < manifest.blocks.length
          ? {
              nextCursor: encodeDataBlockCursor({
                scope,
                collectedAt,
                blockIndex: nextIndex,
              }),
            }
          : {}),
        warnings: manifest.warnings,
      };
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
      const indexed: IndexEntry = {
        ...entry,
        schemaId: entry.schemaId ?? null,
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
