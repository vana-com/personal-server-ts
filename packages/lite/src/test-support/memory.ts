import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
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
  let nextId = 1;

  function envelopeKey(scope: string, collectedAt: string): string {
    return `${scope}\n${collectedAt}`;
  }

  function entriesForScope(scope: string): IndexEntry[] {
    return sortEntries(
      Array.from(entries.values()).filter((entry) => entry.scope === scope),
    );
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
          deleted += 1;
        }
      }
      return deleted;
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
  return {
    kind,
    async readEnvelope(path) {
      return files.get(path) ?? null;
    },
    async writeEnvelope(path, envelope) {
      files.set(path, envelope);
      return new TextEncoder().encode(JSON.stringify(envelope)).length;
    },
    async deleteEnvelope(path) {
      files.delete(path);
    },
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
