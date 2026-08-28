/**
 * In-memory DataStoragePort for unit tests: envelopes in a Map, index rows
 * in an array, versions assigned max+1 per scope like the real index.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../ports/index.js";
import type { IndexEntry } from "../storage/index/types.js";

export interface MemoryDataStorage extends DataStoragePort {
  /** Every index row, oldest first (test inspection). */
  readonly entries: IndexEntry[];
}

export function createMemoryDataStorage(): MemoryDataStorage {
  const entries: IndexEntry[] = [];
  const envelopes = new Map<string, DataFileEnvelope>();
  let nextId = 1;

  const key = (scope: string, collectedAt: string) =>
    `${scope}\n${collectedAt}`;
  const byPath = (path: string) => entries.find((entry) => entry.path === path);
  const forScope = (scope: string) =>
    entries
      .filter((entry) => entry.scope === scope)
      .sort(
        (a, b) =>
          b.collectedAt.localeCompare(a.collectedAt) || b.version - a.version,
      );
  const remove = (predicate: (entry: IndexEntry) => boolean) => {
    let removed = 0;
    for (let index = entries.length - 1; index >= 0; index -= 1) {
      const entry = entries[index]!;
      if (!predicate(entry)) continue;
      entries.splice(index, 1);
      envelopes.delete(key(entry.scope, entry.collectedAt));
      removed += 1;
    }
    return removed;
  };

  return {
    kind: "custom",
    entries,
    listScopes({ scopePrefix, limit = 20, offset = 0 }) {
      const summaries = new Map<
        string,
        { scope: string; latestCollectedAt: string; versionCount: number }
      >();
      for (const entry of entries) {
        if (scopePrefix && !entry.scope.startsWith(scopePrefix)) continue;
        const existing = summaries.get(entry.scope);
        summaries.set(entry.scope, {
          scope: entry.scope,
          latestCollectedAt:
            existing &&
            existing.latestCollectedAt.localeCompare(entry.collectedAt) > 0
              ? existing.latestCollectedAt
              : entry.collectedAt,
          versionCount: (existing?.versionCount ?? 0) + 1,
        });
      }
      const scopes = [...summaries.values()].sort((a, b) =>
        a.scope.localeCompare(b.scope),
      );
      return {
        scopes: scopes.slice(offset, offset + limit),
        total: scopes.length,
      };
    },
    listVersions(scope, { limit = 20, offset = 0 }) {
      return forScope(scope).slice(offset, offset + limit);
    },
    countVersions(scope) {
      return forScope(scope).length;
    },
    findEntry({ scope, fileId, at }) {
      if (fileId) return entries.find((entry) => entry.fileId === fileId);
      const scoped = forScope(scope);
      if (at) return scoped.find((entry) => entry.collectedAt === at);
      return scoped[0];
    },
    findByFileId(fileId) {
      return entries.find((entry) => entry.fileId === fileId);
    },
    findByDataPointId(dataPointId) {
      return entries.find((entry) => entry.dataPointId === dataPointId);
    },
    findUnsynced(options) {
      const unsynced = entries.filter((entry) => entry.dataPointId === null);
      return options?.limit ? unsynced.slice(0, options.limit) : unsynced;
    },
    async readEnvelope(scope, collectedAt) {
      const envelope = envelopes.get(key(scope, collectedAt));
      if (!envelope)
        throw new Error(`missing envelope ${scope}@${collectedAt}`);
      return envelope;
    },
    async writeEnvelope(envelope) {
      envelopes.set(key(envelope.scope, envelope.collectedAt), envelope);
      const path = `${envelope.scope}/${envelope.collectedAt}.json`;
      return {
        path,
        relativePath: path,
        sizeBytes: JSON.stringify(envelope).length,
      };
    },
    insertEntry(entry) {
      const version =
        entry.version ??
        forScope(entry.scope).reduce(
          (max, row) => Math.max(max, row.version),
          0,
        ) + 1;
      const indexed: IndexEntry = {
        ...entry,
        id: nextId,
        schemaId: entry.schemaId ?? null,
        createdAt: new Date(0).toISOString(),
        version,
        dataPointId: entry.dataPointId ?? null,
      };
      nextId += 1;
      entries.push(indexed);
      return indexed;
    },
    updateFileId(path, fileId) {
      const entry = byPath(path);
      if (!entry) return false;
      entry.fileId = fileId;
      return true;
    },
    findLatestVersionByScope(scope) {
      return forScope(scope).reduce(
        (max, row) => Math.max(max, row.version),
        0,
      );
    },
    updateDataPointId(path, dataPointId) {
      const entry = byPath(path);
      if (!entry) return false;
      entry.dataPointId = dataPointId;
      return true;
    },
    updateEntryVersion(path, version) {
      const entry = byPath(path);
      if (!entry) return false;
      entry.version = version;
      return true;
    },
    async deleteScope(scope) {
      return remove((entry) => entry.scope === scope);
    },
    async deleteByFileId(fileId) {
      return remove((entry) => entry.fileId === fileId) > 0;
    },
    async deleteVersion(scope, collectedAt) {
      return (
        remove(
          (entry) => entry.scope === scope && entry.collectedAt === collectedAt,
        ) > 0
      );
    },
    dropUnsyncedEntry(path) {
      const index = entries.findIndex(
        (entry) => entry.path === path && entry.dataPointId === null,
      );
      if (index === -1) return false;
      entries.splice(index, 1);
      return true;
    },
  };
}
