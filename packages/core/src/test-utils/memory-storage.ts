/**
 * In-memory DataStoragePort for unit tests: envelopes in a Map, index rows
 * in an array, CAS revisions assigned max+1 per scope like the real index.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import type { DataStoragePort } from "../ports/index.js";
import type { WriteResult } from "../storage/hierarchy/index.js";
import type { IndexEntry, NewIndexEntry } from "../storage/index/types.js";
import { withScopeLock } from "../additions/scope-lock.js";
import type {
  LegacyWriteHold,
  LegacyWriteSeal,
} from "../storage/legacy-write-seal.js";

export interface MemoryDataStorage extends DataStoragePort {
  /** Every index row, oldest first (test inspection). */
  readonly entries: IndexEntry[];
}

export interface MemoryDataStorageOptions {
  /**
   * Seal this storage the way Node and Lite storage are sealed: a write that
   * makes a version durable runs inside `commit`; a removal runs inside
   * `remove` (or directly, when the caller passes the `hold` it got from
   * `commit`). Without one the storage is unsealed, as every older test
   * expects.
   */
  legacyWriteSeal?: LegacyWriteSeal;
  /**
   * Test seam: awaited inside every sealed write and removal, before it
   * changes anything. A test holds it open to keep a write in flight.
   */
  insideSealed?: () => Promise<void>;
}

export function createMemoryDataStorage(
  options: MemoryDataStorageOptions = {},
): MemoryDataStorage {
  const { legacyWriteSeal: seal, insideSealed } = options;
  const entries: IndexEntry[] = [];
  const envelopes = new Map<string, DataFileEnvelope>();
  // Per-scope first-seen ledgers: beside the data, never an index row.
  const ledgers = new Map<string, unknown>();
  let nextId = 1;

  const key = (scope: string, collectedAt: string) =>
    `${scope}\n${collectedAt}`;
  const byPath = (path: string) => entries.find((entry) => entry.path === path);
  const forScope = (scope: string) =>
    entries
      .filter((entry) => entry.scope === scope)
      .sort(
        (a, b) =>
          (b.casRevision ?? b.version) - (a.casRevision ?? a.version) ||
          b.collectedAt.localeCompare(a.collectedAt),
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

  const dropEmptyLedger = (scope: string) => {
    if (!entries.some((entry) => entry.scope === scope)) ledgers.delete(scope);
  };

  const addRow = (entry: NewIndexEntry): IndexEntry => {
    const casRevision =
      entry.casRevision ??
      entries
        .filter((row) => row.scope === entry.scope)
        .reduce(
          (max, row) => Math.max(max, row.casRevision ?? row.version),
          0,
        ) + 1;
    const version = entry.version ?? casRevision;
    const indexed: IndexEntry = {
      ...entry,
      id: nextId,
      schemaId: entry.schemaId ?? null,
      createdAt: new Date(0).toISOString(),
      version,
      casRevision,
      dataPointId: entry.dataPointId ?? null,
    };
    nextId += 1;
    entries.push(indexed);
    return indexed;
  };
  const putEnvelope = (envelope: DataFileEnvelope): WriteResult => {
    envelopes.set(key(envelope.scope, envelope.collectedAt), envelope);
    const path = `${envelope.scope}/${envelope.collectedAt}.json`;
    return {
      path,
      relativePath: path,
      sizeBytes: JSON.stringify(envelope).length,
    };
  };

  /** A write that adds a visible legacy version. */
  const sealedWrite = <T>(work: () => T | Promise<T>): Promise<T> =>
    seal
      ? seal.commit(async () => {
          await insideSealed?.();
          return work();
        })
      : Promise.resolve().then(work);
  /** A pure removal: sealed in every mode, or direct inside a `commit`. */
  const sealedRemoval = <T>(
    hold: LegacyWriteHold | undefined,
    work: () => T | Promise<T>,
  ): Promise<T> => {
    const run = async () => {
      await insideSealed?.();
      return work();
    };
    return seal && !hold ? seal.remove(run) : run();
  };

  return {
    kind: "custom",
    ...(seal ? { legacyWriteSeal: seal } : {}),
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
            (entries.find(
              (row) =>
                row.scope === entry.scope &&
                row.collectedAt === existing.latestCollectedAt,
            )?.casRevision ?? 0) > (entry.casRevision ?? entry.version)
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
      let newest: IndexEntry | undefined;
      for (const entry of entries) {
        if (entry.dataPointId !== dataPointId) continue;
        if (!newest || entry.version >= newest.version) newest = entry;
      }
      return newest;
    },
    findUnsynced(options) {
      const unsynced = entries.filter((entry) => entry.dataPointId === null);
      return options?.limit ? unsynced.slice(0, options.limit) : unsynced;
    },
    findUnsyncedPage({ afterId, limit }) {
      return entries
        .filter((entry) => entry.dataPointId === null && entry.id > afterId)
        .sort((a, b) => a.id - b.id)
        .slice(0, limit);
    },
    maxUnsyncedId() {
      return entries.reduce(
        (max, entry) =>
          entry.dataPointId === null ? Math.max(max, entry.id) : max,
        0,
      );
    },
    async readEnvelope(scope, collectedAt) {
      const envelope = envelopes.get(key(scope, collectedAt));
      if (!envelope)
        throw new Error(`missing envelope ${scope}@${collectedAt}`);
      return envelope;
    },
    writeEnvelope(envelope) {
      return sealedWrite(() => putEnvelope(envelope));
    },
    ...(seal
      ? {
          // The blob and its row are one sealed step, as in Node and Lite.
          writeEnvelopeAndIndex: (envelope, entry) =>
            sealedWrite(() => {
              const written = putEnvelope(envelope);
              return addRow({
                ...entry,
                path: written.relativePath,
                sizeBytes: entry.sizeBytes ?? written.sizeBytes,
              });
            }),
        }
      : {}),
    insertEntry(entry) {
      return seal ? sealedWrite(() => addRow(entry)) : addRow(entry);
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
    async readFirstSeenLedger(scope) {
      return structuredClone(ledgers.get(scope) ?? null);
    },
    async writeFirstSeenLedger(scope, ledger) {
      ledgers.set(scope, structuredClone(ledger));
    },
    async deleteFirstSeenLedger(scope) {
      ledgers.delete(scope);
    },
    // Deletions run under the scope's sidecar lock, and the sidecar goes with
    // the scope's last version, so a delete never leaves a stale ledger.
    async deleteScope(scope, hold) {
      return sealedRemoval(hold, () =>
        withScopeLock(scope, async () => {
          ledgers.delete(scope);
          return remove((entry) => entry.scope === scope);
        }),
      );
    },
    async deleteByFileId(fileId, hold) {
      const scope = entries.find((entry) => entry.fileId === fileId)?.scope;
      if (scope === undefined) return false;
      return sealedRemoval(hold, () =>
        withScopeLock(scope, async () => {
          const removed = remove((entry) => entry.fileId === fileId) > 0;
          dropEmptyLedger(scope);
          return removed;
        }),
      );
    },
    async deleteVersion(scope, collectedAt, fence, hold) {
      return sealedRemoval(hold, () =>
        withScopeLock(scope, async () => {
          const removed =
            remove(
              (entry) =>
                entry.scope === scope &&
                entry.collectedAt === collectedAt &&
                (fence === undefined ||
                  (entry.id === fence.id && entry.path === fence.path)),
            ) > 0;
          dropEmptyLedger(scope);
          return removed;
        }),
      );
    },
    async deleteVersionIfEnvelopeMissing(scope, collectedAt, fence, hold) {
      return sealedRemoval(hold, () =>
        withScopeLock(scope, async () => {
          if (envelopes.has(key(scope, collectedAt))) return false;
          const removed =
            remove(
              (entry) =>
                entry.scope === scope &&
                entry.collectedAt === collectedAt &&
                entry.id === fence.id &&
                entry.path === fence.path,
            ) > 0;
          dropEmptyLedger(scope);
          return removed;
        }),
      );
    },
    async dropUnsyncedEntry(path, hold) {
      const entry = entries.find(
        (row) => row.path === path && row.dataPointId === null,
      );
      if (!entry) return false;
      return sealedRemoval(hold, () =>
        withScopeLock(entry.scope, async () => {
          const index = entries.indexOf(entry);
          if (index === -1) return false;
          entries.splice(index, 1);
          dropEmptyLedger(entry.scope);
          return true;
        }),
      );
    },
  };
}
