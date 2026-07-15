import {
  deleteAllForScope,
  deleteDataFile,
  readDataFile,
  readDataFilePreview,
  hasScopeBlocks,
  readScopeBlocks,
  writeBlockManifest,
  writeDataFile,
} from "./hierarchy.js";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataStorageEntryLookup,
  DataStorageListOptions,
  DataStoragePort,
  DataStorageScopeListOptions,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/node";

export interface NodeDataStorageDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
}

export function createNodeDataStorage(
  deps: NodeDataStorageDeps,
): DataStoragePort {
  return {
    kind: "node-fs-sqlite",
    listScopes(options: DataStorageScopeListOptions) {
      return deps.indexManager.listDistinctScopes(options);
    },
    listVersions(scope: string, options: DataStorageListOptions) {
      return deps.indexManager.findByScope({ scope, ...options });
    },
    countVersions(scope: string) {
      return deps.indexManager.countByScope(scope);
    },
    findEntry(lookup: DataStorageEntryLookup) {
      if (lookup.fileId) {
        return deps.indexManager.findByFileId(lookup.fileId);
      }
      if (lookup.at) {
        return deps.indexManager.findClosestByScope(lookup.scope, lookup.at);
      }
      return deps.indexManager.findLatestByScope(lookup.scope);
    },
    findByFileId(fileId: string) {
      return deps.indexManager.findByFileId(fileId);
    },
    findByDataPointId(dataPointId: string) {
      return deps.indexManager.findByDataPointId(dataPointId);
    },
    findUnsynced(options?: { limit?: number }) {
      return deps.indexManager.findUnsynced(options);
    },
    readEnvelope(scope: string, collectedAt: string) {
      return readDataFile(deps.hierarchyOptions, scope, collectedAt);
    },
    readEnvelopePreview(scope: string, collectedAt: string, { maxBytes }) {
      return readDataFilePreview(
        deps.hierarchyOptions,
        scope,
        collectedAt,
        maxBytes,
      );
    },
    readScopeBlocks(scope: string, collectedAt: string, options) {
      return readScopeBlocks(
        deps.hierarchyOptions,
        scope,
        collectedAt,
        options,
      );
    },
    hasScopeBlocks(scope: string, collectedAt: string) {
      return hasScopeBlocks(deps.hierarchyOptions, scope, collectedAt);
    },
    writeEnvelope(envelope: DataFileEnvelope) {
      return writeDataFile(deps.hierarchyOptions, envelope);
    },
    writeBlockManifest(scope, collectedAt, manifest, blocks) {
      return writeBlockManifest(
        deps.hierarchyOptions,
        scope,
        collectedAt,
        manifest,
        blocks,
      );
    },
    insertEntry(entry) {
      return deps.indexManager.insert(entry);
    },
    updateFileId(path: string, fileId: string) {
      return deps.indexManager.updateFileId(path, fileId);
    },
    findLatestVersionByScope(scope: string) {
      return deps.indexManager.findLatestVersionByScope(scope);
    },
    updateDataPointId(path: string, dataPointId: string) {
      return deps.indexManager.updateDataPointId(path, dataPointId);
    },
    updateEntryVersion(path: string, version: number) {
      return deps.indexManager.updateVersion(path, version);
    },
    async deleteScope(scope: string) {
      const deletedCount = deps.indexManager.deleteByScope(scope);
      await deleteAllForScope(deps.hierarchyOptions, scope);
      return deletedCount;
    },
    async deleteByFileId(fileId: string) {
      const entry = deps.indexManager.findByFileId(fileId);
      if (!entry) return false;
      // Delete the blob FIRST; only drop the index row once it's gone (deleteDataFile is
      // ENOENT-tolerant). If blob deletion fails for a real reason, the row is preserved so the next
      // sync retry re-attempts — rather than the row vanishing and the cursor advancing past an
      // orphaned local blob.
      await deleteDataFile(
        deps.hierarchyOptions,
        entry.scope,
        entry.collectedAt,
      );
      deps.indexManager.deleteByPath(entry.path);
      return true;
    },
    dropUnsyncedEntry(path: string) {
      // Index row only — the payload file is already gone (that is why the
      // caller is dropping it). No blob delete. Guarded to unsynced rows: if
      // the row raced to synced after selection, its metadata is preserved
      // and this returns false, so the caller surfaces the real error instead
      // of silently discarding registered data.
      return deps.indexManager.deleteUnsyncedByPath(path);
    },
  };
}
