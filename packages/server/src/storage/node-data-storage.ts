import { deleteAllForScope, readDataFile, writeDataFile } from "./hierarchy.js";
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
    findUnsynced(options?: { limit?: number }) {
      return deps.indexManager.findUnsynced(options);
    },
    readEnvelope(scope: string, collectedAt: string) {
      return readDataFile(deps.hierarchyOptions, scope, collectedAt);
    },
    writeEnvelope(envelope: DataFileEnvelope) {
      return writeDataFile(deps.hierarchyOptions, envelope);
    },
    insertEntry(entry) {
      return deps.indexManager.insert(entry);
    },
    updateFileId(path: string, fileId: string) {
      return deps.indexManager.updateFileId(path, fileId);
    },
    async deleteScope(scope: string) {
      const deletedCount = deps.indexManager.deleteByScope(scope);
      await deleteAllForScope(deps.hierarchyOptions, scope);
      return deletedCount;
    },
  };
}
