import {
  deleteAllForScope,
  deleteDataFile,
  deleteFirstSeenLedger,
  readFirstSeenLedger,
  writeFirstSeenLedger,
  readDataFile,
  readDataFileBytes,
  readDataFileStream,
  readDataFilePreview,
  hasScopeBlocks,
  readScopeBlockManifest,
  readScopeBlocks,
  writeBlockManifest,
  writeDataFile,
  stageDataFile,
  publishStagedDataFile,
} from "./hierarchy.js";
import type { VersionFence } from "@opendatalabs/personal-server-ts-core/ports";
import { readFile, readdir, stat, unlink } from "node:fs/promises";
import { join, relative } from "node:path";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { IngestPersistedError } from "@opendatalabs/personal-server-ts-core/contracts";
import { buildDataFilePath } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type {
  DataStorageEntryLookup,
  DataStorageListOptions,
  DataStoragePort,
  DataStorageScopeListOptions,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import { indexDatabase } from "./index-manager.js";
import { createImportOperations } from "./import-operations.js";

export interface NodeDataStorageDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
}

/** Finish committed stages and discard stages that lost their index race. */
export async function recoverStagedDataFiles(
  deps: NodeDataStorageDeps,
): Promise<void> {
  const visit = async (dir: string): Promise<void> => {
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, item.name);
      if (item.isDirectory()) {
        await visit(path);
      } else if (item.isFile()) {
        const marker = item.name.indexOf(".json.pending.");
        if (marker < 0) continue;
        const finalPath = join(
          dir,
          item.name.slice(0, marker + ".json".length),
        );
        const indexed = deps.indexManager.findByPath(
          relative(deps.hierarchyOptions.dataDir, finalPath),
        );
        if (!indexed) {
          await unlink(path);
          continue;
        }
        // A leftover stage can share the final path of a prior committed
        // write after a restart. The existing final file wins: this stage
        // cannot be identified as the one that created the older index row.
        try {
          await stat(finalPath);
          await unlink(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          await publishStagedDataFile(path, finalPath);
        }
      }
    }
  };
  await visit(deps.hierarchyOptions.dataDir);
}

/** Rebuild a lost legacy index from finalized envelopes, never from stages. */
export async function reindexLegacyDataFiles(
  deps: NodeDataStorageDeps & {
    closeRecoveredScopeForWrites?: (
      scope: string,
    ) => boolean | Promise<boolean>;
  },
): Promise<number> {
  const dataDir = deps.hierarchyOptions.dataDir;
  let recovered = 0;
  const recoveredScopes = new Set<string>();
  const visit = async (dir: string): Promise<void> => {
    for (const item of (await readdir(dir, { withFileTypes: true })).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      if (dir === dataDir && item.name === "blocks") continue;
      const path = join(dir, item.name);
      if (item.isDirectory()) {
        await visit(path);
        continue;
      }
      if (!item.isFile() || !item.name.endsWith(".json")) continue;
      const relativePath = relative(dataDir, path);
      if (deps.indexManager.findByPath(relativePath)) continue;
      let raw: unknown;
      try {
        raw = JSON.parse(await readFile(path, "utf8"));
      } catch {
        continue;
      }
      const parsed = DataFileEnvelopeSchema.passthrough().safeParse(raw);
      if (!parsed.success) continue;
      const envelope = parsed.data;
      if (
        buildDataFilePath(dataDir, envelope.scope, envelope.collectedAt) !==
        path
      ) {
        continue;
      }
      const bytes = (await stat(path)).size;
      const closeAfterInsert = await deps.closeRecoveredScopeForWrites?.(
        envelope.scope,
      );
      deps.indexManager.insertRecovered({
        fileId: null,
        schemaId: envelope.schemaId ?? null,
        path: relativePath,
        scope: envelope.scope,
        collectedAt: envelope.collectedAt,
        sizeBytes: bytes,
        producer:
          envelope.producer === "pdpp-projector" ||
          envelope.producer === "pdpp-import-projection"
            ? envelope.producer
            : null,
        producerProvenance:
          envelope.producer_provenance &&
          typeof envelope.producer_provenance === "object"
            ? JSON.stringify(envelope.producer_provenance)
            : null,
      });
      if (closeAfterInsert && !recoveredScopes.has(envelope.scope)) {
        deps.indexManager.closeScopeForWrites(envelope.scope);
        recoveredScopes.add(envelope.scope);
      }
      recovered++;
    }
  };
  await visit(dataDir);
  return recovered;
}

export function createNodeDataStorage(
  deps: NodeDataStorageDeps,
): DataStoragePort {
  const db = indexDatabase(deps.indexManager);
  const operations = db
    ? createImportOperations(db, deps.indexManager, deps.hierarchyOptions)
    : undefined;
  async function dropLedgerIfEmpty(scope: string): Promise<void> {
    if (deps.indexManager.countByScope(scope) === 0) {
      await deleteFirstSeenLedger(deps.hierarchyOptions, scope);
    }
  }

  return {
    kind: "node-fs-sqlite",
    ...(operations ? { commitVersion: operations.commitVersion } : {}),
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
    readEnvelopeBytes(scope: string, collectedAt: string) {
      return readDataFileBytes(deps.hierarchyOptions, scope, collectedAt);
    },
    async readEnvelopeStream(scope: string, collectedAt: string) {
      return readDataFileStream(deps.hierarchyOptions, scope, collectedAt);
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
    readBlockManifest(scope: string, collectedAt: string) {
      return readScopeBlockManifest(deps.hierarchyOptions, scope, collectedAt);
    },
    writeEnvelope(envelope: DataFileEnvelope) {
      return writeDataFile(deps.hierarchyOptions, envelope);
    },
    // The file is durable at its final path before its row exists, and the
    // scope lock keeps every erase of the scope (all of which take it) from
    // running between the two.
    writeEnvelopeAndIndex(envelope, entry) {
      return withScopeLock(envelope.scope, async () => {
        const written = await writeDataFile(deps.hierarchyOptions, envelope);
        try {
          return deps.indexManager.insert({
            ...entry,
            path: written.relativePath,
            sizeBytes: entry.sizeBytes ?? written.sizeBytes,
          });
        } catch (err) {
          throw new IngestPersistedError(written.relativePath, err);
        }
      });
    },
    async commitEnvelope(envelope, entry, precondition) {
      const staged = await stageDataFile(deps.hierarchyOptions, envelope);
      let indexed = false;
      try {
        const result = deps.indexManager.insertIfCurrent(
          {
            ...entry,
            path: staged.relativePath,
            sizeBytes: entry.sizeBytes ?? staged.sizeBytes,
          },
          precondition,
        );
        if (!result.ok) {
          return result;
        }
        indexed = true;
        await publishStagedDataFile(staged.stagePath, staged.finalPath);
        return {
          ok: true as const,
          writeResult: {
            path: staged.finalPath,
            relativePath: staged.relativePath,
            sizeBytes: staged.sizeBytes,
          },
        };
      } catch (err) {
        if (indexed) throw new IngestPersistedError(staged.relativePath, err);
        throw err;
      } finally {
        // An indexed stage must survive a failed rename for boot recovery.
        if (!indexed) await unlink(staged.stagePath);
      }
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
    updateDataPointId(path: string, dataPointId: string | null) {
      return deps.indexManager.updateDataPointId(path, dataPointId);
    },
    updateEntryVersion(path: string, version: number) {
      return deps.indexManager.updateVersion(path, version);
    },
    readFirstSeenLedger(scope: string) {
      return readFirstSeenLedger(deps.hierarchyOptions, scope);
    },
    writeFirstSeenLedger(scope: string, ledger: unknown) {
      return writeFirstSeenLedger(deps.hierarchyOptions, scope, ledger);
    },
    deleteFirstSeenLedger(scope: string) {
      return deleteFirstSeenLedger(deps.hierarchyOptions, scope);
    },
    // Deletions run under the scope's first-seen sidecar lock (so a rebuild in
    // flight cannot write it back), and the sidecar goes with the scope's last
    // version, so no delete path can leave a stale ledger behind.
    deleteScope(scope: string) {
      return withScopeLock(scope, async () => {
        if (operations) return operations.deleteScope(scope);
        // The sidecar first: it holds record ids, so it must not survive a
        // data delete that fails half way. A sidecar that cannot be removed
        // never blocks the data delete; it is tried once more afterwards, and
        // a leftover is harmless (the next write or read finds its newest
        // version gone and drops it).
        const sidecarGone = await deleteFirstSeenLedger(
          deps.hierarchyOptions,
          scope,
        ).then(
          () => true,
          () => false,
        );
        const deletedCount = deps.indexManager.deleteByScope(scope);
        await deleteAllForScope(deps.hierarchyOptions, scope);
        if (!sidecarGone) {
          await deleteFirstSeenLedger(deps.hierarchyOptions, scope).catch(
            () => undefined,
          );
        }
        return deletedCount;
      });
    },
    async deleteByFileId(fileId: string) {
      const entry = deps.indexManager.findByFileId(fileId);
      if (!entry) return false;
      return withScopeLock(entry.scope, async () => {
        if (operations) {
          const removed = operations.deleteVersion(
            entry.scope,
            entry.collectedAt,
            entry.path,
          );
          await dropLedgerIfEmpty(entry.scope);
          return removed;
        }
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
        await dropLedgerIfEmpty(entry.scope);
        return true;
      });
    },
    async deleteVersion(
      scope: string,
      collectedAt: string,
      fence?: VersionFence,
    ) {
      const entry = deps.indexManager.findClosestByScope(scope, collectedAt);
      if (operations) {
        return withScopeLock(scope, async () => {
          const removed = fence
            ? operations.deleteFencedVersion(scope, collectedAt, fence)
            : operations.deleteVersion(
                scope,
                collectedAt,
                entry?.collectedAt === collectedAt ? entry.path : undefined,
              );
          await dropLedgerIfEmpty(scope);
          return removed;
        });
      }
      if (!entry || entry.collectedAt !== collectedAt) return false;
      return withScopeLock(scope, async () => {
        if (fence) {
          const current = deps.indexManager.findByPath(entry.path);
          if (entry.path !== fence.path || current?.id !== fence.id) {
            return false;
          }
        }
        // Same ordering as deleteByFileId: blob first (ENOENT-tolerant), then
        // the index row, so a real blob failure keeps the row for a retry.
        await deleteDataFile(deps.hierarchyOptions, scope, collectedAt);
        deps.indexManager.deleteByPath(entry.path);
        await dropLedgerIfEmpty(scope);
        return true;
      });
    },
    async dropUnsyncedEntry(path: string) {
      // Index row only — the payload file is already gone (that is why the
      // caller is dropping it). No blob delete. Guarded to unsynced rows: if
      // the row raced to synced after selection, its metadata is preserved
      // and this returns false, so the caller surfaces the real error instead
      // of silently discarding registered data.
      const entry = deps.indexManager.findByPath(path);
      const removed = operations
        ? operations.dropUnsyncedEntry(path)
        : deps.indexManager.deleteUnsyncedByPath(path);
      if (removed && entry) {
        await withScopeLock(entry.scope, () => dropLedgerIfEmpty(entry.scope));
      }
      return removed;
    },
  };
}
