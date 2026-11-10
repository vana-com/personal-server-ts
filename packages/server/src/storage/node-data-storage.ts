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
import {
  LegacyWriteRefusedError,
  type LegacyWriteHold,
  type LegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";

export interface NodeDataStorageDeps {
  indexManager: IndexManager;
  hierarchyOptions: HierarchyManagerOptions;
  /**
   * The one seal every legacy file and row of this storage becomes durable
   * through. Required: a storage built without one does not compile.
   */
  legacyWriteSeal: LegacyWriteSeal;
}

/**
 * Finish committed stages and discard stages that lost their index race.
 *
 * A stage whose row is already indexed is a legacy write that was acknowledged
 * before the crash. Finishing it publishes a legacy file, so it is a sealed
 * commit like any other publication: an unswitched account publishes it; a
 * switched one drops the stage and its row (the account's legacy files go
 * after the switch, and this one must not outlive it); an unknown mode leaves
 * both in place, because the answer is not known yet and a later boot decides.
 * Removing a stage that lost its race is a removal, not a write.
 */
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
        const relativeFinal = relative(
          deps.hierarchyOptions.dataDir,
          finalPath,
        );
        const indexed = deps.indexManager.findByPath(relativeFinal);
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
          try {
            await deps.legacyWriteSeal.commit((hold) =>
              publishStagedDataFile(hold, path, finalPath),
            );
          } catch (refused) {
            if (!(refused instanceof LegacyWriteRefusedError)) throw refused;
            if (refused.verdict === "switched") {
              await deps.legacyWriteSeal.remove(async () => {
                await unlink(path);
                deps.indexManager.deleteByPath(relativeFinal);
              });
            }
            // unknown: leave the stage and its row for a later boot.
          }
        }
      }
    }
  };
  await visit(deps.hierarchyOptions.dataDir);
}

/**
 * Boot recovery of interrupted owner import operations (the journal behind
 * `commitVersion`). A prepared operation was acknowledged to a legacy client
 * and not yet published: an unswitched account publishes it, a switched one
 * drops it, an unknown mode leaves it for a later boot. A storage whose index
 * has no journal has nothing to recover.
 */
export async function recoverImportOperations(
  deps: NodeDataStorageDeps,
): Promise<void> {
  const db = indexDatabase(deps.indexManager);
  if (!db) return;
  await createImportOperations(
    db,
    deps.indexManager,
    deps.hierarchyOptions,
    deps.legacyWriteSeal,
  ).recoverAtBoot();
}

/**
 * Rebuild a lost legacy index from finalized envelopes, never from stages.
 *
 * Re-creating a row makes a legacy version visible again, so each row is a
 * sealed commit. A file the seal refuses (switched or unknown) stays on disk,
 * unindexed, and is not counted.
 */
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
      try {
        await deps.legacyWriteSeal.commit((hold) => {
          deps.indexManager.insertRecovered(hold, {
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
        });
      } catch (error) {
        if (error instanceof LegacyWriteRefusedError) continue;
        throw error;
      }
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
  const seal = deps.legacyWriteSeal;
  const operations = db
    ? createImportOperations(db, deps.indexManager, deps.hierarchyOptions, seal)
    : undefined;
  // Where the seal is taken. Rule 1: only the outermost storage method seals,
  // and its inner helpers take the `hold`. Rule 2, the lock order: the seal is
  // the OUTERMOST lock, then the scope lock, then anything finer. A scope lock
  // is taken inside `seal.commit` / `seal.remove` (or inside the caller's
  // hold), never around them: a writer that held a scope lock and then waited
  // for the seal could deadlock behind a queued On, which waits for a delete
  // that holds the seal and needs that scope lock. Nothing that holds a scope
  // lock calls into the seal.
  //
  // - A write seals with `seal.commit` and hands `hold` down.
  // - A pure removal runs under `seal.remove` (every mode admits it), or
  //   directly when the caller passes its `hold` because it is already inside
  //   `seal.commit`. Either way the removal takes the scope's lock itself.
  // - Metadata updates that add no visible version (updateFileId,
  //   updateDataPointId, updateEntryVersion) and sidecars (block manifests,
  //   first-seen ledgers) are not sealed: nothing new becomes readable.
  const removal = <T>(
    hold: LegacyWriteHold | undefined,
    work: () => T | Promise<T>,
  ): Promise<T> => (hold ? Promise.resolve(work()) : seal.remove(work));
  /** A pure removal under the scope's lock, taken inside the seal. */
  const removalUnderScopeLock = <T>(
    hold: LegacyWriteHold | undefined,
    scope: string,
    work: () => Promise<T>,
  ): Promise<T> => removal(hold, () => withScopeLock(scope, work));
  /** The sidecar goes with the scope's last version, under the scope's lock. */
  const dropLedgerUnderScopeLock = (scope: string): Promise<void> =>
    withScopeLock(scope, () => dropLedgerIfEmpty(scope));
  async function dropLedgerIfEmpty(scope: string): Promise<void> {
    if (deps.indexManager.countByScope(scope) === 0) {
      await deleteFirstSeenLedger(deps.hierarchyOptions, scope);
    }
  }

  return {
    legacyWriteSeal: seal,
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
    findUnsyncedPage(options: { afterId: number; limit: number }) {
      return deps.indexManager.findUnsyncedPage(options);
    },
    maxUnsyncedId() {
      return deps.indexManager.maxUnsyncedId();
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
    // Stage outside the seal; only the publication is sealed, so the lock is
    // held for the rename, not for the bytes. A refusal leaves the stage
    // behind, which is removed: a refused write leaves nothing.
    async writeEnvelope(envelope: DataFileEnvelope) {
      const staged = await stageDataFile(deps.hierarchyOptions, envelope);
      try {
        await seal.commit((hold) =>
          publishStagedDataFile(hold, staged.stagePath, staged.finalPath),
        );
      } catch (error) {
        await unlink(staged.stagePath).catch(() => undefined);
        throw error;
      }
      return {
        path: staged.finalPath,
        relativePath: staged.relativePath,
        sizeBytes: staged.sizeBytes,
      };
    },
    // The file is durable at its final path before its row exists, and the
    // scope lock (taken inside the seal) keeps every erase of the scope, all
    // of which take it, from running between the two. The stage, the publish
    // and the row are one sealed commit, so a refused write stages nothing.
    async writeEnvelopeAndIndex(envelope, entry) {
      let staged: Awaited<ReturnType<typeof stageDataFile>> | undefined;
      try {
        return await seal.commit((hold) =>
          withScopeLock(envelope.scope, async () => {
            staged = await stageDataFile(deps.hierarchyOptions, envelope);
            await publishStagedDataFile(
              hold,
              staged.stagePath,
              staged.finalPath,
            );
            try {
              return deps.indexManager.insert(hold, {
                ...entry,
                path: staged.relativePath,
                sizeBytes: entry.sizeBytes ?? staged.sizeBytes,
              });
            } catch (err) {
              throw new IngestPersistedError(staged.relativePath, err);
            }
          }),
        );
      } catch (error) {
        // Removing a stage that was already renamed away is a no-op.
        if (staged) await unlink(staged.stagePath).catch(() => undefined);
        throw error;
      }
    },
    async commitEnvelope(envelope, entry, precondition) {
      const staged = await stageDataFile(deps.hierarchyOptions, envelope);
      let indexed = false;
      try {
        return await seal.commit(async (hold) => {
          const result = deps.indexManager.insertIfCurrent(
            hold,
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
          try {
            await publishStagedDataFile(
              hold,
              staged.stagePath,
              staged.finalPath,
            );
          } catch (err) {
            throw new IngestPersistedError(staged.relativePath, err);
          }
          return {
            ok: true as const,
            writeResult: {
              path: staged.finalPath,
              relativePath: staged.relativePath,
              sizeBytes: staged.sizeBytes,
            },
          };
        });
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
      return seal.commit((hold) => deps.indexManager.insert(hold, entry));
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
    // Deletions are pure removals: admitted in every mode, sealed so an On
    // latch waits for them. Each takes the scope's lock inside the seal (so a
    // first-seen rebuild in flight cannot write the sidecar back), and the
    // sidecar goes with the scope's last version, so no delete path can leave a
    // stale ledger behind. The import operations seal their own removals.
    deleteScope(scope: string, hold?: LegacyWriteHold) {
      if (operations) return operations.deleteScope(scope, hold);
      return removalUnderScopeLock(hold, scope, async () => {
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
    async deleteByFileId(fileId: string, hold?: LegacyWriteHold) {
      const entry = deps.indexManager.findByFileId(fileId);
      if (!entry) return false;
      if (operations) {
        const removed = await operations.deleteVersion(
          entry.scope,
          entry.collectedAt,
          entry.path,
          hold,
        );
        await dropLedgerUnderScopeLock(entry.scope);
        return removed;
      }
      // Delete the blob FIRST; only drop the index row once it's gone (deleteDataFile is
      // ENOENT-tolerant). If blob deletion fails for a real reason, the row is preserved so the next
      // sync retry re-attempts — rather than the row vanishing and the cursor advancing past an
      // orphaned local blob.
      return removalUnderScopeLock(hold, entry.scope, async () => {
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
      hold?: LegacyWriteHold,
    ) {
      const entry = deps.indexManager.findClosestByScope(scope, collectedAt);
      if (operations) {
        const removed = fence
          ? await operations.deleteFencedVersion(
              scope,
              collectedAt,
              fence,
              hold,
            )
          : await operations.deleteVersion(
              scope,
              collectedAt,
              entry?.collectedAt === collectedAt ? entry.path : undefined,
              hold,
            );
        await dropLedgerUnderScopeLock(scope);
        return removed;
      }
      if (!entry || entry.collectedAt !== collectedAt) return false;
      return removalUnderScopeLock(hold, scope, async () => {
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
    async deleteVersionIfEnvelopeMissing(
      scope: string,
      collectedAt: string,
      fence: VersionFence,
      hold?: LegacyWriteHold,
    ) {
      if (operations) {
        const removed = await operations.deleteFencedVersionIfMissing(
          scope,
          collectedAt,
          fence,
          hold,
        );
        await dropLedgerUnderScopeLock(scope);
        return removed;
      }
      return removalUnderScopeLock(hold, scope, async () => {
        const current = deps.indexManager.findByPath(fence.path);
        if (
          !current ||
          current.id !== fence.id ||
          current.scope !== scope ||
          current.collectedAt !== collectedAt
        ) {
          return false;
        }
        try {
          await stat(
            buildDataFilePath(
              deps.hierarchyOptions.dataDir,
              scope,
              collectedAt,
            ),
          );
          return false;
        } catch (err) {
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
        }
        await deleteDataFile(deps.hierarchyOptions, scope, collectedAt);
        deps.indexManager.deleteByPath(fence.path);
        await dropLedgerIfEmpty(scope);
        return true;
      });
    },
    async dropUnsyncedEntry(path: string, hold?: LegacyWriteHold) {
      // Index row only — the payload file is already gone (that is why the
      // caller is dropping it). No blob delete. Guarded to unsynced rows: if
      // the row raced to synced after selection, its metadata is preserved
      // and this returns false, so the caller surfaces the real error instead
      // of silently discarding registered data.
      const entry = deps.indexManager.findByPath(path);
      if (!entry) return false;
      const removed = operations
        ? await operations.dropUnsyncedEntry(path, hold)
        : await removalUnderScopeLock(hold, entry.scope, async () =>
            deps.indexManager.deleteUnsyncedByPath(path),
          );
      if (removed) await dropLedgerUnderScopeLock(entry.scope);
      return removed;
    },
  };
}
