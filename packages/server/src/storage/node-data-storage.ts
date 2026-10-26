import {
  assertLegacyPublicationAllowed,
  assertLegacyHistoryMutable,
  assertRetainedVersionRepair,
  legacyPublicationFenced,
  legacyPublicationGateActive,
  holdLegacyPublication,
  exactVersionIdentity,
  isRetainedVersion,
  recordUnknownRetainedFiles,
} from "./legacy-publication-fence.js";
import {
  hasPdppOrigin,
  isPdppProducer,
} from "@opendatalabs/personal-server-ts-core/sync";
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
  assertPublishable,
  publishStagedDataFile,
  publishStagedDataFileSync,
  publishStageBytesSync,
  discardDataFile,
} from "./hierarchy.js";
import { readFileSync } from "node:fs";
import { readFile, readdir, stat } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { IngestPersistedError } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  buildDataFilePath,
  envelopeGeneration,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
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

/**
 * Publish a leftover stage for an indexed version whose final file is missing.
 * Off the gate this is the ordinary publication. Under the gate the stage
 * bytes are read, checked and linked in one writer transaction: only the
 * row's exact known identity publishes, for a retained version in any state
 * or an unretained one in an unfenced scope. Any other stage is held with its
 * bytes, left in place and not published. Returns false when not published.
 */
export async function publishIndexedStage(
  deps: NodeDataStorageDeps,
  stagePath: string,
  finalPath: string,
): Promise<boolean> {
  const db = indexDatabase(deps.indexManager);
  recordUnknownRetainedFiles(db, deps.hierarchyOptions);
  if (!db || !legacyPublicationGateActive(db)) {
    await publishStagedDataFile(stagePath, finalPath);
    return true;
  }
  const dataDir = deps.hierarchyOptions.dataDir;
  const relativePath = relative(dataDir, finalPath);
  return db
    .transaction((): boolean => {
      const entry = deps.indexManager.findByPath(relativePath);
      if (!entry) return false;
      const bytes = readFileSync(stagePath);
      let envelope: DataFileEnvelope | undefined;
      try {
        const parsed = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
        if (
          buildDataFilePath(dataDir, parsed.scope, parsed.collectedAt) ===
          finalPath
        )
          envelope = parsed;
      } catch {
        // Unreadable bytes have unknown identity.
      }
      if (
        exactVersionIdentity(entry, envelope) &&
        (isRetainedVersion(db, entry.id) ||
          !legacyPublicationFenced(db, entry.scope))
      ) {
        // Publish exactly the checked bytes, never the stage path again. A
        // file that appeared at the final path is not replaced; hold.
        if (publishStageBytesSync(stagePath, bytes, finalPath)) return true;
      }
      holdLegacyPublication(
        db,
        entry.scope,
        "recovery-stage",
        { path: relativePath, stage: basename(stagePath) },
        bytes,
      );
      return false;
    })
    .immediate();
}

/** Finish committed stages and discard stages that lost their index race. */
export async function recoverStagedDataFiles(
  deps: NodeDataStorageDeps,
): Promise<void> {
  recordUnknownRetainedFiles(
    indexDatabase(deps.indexManager),
    deps.hierarchyOptions,
  );
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
          await discardDataFile(path);
          continue;
        }
        // A leftover stage can share the final path of a prior committed
        // write after a restart. The existing final file wins: this stage
        // cannot be identified as the one that created the older index row.
        try {
          await stat(finalPath);
          await discardDataFile(path);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          await publishIndexedStage(deps, path, finalPath);
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
  recordUnknownRetainedFiles(
    indexDatabase(deps.indexManager),
    deps.hierarchyOptions,
  );
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
      const recoveryDb = indexDatabase(deps.indexManager);
      if (recoveryDb && legacyPublicationFenced(recoveryDb, envelope.scope)) {
        holdLegacyPublication(
          recoveryDb,
          envelope.scope,
          "recovery-orphan",
          { path: relativePath },
          await readFile(path),
        );
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
        producer: isPdppProducer(envelope.producer) ? envelope.producer : null,
        pdppOrigin: hasPdppOrigin(envelope),
        generation: envelopeGeneration(raw),
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
  recordUnknownRetainedFiles(db, deps.hierarchyOptions);
  /**
   * PDPP provenance and generation of the bytes at a version path, both from
   * one read, or undefined when they cannot be read. Read at insert, never on
   * a read path. Provenance only lets a read that will be refused fail before
   * payment; the generation is what a non-owner read pins, so it serves only
   * these bytes.
   */
  async function identityOfPublishedBytes(
    path: string,
  ): Promise<{ pdppOrigin?: boolean; generation?: string }> {
    try {
      const envelope = JSON.parse(
        await readFile(join(deps.hierarchyOptions.dataDir, path), "utf8"),
      ) as { data: unknown; producer?: unknown };
      return {
        pdppOrigin: hasPdppOrigin(envelope),
        generation: envelopeGeneration(envelope),
      };
    } catch {
      return {};
    }
  }
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
        // A fileId names one version of one scope; never another scope's row.
        const entry = deps.indexManager.findByFileId(lookup.fileId);
        return entry?.scope === lookup.scope ? entry : undefined;
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
    async writeEnvelope(envelope: DataFileEnvelope) {
      // Publication refuses different bytes at an existing file. An index row
      // whose file was lost still names its version: new bytes may restore
      // it only with the same provenance the row already records.
      const relativePath = relative(
        deps.hierarchyOptions.dataDir,
        buildDataFilePath(
          deps.hierarchyOptions.dataDir,
          envelope.scope,
          envelope.collectedAt,
        ),
      );
      const indexed = deps.indexManager.findByPath(relativePath);
      if (
        indexed?.pdppOrigin !== undefined &&
        indexed.pdppOrigin !== hasPdppOrigin(envelope)
      ) {
        return Promise.reject(
          new Error(
            `Stored envelope conflicts with publication at ${indexed.path}`,
          ),
        );
      }
      if (db && legacyPublicationGateActive(db)) {
        // A retained version is immutable in every state; refuse before
        // staging and again at the writer barrier.
        const admit = () => {
          if (
            !assertRetainedVersionRepair(
              db,
              deps.indexManager.findByPath(relativePath),
              envelope,
            )
          )
            assertLegacyPublicationAllowed(db, envelope.scope);
        };
        admit();
        const staged = await stageDataFile(deps.hierarchyOptions, envelope);
        try {
          return db
            .transaction(() => {
              admit();
              publishStagedDataFileSync(staged.stagePath, staged.finalPath);
              return {
                path: staged.finalPath,
                relativePath: staged.relativePath,
                sizeBytes: staged.sizeBytes,
              };
            })
            .immediate();
        } finally {
          await discardDataFile(staged.stagePath);
        }
      }
      return writeDataFile(deps.hierarchyOptions, envelope);
    },
    async commitEnvelope(envelope, entry, precondition) {
      const gated = !!db && legacyPublicationGateActive(db);
      const staged = await stageDataFile(deps.hierarchyOptions, envelope);
      let indexed = false;
      try {
        // Refuse a conflicting publication before the index commits: the row
        // and its revision would otherwise describe bytes that are not there.
        await assertPublishable(staged.stagePath, staged.finalPath);
        const commit = () => {
          if (gated) assertLegacyPublicationAllowed(db!, envelope.scope);
          const result = deps.indexManager.insertIfCurrent(
            {
              ...entry,
              ...staged.identity,
              path: staged.relativePath,
              sizeBytes: entry.sizeBytes ?? staged.sizeBytes,
            },
            precondition,
          );
          if (result.ok && gated)
            publishStagedDataFileSync(staged.stagePath, staged.finalPath);
          return result;
        };
        const result = gated ? db!.transaction(commit).immediate() : commit();
        if (!result.ok) {
          return result;
        }
        indexed = true;
        if (!gated)
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
        if (!indexed) await discardDataFile(staged.stagePath);
      }
    },
    writeBlockManifest(scope, collectedAt, manifest, blocks) {
      return writeBlockManifest(
        deps.hierarchyOptions,
        scope,
        collectedAt,
        manifest,
        blocks,
        db && legacyPublicationGateActive(db)
          ? (publish) =>
              db
                .transaction(() => {
                  assertLegacyPublicationAllowed(db, scope);
                  publish();
                })
                .immediate()
          : undefined,
      );
    },
    async insertEntry(entry) {
      // Storage derives provenance and generation from the bytes it
      // published; a caller's values are never trusted.
      const {
        pdppOrigin: _callerOrigin,
        generation: _callerGeneration,
        ...callerEntry
      } = entry;
      return deps.indexManager.insert({
        ...callerEntry,
        ...(await identityOfPublishedBytes(entry.path)),
      });
    },
    async backfillGeneration(entry) {
      if (entry.generation) return entry.generation;
      if (
        db &&
        db
          .prepare(
            "SELECT 1 FROM legacy_publication_retained_versions WHERE version_id=?",
          )
          .get(entry.id)
      ) {
        // Retained identities cannot be changed or rolled back. Verify both reads
        // before the one-time fill, inside the writer transaction, with no await.
        return db
          .transaction(() => {
            const current = deps.indexManager.findByPath(entry.path);
            if (!current || current.id !== entry.id) return undefined;
            if (current.generation) return current.generation;
            const path = join(deps.hierarchyOptions.dataDir, entry.path);
            let generation: string;
            try {
              const first = readFileSync(path);
              const envelope = JSON.parse(
                first.toString("utf8"),
              ) as DataFileEnvelope;
              if (
                envelope.scope !== current.scope ||
                envelope.collectedAt !== current.collectedAt ||
                !first.equals(readFileSync(path))
              )
                return undefined;
              generation = envelopeGeneration(envelope);
            } catch {
              // Preserve the ordinary lazy-read refusal when bytes are missing
              // or invalid; never assign a retained identity from uncertainty.
              return undefined;
            }
            db.prepare(
              "INSERT INTO legacy_publication_generation_backfill VALUES (?, ?)",
            ).run(entry.id, generation);
            try {
              return deps.indexManager.swapGeneration(
                entry.id,
                null,
                generation,
              )
                ? generation
                : undefined;
            } finally {
              db.prepare(
                "DELETE FROM legacy_publication_generation_backfill WHERE version_id=?",
              ).run(entry.id);
            }
          })
          .immediate();
      }
      const first = (await identityOfPublishedBytes(entry.path)).generation;
      if (!first) return undefined;
      if (!deps.indexManager.swapGeneration(entry.id, null, first)) {
        const current = deps.indexManager.findByPath(entry.path);
        return current?.id === entry.id ? current.generation : undefined;
      }
      // The bytes are read again: a version replaced between the two reads
      // is not recorded.
      const second = (await identityOfPublishedBytes(entry.path)).generation;
      if (second !== first) {
        deps.indexManager.swapGeneration(entry.id, first, null);
        return undefined;
      }
      return first;
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
        if (db) assertLegacyHistoryMutable(db, scope);
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
    async deleteVersion(scope: string, collectedAt: string) {
      const entry = deps.indexManager.findClosestByScope(scope, collectedAt);
      if (operations) {
        return withScopeLock(scope, async () => {
          const removed = operations.deleteVersion(
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
