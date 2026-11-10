import { existsSync, statSync } from "node:fs";
import type Database from "better-sqlite3";
import type {
  ImportIntent,
  ImportReceipt,
  VersionCommit,
  VersionCommitResult,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import {
  buildDataFilePath,
  type HierarchyManagerOptions,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { withScopeLock } from "@opendatalabs/personal-server-ts-core/additions";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { IngestPersistedError } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  LegacyWriteRefusedError,
  type LegacyWriteHold,
  type LegacyWriteSeal,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  deleteDataFileSync,
  deleteFirstSeenLedgerSync,
  deleteScopeFilesSync,
  publishDataFile,
  PublishedDataFileError,
  snapshotScopeFiles,
} from "./hierarchy.js";
import { relative, resolve } from "node:path";
import type { VersionFence } from "@opendatalabs/personal-server-ts-core/ports";

interface OperationRow {
  authority: string;
  owner: string;
  scope: string;
  operation: string;
  body_sha256: string;
  state: "prepared" | "accepted" | "deleted" | "cancelled";
  collected_at: string;
  path: string;
  envelope_bytes: Buffer | null;
  metadata_json: string | null;
  receipt_json: string | null;
}

const keyWhere =
  "authority = @authority AND owner = @owner AND scope = @scope AND operation = @operation";

/**
 * Owner import operations: journaled legacy writes and their erasers.
 *
 * Seal map (see `LegacyWriteSeal`). A publication (`commitVersion`, and
 * `recover` when it finishes a prepared operation) installs a legacy file and
 * row, so it runs inside `seal.commit` and every primitive below it takes the
 * `hold`. The whole sealed region is one synchronous SQLite transaction with
 * no await in it, so the seal's lock is held only for that transaction.
 * An eraser is a pure removal: it runs inside `seal.remove`, or directly when
 * the caller is already inside `seal.commit` and passes its `hold`. The lock
 * is not re-entrant, so no function here seals inside another sealed region.
 * An eraser that must also finish other operations' publications does that as
 * its own sealed commit first, then removes, in sequence.
 *
 * Lock order is seal, then scope lock: the seal is the outermost lock, and an
 * eraser takes the scope's lock INSIDE its removal (or inside the caller's
 * hold). Nothing here takes the scope lock and then asks for the seal.
 */
export function createImportOperations(
  db: Database.Database,
  index: IndexManager,
  options: HierarchyManagerOptions,
  seal: LegacyWriteSeal,
) {
  const immediate = <T>(run: () => T): T => db.transaction(run).immediate();
  const lookup = db.prepare(
    `SELECT * FROM owner_import_operations WHERE ${keyWhere}`,
  );
  const key = (scope: string, intent: ImportIntent) => ({
    scope,
    authority: intent.authority,
    owner: intent.owner,
    operation: intent.operation,
  });
  const find = (
    scope: string,
    intent: ImportIntent,
  ): OperationRow | undefined =>
    lookup.get(key(scope, intent)) as OperationRow | undefined;

  function check(row: OperationRow | undefined, intent: ImportIntent): void {
    if (!row) return;
    if (row.body_sha256 !== intent.bodySha256) {
      throw new ProtocolError(
        409,
        "IMPORT_CONFLICT",
        "This import operation is bound to different JSON data",
      );
    }
    if (row.state === "deleted" || row.state === "cancelled") {
      throw new ProtocolError(
        410,
        "IMPORT_DELETED",
        "This import operation was deleted; use a new operation for an intentional re-add",
        row.receipt_json
          ? { importReceipt: JSON.parse(row.receipt_json) as ImportReceipt }
          : undefined,
      );
    }
  }

  /**
   * Finish interrupted work. Cleaning up a retired operation is a removal and
   * needs nothing; finishing a prepared one publishes a legacy file, so it
   * happens only for a caller that holds the seal (`hold`). Without a hold
   * prepared operations are left as they are, and so are those `spare` names.
   */
  function recover(
    hold: LegacyWriteHold | undefined,
    own?: ReturnType<typeof key>,
    replicaPath?: string,
    spare?: (row: OperationRow) => boolean,
  ): void {
    const rows = db
      .prepare(
        "SELECT * FROM owner_import_operations WHERE state = 'prepared' OR (state IN ('deleted', 'cancelled') AND metadata_json IS NOT NULL) ORDER BY rowid",
      )
      .all() as OperationRow[];
    for (const row of rows) {
      if (row.state === "prepared" && (!hold || spare?.(row))) continue;
      try {
        recoverRow(row, hold);
      } catch (error) {
        if (
          row.path === replicaPath ||
          (own &&
            row.scope === own.scope &&
            row.authority === own.authority &&
            row.owner === own.owner &&
            row.operation === own.operation)
        ) {
          throw error;
        }
      }
    }
  }

  function recoverRow(
    row: OperationRow,
    hold: LegacyWriteHold | undefined,
  ): void {
    if (row.state !== "prepared") {
      deleteDataFileSync(options, row.scope, row.collected_at, row.operation);
      index.deleteByPath(row.path);
      db.prepare(
        `UPDATE owner_import_operations SET envelope_bytes = NULL, metadata_json = NULL WHERE ${keyWhere}`,
      ).run(row);
      return;
    }
    if (!hold) return;
    const bytes = row.envelope_bytes!;
    const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
    const metadata = JSON.parse(
      row.metadata_json!,
    ) as VersionCommit["metadata"] & {
      sizeBytes?: number;
      afterTombstoneVersion?: number | null;
    };
    const written = publishDataFile(
      hold,
      options,
      envelope,
      bytes,
      row.operation,
    );
    let entry = index.findByPath(row.path);
    if (!entry) {
      const inserted = index.insertIfCurrent(hold, {
        fileId: null,
        schemaId: null,
        path: row.path,
        scope: row.scope,
        collectedAt: row.collected_at,
        sizeBytes: metadata.sizeBytes ?? written.sizeBytes,
        afterTombstoneVersion: metadata.afterTombstoneVersion ?? null,
      });
      if (!inserted.ok) {
        // The index closed this scope for writes (history unknown). Fail
        // closed like an ordinary write: drop the unacknowledged operation
        // so the caller can retry once the scope is repaired.
        deleteDataFileSync(options, row.scope, row.collected_at, row.operation);
        db.prepare(`DELETE FROM owner_import_operations WHERE ${keyWhere}`).run(
          row,
        );
        return;
      }
      entry = inserted.entry;
    }
    const receipt: ImportReceipt = {
      operation: row.operation,
      bodySha256: row.body_sha256,
      scope: row.scope,
      collectedAt: entry.collectedAt,
      acceptedAt: new Date().toISOString(),
    };
    db.prepare(
      `UPDATE owner_import_operations SET state = 'accepted', receipt_json = @receipt, envelope_bytes = NULL, metadata_json = NULL WHERE ${keyWhere}`,
    ).run({ ...row, receipt: JSON.stringify(receipt) });
  }

  function reserve(envelope: DataFileEnvelope): DataFileEnvelope {
    // Ordinary writes keep a scope's collectedAt strictly increasing (see
    // reserveIngestStamp); an import must not land behind the current head.
    const latest = Date.parse(
      index.findLatestByScope(envelope.scope)?.collectedAt ?? "",
    );
    let base = Math.floor(Date.parse(envelope.collectedAt) / 1000) * 1000;
    if (Number.isFinite(latest) && base <= latest) {
      base = (Math.floor(latest / 1000) + 1) * 1000;
    }
    for (let bump = 0; bump < 60; bump++) {
      const collectedAt = new Date(base + bump * 1000)
        .toISOString()
        .replace(/\.\d{3}Z$/, "Z");
      const path = buildDataFilePath(
        options.dataDir,
        envelope.scope,
        collectedAt,
      );
      if (existsSync(path) || index.findByPath(relative(options.dataDir, path)))
        continue;
      if (
        db
          .prepare("SELECT 1 FROM owner_import_operations WHERE path = ?")
          .get(relative(options.dataDir, path))
      )
        continue;
      return { ...envelope, collectedAt };
    }
    throw new ProtocolError(
      429,
      "INGEST_CAPACITY",
      "Too many writes to this scope; retry after a minute",
    );
  }

  async function commitVersion(
    command: VersionCommit,
  ): Promise<VersionCommitResult> {
    const intent = command.kind === "append" ? command.import : undefined;
    if (intent) {
      return seal.commit((hold) => {
        const admitted = immediate(() => {
          const prior = find(command.envelope.scope, intent);
          check(prior, intent);
          recover(hold, key(command.envelope.scope, intent));
          if (prior) return false;
          const envelope = reserve(command.envelope);
          const path = relative(
            options.dataDir,
            buildDataFilePath(
              options.dataDir,
              envelope.scope,
              envelope.collectedAt,
            ),
          );
          db.prepare(
            `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
          VALUES (@authority, @owner, @scope, @operation, @body_sha256, 'prepared', @collected_at, @path, @envelope_bytes, @metadata_json)`,
          ).run({
            ...key(envelope.scope, intent),
            body_sha256: intent.bodySha256,
            collected_at: envelope.collectedAt,
            path,
            envelope_bytes: Buffer.from(JSON.stringify(envelope, null, 2)),
            metadata_json: JSON.stringify(command.metadata),
          });
          return true;
        });
        const published = immediate((): VersionCommitResult | undefined => {
          recover(hold, key(command.envelope.scope, intent));
          const row = find(command.envelope.scope, intent);
          // recover() dropped the operation: the scope is closed for writes.
          // Report it after the drop commits; a throw here would roll it back.
          if (!row) return undefined;
          check(row, intent);
          const receipt = JSON.parse(row.receipt_json!) as ImportReceipt;
          if (!admitted) return { kind: "replay", receipt };
          const entry = index.findByPath(row.path)!;
          const envelope = {
            ...command.envelope,
            collectedAt: receipt.collectedAt,
          };
          return {
            kind: "stored",
            envelope,
            entry,
            receipt,
            writeResult: {
              path: buildDataFilePath(
                options.dataDir,
                envelope.scope,
                envelope.collectedAt,
              ),
              relativePath: row.path,
              sizeBytes: entry.sizeBytes,
            },
          };
        });
        if (!published) {
          throw new ProtocolError(
            409,
            "SCOPE_CLOSED_FOR_WRITES",
            "This scope is closed for writes until its index history is repaired",
          );
        }
        return published;
      });
    }
    let publishedPath: string | undefined;
    try {
      return await seal.commit((hold) =>
        immediate(() => {
          // A replica cannot reuse a path still owned by failed import cleanup.
          recover(
            hold,
            undefined,
            command.kind === "replica"
              ? relative(
                  options.dataDir,
                  buildDataFilePath(
                    options.dataDir,
                    command.envelope.scope,
                    command.envelope.collectedAt,
                  ),
                )
              : undefined,
          );
          const envelope =
            command.kind === "append"
              ? reserve(command.envelope)
              : command.envelope;
          const bytes = Buffer.from(JSON.stringify(envelope, null, 2));
          let writeResult;
          try {
            writeResult = publishDataFile(hold, options, envelope, bytes);
          } catch (err) {
            if (err instanceof PublishedDataFileError)
              publishedPath = err.relativePath;
            throw err;
          }
          publishedPath = writeResult.relativePath;
          let entry = index.findByPath(writeResult.relativePath);
          if (entry && command.kind === "replica") {
            index.updateDataPointId(entry.path, command.metadata.dataPointId);
            index.updateVersion(entry.path, command.metadata.version);
            entry = index.findByPath(entry.path)!;
          } else {
            entry = index.insert(hold, {
              fileId: null,
              path: writeResult.relativePath,
              scope: envelope.scope,
              collectedAt: envelope.collectedAt,
              sizeBytes:
                command.kind === "append"
                  ? (command.metadata.sizeBytes ?? writeResult.sizeBytes)
                  : writeResult.sizeBytes,
              ...(command.kind === "replica"
                ? command.metadata
                : {
                    afterTombstoneVersion:
                      command.metadata.afterTombstoneVersion ?? null,
                  }),
            });
          }
          return { kind: "stored" as const, envelope, entry, writeResult };
        }),
      );
    } catch (err) {
      if (command.kind === "append" && publishedPath) {
        throw new IngestPersistedError(publishedPath, err);
      }
      throw err;
    }
  }

  function retire(where: string, params: Record<string, unknown>): void {
    db.prepare(
      `UPDATE owner_import_operations SET state = CASE WHEN state = 'prepared' THEN 'cancelled' ELSE 'deleted' END, metadata_json = COALESCE(metadata_json, '{}') WHERE ${where} AND state IN ('prepared', 'accepted')`,
    ).run(params);
  }

  /**
   * A pure removal of one scope's data: under the seal's lock, or inside the
   * caller's own commit, and under that scope's lock taken inside the seal.
   */
  function removal<T>(
    hold: LegacyWriteHold | undefined,
    scope: string,
    work: () => T,
  ): Promise<T> {
    const locked = () => withScopeLock(scope, async () => work());
    return hold ? locked() : seal.remove(locked);
  }

  /**
   * Before an erase, finish the publications other operations are owed, as an
   * erase always did. That publishes legacy files, so it is a sealed commit of
   * its own, run before and apart from the removal (the lock is not
   * re-entrant): a removal never publishes. A caller that already holds the
   * seal publishes under its own hold. A refusal leaves those operations
   * prepared; the erase itself is never refused. The operations the erase
   * targets (`spare`) stay prepared: the erase retires them, so they are never
   * published, not even for the moment before the removal.
   */
  async function finishOwedPublications(
    hold: LegacyWriteHold | undefined,
    spare?: (row: OperationRow) => boolean,
  ): Promise<void> {
    if (hold) {
      immediate(() => recover(hold, undefined, undefined, spare));
      return;
    }
    const owed = db
      .prepare(
        "SELECT 1 FROM owner_import_operations WHERE state = 'prepared' LIMIT 1",
      )
      .get();
    if (!owed) return;
    try {
      await seal.commit((sealed) =>
        immediate(() => recover(sealed, undefined, undefined, spare)),
      );
    } catch (error) {
      if (!(error instanceof LegacyWriteRefusedError)) throw error;
    }
  }

  /**
   * Boot recovery of interrupted operations. A prepared operation was
   * acknowledged to a legacy client but not yet published, so finishing it is
   * a sealed publication. Unswitched: published. Switched: dropped, with any
   * file it left, so it cannot outlive the switch. Unknown: left prepared for
   * a later boot to decide. Cleaning up retired operations is a removal and
   * always runs.
   */
  async function recoverAtBoot(): Promise<void> {
    try {
      await seal.commit((hold) => immediate(() => recover(hold)));
    } catch (error) {
      if (!(error instanceof LegacyWriteRefusedError)) throw error;
      await seal.remove(() =>
        immediate(() => {
          if (error.verdict === "switched") dropPrepared();
          recover(undefined);
        }),
      );
    }
  }

  function dropPrepared(): void {
    const rows = db
      .prepare("SELECT * FROM owner_import_operations WHERE state = 'prepared'")
      .all() as OperationRow[];
    for (const row of rows) {
      deleteDataFileSync(options, row.scope, row.collected_at, row.operation);
      db.prepare(`DELETE FROM owner_import_operations WHERE ${keyWhere}`).run(
        row,
      );
    }
  }

  return {
    commitVersion,
    recoverAtBoot,
    async deleteScope(scope: string, hold?: LegacyWriteHold): Promise<number> {
      await finishOwedPublications(hold, (row) => row.scope === scope);
      return removal(hold, scope, () => {
        const snapshot = immediate(() => {
          deleteFirstSeenLedgerSync(options, scope);
          const files = snapshotScopeFiles(options, scope);
          const entries = db
            .prepare("SELECT id, path FROM data_files WHERE scope = ?")
            .all(scope) as { id: number; path: string }[];
          retire("scope = @scope", { scope });
          return { files, entries };
        });
        return immediate(() => {
          recover(undefined);
          // A replica can reuse a captured path between these transactions.
          const captured = new Set(snapshot.entries.map(({ id }) => id));
          const later = new Set(
            (
              db
                .prepare("SELECT id, path FROM data_files WHERE scope = ?")
                .all(scope) as { id: number; path: string }[]
            )
              .filter(({ id }) => !captured.has(id))
              .map(({ path }) => resolve(options.dataDir, path)),
          );
          deleteScopeFilesSync({
            ...snapshot.files,
            files: snapshot.files.files.filter((file) => !later.has(file)),
          });
          const remove = db.prepare(
            "DELETE FROM data_files WHERE id = @id AND path = @path",
          );
          for (const entry of snapshot.entries) remove.run(entry);
          if (index.countByScope(scope) === 0) {
            deleteFirstSeenLedgerSync(options, scope);
          }
          return snapshot.entries.length;
        });
      });
    },
    /**
     * Erases one version only while its row is still the one the caller
     * decided on (same local id and path). The check, the retirement of that
     * row's import operation and the erase run in one immediate transaction,
     * the same kind every owner import commits in, so a replacement row cannot
     * land between them. A row erased or replaced since is left alone.
     */
    async deleteFencedVersion(
      scope: string,
      collectedAt: string,
      fence: VersionFence,
      hold?: LegacyWriteHold,
    ): Promise<boolean> {
      await finishOwedPublications(hold);
      return removal(hold, scope, () =>
        immediate(() => {
          recover(undefined);
          const row = index.findByPath(fence.path);
          if (
            !row ||
            row.id !== fence.id ||
            row.scope !== scope ||
            row.collectedAt !== collectedAt
          ) {
            return false;
          }
          retire("path = @path", { path: fence.path });
          deleteDataFileSync(options, scope, collectedAt);
          index.deleteByPath(fence.path);
          return true;
        }),
      );
    },
    /**
     * Like `deleteFencedVersion`, and only while the envelope file is absent.
     * The file check runs in the same immediate transaction that a replica
     * write publishes in, so a restored file cannot be erased. Only ENOENT is
     * absence; any other fault throws and the row stays.
     */
    async deleteFencedVersionIfMissing(
      scope: string,
      collectedAt: string,
      fence: VersionFence,
      hold?: LegacyWriteHold,
    ): Promise<boolean> {
      await finishOwedPublications(hold);
      return removal(hold, scope, () =>
        immediate(() => {
          recover(undefined);
          const row = index.findByPath(fence.path);
          if (
            !row ||
            row.id !== fence.id ||
            row.scope !== scope ||
            row.collectedAt !== collectedAt
          ) {
            return false;
          }
          try {
            statSync(buildDataFilePath(options.dataDir, scope, collectedAt));
            return false;
          } catch (err) {
            if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
          }
          retire("path = @path", { path: fence.path });
          deleteDataFileSync(options, scope, collectedAt);
          index.deleteByPath(fence.path);
          return true;
        }),
      );
    },
    async deleteVersion(
      scope: string,
      collectedAt: string,
      indexedPath?: string,
      hold?: LegacyWriteHold,
    ): Promise<boolean> {
      await finishOwedPublications(
        hold,
        (row) => row.scope === scope && row.collected_at === collectedAt,
      );
      return removal(hold, scope, () => {
        immediate(() => {
          retire("scope = @scope AND collected_at = @collectedAt", {
            scope,
            collectedAt,
          });
        });
        return immediate(() => {
          const path =
            indexedPath ??
            relative(
              options.dataDir,
              buildDataFilePath(options.dataDir, scope, collectedAt),
            );
          const existed = index.findByPath(path) !== undefined;
          recover(undefined);
          deleteDataFileSync(options, scope, collectedAt);
          index.deleteByPath(path);
          return existed;
        });
      });
    },
    dropUnsyncedEntry(path: string, hold?: LegacyWriteHold): Promise<boolean> {
      const scope = index.findByPath(path)?.scope;
      if (scope === undefined) return Promise.resolve(false);
      return removal(hold, scope, () =>
        immediate(() => {
          if (index.findByPath(path)?.dataPointId !== null) return false;
          if (!index.deleteUnsyncedByPath(path)) return false;
          retire("path = @path", { path });
          return true;
        }),
      );
    },
  };
}
