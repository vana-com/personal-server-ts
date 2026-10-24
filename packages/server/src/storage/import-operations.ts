import {
  assertLegacyPublicationAllowed,
  assertLegacyHistoryMutable,
  holdLegacyPublication,
} from "./legacy-publication-fence.js";
import {
  hasPdppOrigin,
  isPdppProducer,
} from "@opendatalabs/personal-server-ts-core/sync";
import { existsSync } from "node:fs";
import { keccak256, stringToHex } from "viem";
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
  buildScopeDir,
  envelopeGeneration,
  type HierarchyManagerOptions,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { IngestPersistedError } from "@opendatalabs/personal-server-ts-core/contracts";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  deleteDataFileSync,
  deleteFirstSeenLedgerSync,
  deleteScopeFilesSync,
  publishDataFile,
  PublishedDataFileError,
  snapshotScopeFiles,
} from "./hierarchy.js";
import { join, relative, resolve } from "node:path";

function producerOf(envelope: DataFileEnvelope) {
  const producer = (envelope as { producer?: unknown }).producer;
  return isPdppProducer(producer) ? producer : null;
}

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
 * The replica fields a caller may set on an index row. Anything else in the
 * metadata, such as provenance or a generation, is never copied.
 */
function replicaMetadata(
  metadata: Extract<VersionCommit, { kind: "replica" }>["metadata"],
) {
  return {
    schemaId: metadata.schemaId,
    dataPointId: metadata.dataPointId,
    version: metadata.version,
    ...(metadata.producer === undefined ? {} : { producer: metadata.producer }),
    ...(metadata.producerProvenance === undefined
      ? {}
      : { producerProvenance: metadata.producerProvenance }),
  };
}

export function createImportOperations(
  db: Database.Database,
  index: IndexManager,
  options: HierarchyManagerOptions,
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

  function recover(): void {
    const rows = db
      .prepare(
        "SELECT * FROM owner_import_operations WHERE state = 'prepared' OR (state IN ('deleted', 'cancelled') AND metadata_json IS NOT NULL) ORDER BY rowid",
      )
      .all() as OperationRow[];
    for (const row of rows) {
      if (row.state !== "prepared") {
        if (!index.isHistoryOnly(row.scope, row.path)) {
          deleteDataFileSync(
            options,
            row.scope,
            row.collected_at,
            row.operation,
          );
          index.deleteByPath(row.path);
        }
        db.prepare(
          `UPDATE owner_import_operations SET envelope_bytes = NULL, metadata_json = NULL WHERE ${keyWhere}`,
        ).run(row);
        continue;
      }
      const bytes = row.envelope_bytes!;
      const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
      const metadata = JSON.parse(
        row.metadata_json!,
      ) as VersionCommit["metadata"] & {
        sizeBytes?: number;
        afterTombstoneVersion?: number | null;
      };
      try {
        assertLegacyPublicationAllowed(db, row.scope, {
          operation: row.operation,
          authority: row.authority,
          bodySha256: row.body_sha256,
        });
      } catch (error) {
        if (
          !(error instanceof ProtocolError) ||
          error.errorCode !== "legacy_scope_retired"
        )
          throw error;
        holdLegacyPublication(
          db,
          row.scope,
          "prepared-import",
          {
            operation: row.operation,
            authority: row.authority,
            owner: row.owner,
            path: row.path,
          },
          bytes,
        );
        continue;
      }
      const written = publishDataFile(options, envelope, bytes, row.operation);
      let entry = index.findByPath(row.path);
      if (!entry) {
        const inserted = index.insertIfCurrent({
          fileId: null,
          schemaId: null,
          path: row.path,
          pdppOrigin: hasPdppOrigin(envelope),
          generation: envelopeGeneration(envelope),
          producer: producerOf(envelope),
          scope: row.scope,
          collectedAt: row.collected_at,
          sizeBytes: metadata.sizeBytes ?? written.sizeBytes,
          afterTombstoneVersion: metadata.afterTombstoneVersion ?? null,
        });
        if (!inserted.ok) {
          // The index closed this scope for writes (history unknown). Fail
          // closed like an ordinary write: drop the unacknowledged operation
          // so the caller can retry once the scope is repaired.
          deleteDataFileSync(
            options,
            row.scope,
            row.collected_at,
            row.operation,
          );
          db.prepare(
            `DELETE FROM owner_import_operations WHERE ${keyWhere}`,
          ).run(row);
          continue;
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
      // Protect every restored version at acceptance, including a lost remote
      // acknowledgement or a later restoration of a newer canonical revision.
      db.prepare(
        `
        INSERT OR IGNORE INTO legacy_publication_retained_versions(version_id)
        SELECT @version_id WHERE EXISTS (
          SELECT 1 FROM legacy_publication_restore_authorization a
          JOIN legacy_publication_policy p ON p.scope=a.scope AND p.owner=a.owner
            AND p.server_generation=a.server_generation AND p.epoch=a.epoch
            AND p.state='restoring'
          WHERE a.scope=@scope AND a.owner=@owner AND a.operation=@operation
            AND a.authority=@authority AND a.body_sha256=@body_sha256
        )
      `,
      ).run({ ...row, version_id: entry.id });
      db.prepare(
        `INSERT OR IGNORE INTO legacy_publication_restore_versions
        SELECT @version_id, a.owner, a.server_generation, a.epoch, a.operation, @data_hash, 'current'
        FROM legacy_publication_restore_authorization a
        JOIN legacy_publication_policy p ON p.scope=a.scope AND p.owner=a.owner
          AND p.server_generation=a.server_generation AND p.epoch=a.epoch AND p.state='restoring'
        WHERE a.scope=@scope AND a.owner=@owner AND a.operation=@operation
          AND a.authority=@authority AND a.body_sha256=@body_sha256`,
      ).run({
        ...row,
        version_id: entry.id,
        data_hash: keccak256(stringToHex(JSON.stringify(envelope))),
      });
    }
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

  function commitVersionSync(command: VersionCommit): VersionCommitResult {
    const intent = command.kind === "append" ? command.import : undefined;
    if (intent) {
      const admitted = immediate(() => {
        const prior = find(command.envelope.scope, intent);
        check(prior, intent);
        recover();
        if (prior) return false;
        assertLegacyPublicationAllowed(db, command.envelope.scope, {
          operation: intent.operation,
          authority: intent.authority,
          bodySha256: intent.bodySha256,
        });
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
        recover();
        const row = find(command.envelope.scope, intent);
        // recover() dropped the operation: the scope is closed for writes.
        // Report it after the drop commits; a throw here would roll it back.
        if (!row) return undefined;
        check(row, intent);
        if (row.state !== "accepted")
          assertLegacyPublicationAllowed(db, row.scope);
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
    }
    let publishedPath: string | undefined;
    try {
      return immediate(() => {
        recover();
        const envelope =
          command.kind === "append"
            ? reserve(command.envelope)
            : command.envelope;
        const path = relative(
          options.dataDir,
          buildDataFilePath(
            options.dataDir,
            envelope.scope,
            envelope.collectedAt,
          ),
        );
        const known =
          command.kind === "replica" ? index.findByPath(path) : undefined;
        const repairingRetained =
          known?.generation === envelopeGeneration(envelope) &&
          command.kind === "replica" &&
          known.version === command.metadata.version &&
          known.dataPointId === command.metadata.dataPointId &&
          !!db
            .prepare(
              "SELECT 1 FROM legacy_publication_retained_versions WHERE version_id=?",
            )
            .get(known.id);
        if (!repairingRetained)
          assertLegacyPublicationAllowed(db, envelope.scope);
        const bytes = Buffer.from(JSON.stringify(envelope, null, 2));
        // Synchronous with the serialization above: these describe the bytes.
        const producer = producerOf(envelope);
        const identity = {
          pdppOrigin: hasPdppOrigin(envelope),
          generation: envelopeGeneration(envelope),
          ...(producer ? { producer } : {}),
        };
        let writeResult;
        try {
          writeResult = publishDataFile(options, envelope, bytes);
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
          entry = index.insert({
            fileId: null,
            path: writeResult.relativePath,
            scope: envelope.scope,
            collectedAt: envelope.collectedAt,
            sizeBytes:
              command.kind === "append"
                ? (command.metadata.sizeBytes ?? writeResult.sizeBytes)
                : writeResult.sizeBytes,
            ...(command.kind === "replica"
              ? replicaMetadata(command.metadata)
              : {
                  afterTombstoneVersion:
                    command.metadata.afterTombstoneVersion ?? null,
                }),
            // Storage's own values, from the bytes it serialized; last, so
            // nothing a caller passes can replace them.
            ...identity,
          });
        }
        return { kind: "stored", envelope, entry, writeResult };
      });
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

  immediate(recover);
  return {
    commitVersion: async (command: VersionCommit) => commitVersionSync(command),
    commitVersionSync,
    deleteScope(scope: string): number {
      return immediate(() => {
        assertLegacyHistoryMutable(db, scope);
        const history = index.findHistoryOnly(scope);
        const dataRoot = resolve(options.dataDir);
        const preservePaths = history.flatMap((entry) => [
          resolve(dataRoot, entry.path),
          join(
            buildScopeDir(join(dataRoot, "blocks"), scope),
            entry.collectedAt,
          ),
        ]);
        const files = snapshotScopeFiles(options, scope, preservePaths);
        const entries = db
          .prepare("SELECT id, path FROM data_files WHERE scope = ?")
          .all(scope) as { id: number; path: string }[];
        const retainedPaths = new Set(history.map((entry) => entry.path));
        const removableEntries = entries.filter(
          (entry) => !retainedPaths.has(entry.path),
        );
        if (history.length === 0) deleteFirstSeenLedgerSync(options, scope);
        retire("scope = @scope", { scope });
        recover();
        deleteScopeFilesSync(files);
        const remove = db.prepare(
          "DELETE FROM data_files WHERE id = @id AND path = @path",
        );
        for (const entry of removableEntries) remove.run(entry);
        if (index.countByScope(scope) === 0) {
          deleteFirstSeenLedgerSync(options, scope);
        }
        return removableEntries.length;
      });
    },
    deleteVersion(
      scope: string,
      collectedAt: string,
      indexedPath?: string,
    ): boolean {
      return immediate(() => {
        const path =
          indexedPath ??
          relative(
            options.dataDir,
            buildDataFilePath(options.dataDir, scope, collectedAt),
          );
        assertLegacyHistoryMutable(db, scope, index.findByPath(path)?.id);
        if (index.isHistoryOnly(scope, path)) return false;
        retire("scope = @scope AND collected_at = @collectedAt", {
          scope,
          collectedAt,
        });
        const existed = index.findByPath(path) !== undefined;
        recover();
        deleteDataFileSync(options, scope, collectedAt);
        index.deleteByPath(path);
        return existed;
      });
    },
    dropUnsyncedEntry(path: string): boolean {
      return immediate(() => {
        const entry = index.findByPath(path);
        if (!entry || entry.dataPointId !== null) return false;
        assertLegacyHistoryMutable(db, entry.scope, entry.id);
        if (index.isHistoryOnly(entry.scope, path)) return false;
        if (!index.deleteUnsyncedByPath(path)) return false;
        retire("path = @path", { path });
        return true;
      });
    },
  };
}
