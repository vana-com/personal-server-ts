import { existsSync } from "node:fs";
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
import { relative } from "node:path";

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

  /**
   * Finish interrupted work. A row that cannot finish stays as it is, so every
   * later call retries it, and it fails only the caller that owns it.
   */
  function recover(own?: ReturnType<typeof key>): void {
    const rows = db
      .prepare(
        "SELECT * FROM owner_import_operations WHERE state = 'prepared' OR (state IN ('deleted', 'cancelled') AND metadata_json IS NOT NULL) ORDER BY rowid",
      )
      .all() as OperationRow[];
    for (const row of rows) {
      try {
        recoverRow(row);
      } catch (err) {
        if (
          own &&
          row.scope === own.scope &&
          row.authority === own.authority &&
          row.owner === own.owner &&
          row.operation === own.operation
        )
          throw err;
      }
    }
  }

  function recoverRow(row: OperationRow): void {
    if (row.state !== "prepared") {
      deleteDataFileSync(options, row.scope, row.collected_at, row.operation);
      index.deleteByPath(row.path);
      db.prepare(
        `UPDATE owner_import_operations SET envelope_bytes = NULL, metadata_json = NULL WHERE ${keyWhere}`,
      ).run(row);
      return;
    }
    const bytes = row.envelope_bytes!;
    const envelope = JSON.parse(bytes.toString("utf8")) as DataFileEnvelope;
    const metadata = JSON.parse(
      row.metadata_json!,
    ) as VersionCommit["metadata"] & {
      sizeBytes?: number;
      afterTombstoneVersion?: number | null;
    };
    const written = publishDataFile(options, envelope, bytes, row.operation);
    const entry =
      index.findByPath(row.path) ??
      index.insert({
        fileId: null,
        schemaId: null,
        path: row.path,
        scope: row.scope,
        collectedAt: row.collected_at,
        sizeBytes: metadata.sizeBytes ?? written.sizeBytes,
        afterTombstoneVersion: metadata.afterTombstoneVersion ?? null,
      });
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
    const base = Math.floor(Date.parse(envelope.collectedAt) / 1000) * 1000;
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
      const admitted = immediate(() => {
        const prior = find(command.envelope.scope, intent);
        check(prior, intent);
        recover(key(command.envelope.scope, intent));
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
      return immediate(() => {
        recover(key(command.envelope.scope, intent));
        const row = find(command.envelope.scope, intent)!;
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
    }
    let publishedPath: string | undefined;
    try {
      return immediate(() => {
        recover();
        const envelope =
          command.kind === "append"
            ? reserve(command.envelope)
            : command.envelope;
        const bytes = Buffer.from(JSON.stringify(envelope, null, 2));
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
              ? command.metadata
              : {
                  afterTombstoneVersion:
                    command.metadata.afterTombstoneVersion ?? null,
                }),
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
    commitVersion,
    deleteScope(scope: string): number {
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
        recover();
        deleteScopeFilesSync(snapshot.files);
        const remove = db.prepare(
          "DELETE FROM data_files WHERE id = @id AND path = @path",
        );
        for (const entry of snapshot.entries) remove.run(entry);
        if (index.countByScope(scope) === 0) {
          deleteFirstSeenLedgerSync(options, scope);
        }
        return snapshot.entries.length;
      });
    },
    deleteVersion(
      scope: string,
      collectedAt: string,
      indexedPath?: string,
    ): boolean {
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
        recover();
        deleteDataFileSync(options, scope, collectedAt);
        index.deleteByPath(path);
        return existed;
      });
    },
    dropUnsyncedEntry(path: string): boolean {
      return immediate(() => {
        if (index.findByPath(path)?.dataPointId !== null) return false;
        if (!index.deleteUnsyncedByPath(path)) return false;
        retire("path = @path", { path });
        return true;
      });
    },
  };
}
