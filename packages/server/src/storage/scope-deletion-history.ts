import {
  assertScopeStreamsBound,
  UnboundScopeStreamsError,
} from "./scope-deletion-bindings.js";
import { exclusiveScopeStreams } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { Database } from "better-sqlite3";
import type {
  ScopeDeletionHistory,
  ScopeTombstone,
} from "@opendatalabs/personal-server-ts-core/sync";

/**
 * Gateway deletion observations survive file registration and restart.
 * A marker authorizes canonical reads only after the matching erase commits.
 */
export function createScopeDeletionHistory(
  db: Database,
  ownerAddress: string,
  records?:
    | {
        readonly database: Database;
        recordScopeDeletion(
          scope: string,
          writeHistory: () => boolean,
          markApplied: () => void,
        ): void;
      }
    | (() =>
        | {
            readonly database: Database;
            recordScopeDeletion(
              scope: string,
              writeHistory: () => boolean,
              markApplied: () => void,
            ): void;
          }
        | undefined),
  options: {
    replicationEnabled?: boolean;
    logger?: { error(fields: Record<string, unknown>, message: string): void };
  } = {},
): ScopeDeletionHistory {
  if (records && typeof records !== "function" && records.database !== db)
    throw new Error(
      "History and record store must share the same SQLite connection",
    );
  db.exec(`
    CREATE TABLE IF NOT EXISTS vana_scope_deletion_history (
      owner_address TEXT NOT NULL,
      scope TEXT NOT NULL,
      deleted_at TEXT NOT NULL,
      tombstone_version TEXT,
      PRIMARY KEY (owner_address, scope)
    );
  `);
  const columns = db.pragma("table_info(vana_scope_deletion_history)") as {
    name: string;
  }[];
  if (!columns.some((column) => column.name === "erase_applied")) {
    db.exec(
      "ALTER TABLE vana_scope_deletion_history ADD COLUMN erase_applied INTEGER NOT NULL DEFAULT 0",
    );
  }
  if (!columns.some((column) => column.name === "erase_applied_version")) {
    db.exec(
      "ALTER TABLE vana_scope_deletion_history ADD COLUMN erase_applied_version TEXT",
    );
  }
  const owner = ownerAddress.toLowerCase();
  // A previously applied local erase does not prove replicated copies are gone.
  // Re-enable the read gate before replication can import or serve records.
  if (options.replicationEnabled) {
    db.prepare(
      "UPDATE vana_scope_deletion_history SET erase_applied = 0 WHERE owner_address = ? AND erase_applied = 1",
    ).run(owner);
  }
  const remember = db.prepare(`
    INSERT INTO vana_scope_deletion_history
      (owner_address, scope, deleted_at, tombstone_version)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (owner_address, scope) DO UPDATE SET
      deleted_at = excluded.deleted_at,
      tombstone_version = excluded.tombstone_version,
      erase_applied = 0, erase_applied_version = NULL
  `);
  const get = db.prepare(`
    SELECT deleted_at, tombstone_version, erase_applied, erase_applied_version FROM vana_scope_deletion_history
    WHERE owner_address = ? AND scope = ?
  `);
  return {
    remember(scope, tombstone) {
      const write = () => {
        const previous = get.get(owner, scope) as
          | {
              deleted_at: string;
              tombstone_version: string | null;
              erase_applied: number;
              erase_applied_version: string | null;
            }
          | undefined;
        if (previous) {
          const priorVersion =
            previous.tombstone_version === "0"
              ? null
              : previous.tombstone_version;
          if (tombstone.version === null || tombstone.version === "0")
            return false;
          if (priorVersion !== null) {
            if (BigInt(tombstone.version) < BigInt(priorVersion)) return false;
            if (BigInt(tombstone.version) === BigInt(priorVersion)) {
              return (
                (previous.erase_applied !== 1 ||
                  previous.erase_applied_version !==
                    previous.tombstone_version) &&
                !options.replicationEnabled
              );
            }
          }
        }
        remember.run(owner, scope, tombstone.deletedAt, tombstone.version);
        return true;
      };
      const store = typeof records === "function" ? records() : records;
      if (store && store.database !== db)
        throw new Error(
          "History and record store must share the same SQLite connection",
        );
      const markApplied = () => {
        db.prepare(
          "UPDATE vana_scope_deletion_history SET erase_applied = 1, erase_applied_version = tombstone_version WHERE owner_address = ? AND scope = ?",
        ).run(owner, scope);
      };
      try {
        if (options.replicationEnabled) db.transaction(write).immediate();
        else if (store) store.recordScopeDeletion(scope, write, markApplied);
        else if (records) {
          db.transaction(() => {
            const registry = db
              .prepare(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name IN ('pdpp_instance_binding', 'pdpp_records', 'pdpp_record_changes', 'pdpp_stream_completion', 'pdpp_record_arrival') LIMIT 1",
              )
              .get();
            if (registry)
              throw new Error(
                "Canonical record store unavailable for deletion observation",
              );
            if (write()) markApplied();
          }).immediate();
        } else write();
      } catch (error) {
        options.logger?.error(
          {
            scope,
            error: error instanceof Error ? error.message : String(error),
            ...(error instanceof Error
              ? {
                  instance: (error as Error & { instance?: string }).instance,
                  stream: (error as Error & { stream?: string }).stream,
                }
              : {}),
          },
          "Scope deletion observation failed; deletion remains hidden",
        );
        if (error instanceof UnboundScopeStreamsError) {
          // The erase transaction rolled back. Keep its observation durable and
          // unmarked so reads refuse it and sync can move past this tombstone.
          // A failure of this separate history write must still propagate.
          db.transaction(write).immediate();
          return;
        }
        throw error;
      }
    },
    get(scope): ScopeTombstone | null {
      const row = get.get(owner, scope) as
        | {
            deleted_at: string;
            tombstone_version: string | null;
            erase_applied: number;
            erase_applied_version: string | null;
          }
        | undefined;
      return row
        ? {
            deletedAt: row.deleted_at,
            version: row.tombstone_version,
            ...(row.erase_applied === 1 &&
            row.erase_applied_version === row.tombstone_version
              ? { eraseApplied: true }
              : {}),
          }
        : null;
    },
  };
}

/** Migrate old unmarked observations one transaction at a time. */
export function migrateScopeDeletionHistory(
  db: Database,
  ownerAddress: string,
  records:
    | {
        readonly database: Database;
        recordScopeDeletion(
          scope: string,
          writeHistory: () => boolean,
          markApplied: () => void,
        ): void;
      }
    | undefined,
  logger: {
    info(fields: Record<string, unknown>, message: string): void;
    error(fields: Record<string, unknown>, message: string): void;
  },
  options: { dryRun?: boolean; replicationEnabled?: boolean } = {},
): void {
  const owner = ownerAddress.toLowerCase();
  let scopes = db
    .prepare(
      "SELECT scope FROM vana_scope_deletion_history WHERE owner_address = ? AND (erase_applied = 0 OR erase_applied_version IS NOT tombstone_version) ORDER BY scope",
    )
    .all(owner) as { scope: string }[];
  if (records && records.database !== db)
    throw new Error(
      "History and record store must share the same SQLite connection",
    );
  if (!options.dryRun && !options.replicationEnabled) {
    const unmapped = scopes
      .filter(({ scope }) => exclusiveScopeStreams(scope).size === 0)
      .map(({ scope }) => scope);
    if (unmapped.length) {
      db.prepare(
        "UPDATE vana_scope_deletion_history SET erase_applied = 1, erase_applied_version = tombstone_version WHERE owner_address = ? AND scope IN (SELECT value FROM json_each(?))",
      ).run(owner, JSON.stringify(unmapped));
      logger.info(
        { rule: "unmapped", count: unmapped.length },
        "Scope deletion migration",
      );
      const applied = new Set(unmapped);
      scopes = scopes.filter(({ scope }) => !applied.has(scope));
    }
  }
  const current = db.prepare(
    "SELECT erase_applied, erase_applied_version, tombstone_version FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
  );
  const mark = db.prepare(
    "UPDATE vana_scope_deletion_history SET erase_applied = 1, erase_applied_version = tombstone_version WHERE owner_address = ? AND scope = ? AND (erase_applied = 0 OR erase_applied_version IS NOT tombstone_version)",
  );
  const hasRegistry = () =>
    db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name IN ('pdpp_instance_binding', 'pdpp_records', 'pdpp_record_changes', 'pdpp_stream_completion', 'pdpp_record_arrival') LIMIT 1",
      )
      .get() !== undefined;
  if (options.replicationEnabled) {
    logger.info(
      {
        skipped: "replication",
        count: scopes.length,
        dryRun: options.dryRun === true,
      },
      "Scope deletion migration skip count",
    );
  }
  for (const { scope } of scopes) {
    try {
      if (options.replicationEnabled) {
        logger.info(
          { scope, skipped: "replication", dryRun: options.dryRun === true },
          "Scope deletion migration skipped",
        );
        continue;
      }
      const preview = () => {
        const row = current.get(owner, scope) as
          | {
              erase_applied: number;
              erase_applied_version: string | null;
              tombstone_version: string | null;
            }
          | undefined;
        if (
          !row ||
          (row.erase_applied === 1 &&
            row.erase_applied_version === row.tombstone_version)
        )
          return false;
        if (!records && hasRegistry())
          throw new Error(
            "Canonical record store unavailable for deletion migration",
          );
        if (records) assertScopeStreamsBound(db, scope);
        const methods = exclusiveScopeStreams(scope);
        type Count = { erase: number; keep: number };
        type StreamCounts = {
          stream: string;
          erase: number;
          keep: number;
          tables: Record<string, Count>;
        };
        const streams = new Map<string, StreamCounts>();
        const add = (
          stream: string,
          table: string,
          erase: boolean,
          count: number,
        ) => {
          const summary = streams.get(stream) ?? {
            stream,
            erase: 0,
            keep: 0,
            tables: {},
          };
          const tableCounts = summary.tables[table] ?? { erase: 0, keep: 0 };
          if (erase) tableCounts.erase += count;
          else tableCounts.keep += count;
          summary.tables[table] = tableCounts;
          if (table === "pdpp_records") {
            summary.erase = tableCounts.erase;
            summary.keep = tableCounts.keep;
          }
          streams.set(stream, summary);
        };
        for (const exclusive of methods.values()) {
          for (const stream of exclusive) add(stream, "pdpp_records", true, 0);
        }
        if (records && methods.size > 0) {
          const names = [...methods.keys()];
          const archive =
            scope === "claude.conversations"
              ? {
                  table: "pdpp_claude_transition",
                  erase: ["conversations", "messages"],
                }
              : scope === "claude.projects"
                ? {
                    table: "pdpp_claude_transition",
                    erase: ["projects", "project_documents"],
                  }
                : scope === "strava.activities"
                  ? { table: "pdpp_strava_transition", erase: ["activities"] }
                  : scope === "strava.coverage_diagnostics"
                    ? {
                        table: "pdpp_strava_transition",
                        erase: ["coverage_diagnostics"],
                      }
                    : undefined;
          for (const table of [
            "pdpp_records",
            "pdpp_record_changes",
            "pdpp_stream_completion",
            "pdpp_record_arrival",
          ]) {
            const rows = db
              .prepare(
                `SELECT b.method, r.stream, COUNT(*) AS count FROM ${table} r JOIN pdpp_instance_binding b ON b.instance = r.instance WHERE b.method IN (${names.map(() => "?").join(",")}) GROUP BY b.method, r.stream`,
              )
              .all(...names) as {
              method: string;
              stream: string;
              count: number;
            }[];
            for (const item of rows)
              add(
                item.stream,
                table,
                methods.get(item.method)?.includes(item.stream) === true,
                item.count,
              );
            if (archive) {
              const archived = db
                .prepare(
                  `SELECT stream, COUNT(*) AS count FROM ${table} WHERE instance IN (SELECT archive_instance FROM ${archive.table}) GROUP BY stream`,
                )
                .all() as { stream: string; count: number }[];
              for (const item of archived)
                add(
                  item.stream,
                  table,
                  archive.erase.includes(item.stream),
                  item.count,
                );
            }
          }
        }
        logger.info(
          {
            scope,
            rule: "erase_all",
            dryRun: options.dryRun === true,
            streams: [...streams.values()].sort((a, b) =>
              a.stream.localeCompare(b.stream),
            ),
          },
          options.dryRun
            ? "Scope deletion migration preview"
            : "Scope deletion migration",
        );
        return true;
      };
      if (options.dryRun) db.transaction(preview).immediate();
      else if (records)
        records.recordScopeDeletion(scope, preview, () => {
          mark.run(owner, scope);
        });
      else
        db.transaction(() => {
          if (preview()) mark.run(owner, scope);
        }).immediate();
    } catch (error) {
      logger.error(
        {
          scope,
          error: error instanceof Error ? error.message : String(error),
          ...(error instanceof Error
            ? {
                instance: (error as Error & { instance?: string }).instance,
                stream: (error as Error & { stream?: string }).stream,
              }
            : {}),
        },
        "Scope deletion migration failed; deletion remains hidden",
      );
    }
  }
}
