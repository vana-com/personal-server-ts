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
        recordScopeDeletion(
          scope: string,
          writeHistory: () => boolean,
          markApplied: () => void,
        ): void;
      }
    | (() =>
        | {
            recordScopeDeletion(
              scope: string,
              writeHistory: () => boolean,
              markApplied: () => void,
            ): void;
          }
        | undefined),
  options: { replicationEnabled?: boolean } = {},
): ScopeDeletionHistory {
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
      erase_applied = 0
  `);
  const get = db.prepare(`
    SELECT deleted_at, tombstone_version, erase_applied FROM vana_scope_deletion_history
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
                previous.erase_applied !== 1 && !options.replicationEnabled
              );
            }
          }
        }
        remember.run(owner, scope, tombstone.deletedAt, tombstone.version);
        return true;
      };
      const store = typeof records === "function" ? records() : records;
      const markApplied = () => {
        db.prepare(
          "UPDATE vana_scope_deletion_history SET erase_applied = 1 WHERE owner_address = ? AND scope = ?",
        ).run(owner, scope);
      };
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
    },
    get(scope): ScopeTombstone | null {
      const row = get.get(owner, scope) as
        | {
            deleted_at: string;
            tombstone_version: string | null;
            erase_applied: number;
          }
        | undefined;
      return row
        ? {
            deletedAt: row.deleted_at,
            version: row.tombstone_version,
            ...(row.erase_applied === 1 ? { eraseApplied: true } : {}),
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
  const scopes = db
    .prepare(
      "SELECT scope FROM vana_scope_deletion_history WHERE owner_address = ? AND erase_applied = 0 ORDER BY scope",
    )
    .all(owner) as { scope: string }[];
  const current = db.prepare(
    "SELECT erase_applied FROM vana_scope_deletion_history WHERE owner_address = ? AND scope = ?",
  );
  const mark = db.prepare(
    "UPDATE vana_scope_deletion_history SET erase_applied = 1 WHERE owner_address = ? AND scope = ? AND erase_applied = 0",
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
          { erase_applied: number } | undefined;
        if (!row || row.erase_applied !== 0) return false;
        if (!records && hasRegistry())
          throw new Error(
            "Canonical record store unavailable for deletion migration",
          );
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
          const exclusive = [...new Set([...methods.values()].flat())];
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
            if (exclusive.length > 0) {
              const marks = exclusive.map(() => "?").join(",");
              const unknown = db
                .prepare(
                  `SELECT 1 FROM ${table} r LEFT JOIN pdpp_instance_binding b ON b.instance = r.instance WHERE (b.instance IS NULL OR b.method IS NULL) AND NOT EXISTS (SELECT 1 FROM pdpp_claude_transition c WHERE c.archive_instance = r.instance) AND NOT EXISTS (SELECT 1 FROM pdpp_strava_transition t WHERE t.archive_instance = r.instance) AND r.stream IN (${marks}) LIMIT 1`,
                )
                .get(...exclusive);
              if (unknown)
                throw new Error("Cannot establish the owner of a stream");
            }
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
          "Scope deletion migration preview",
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
    } catch {
      logger.error(
        { scope },
        "Scope deletion migration failed; deletion remains hidden",
      );
    }
  }
}
