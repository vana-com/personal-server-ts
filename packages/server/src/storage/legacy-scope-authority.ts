import type { Database } from "better-sqlite3";
import type {
  LegacyScopeAuthority,
  LegacyScopeHead,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

/**
 * Registry facts for the legacy scope view, plus its durable takeover ledger.
 * It does not open the record store: opening it migrates and sweeps, and this
 * must also answer when PDPP is disabled. A table that was never created
 * holds no connection and no evidence.
 *
 * It shares the record store's database connection, so its reads inside
 * `readSnapshot` see that same snapshot. Takeover writes only the separate
 * diagnostic ledger; it never changes the legacy index or its files.
 */
export function createLegacyScopeAuthority(db: Database): LegacyScopeAuthority {
  const hasTable = (name: string) =>
    db
      .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(name) !== undefined;

  return {
    listMethodConnections(methods) {
      if (methods.length === 0 || !hasTable("pdpp_instance_binding")) {
        return [];
      }
      // `listConnections` hides deleted connections; a deleted one is still
      // evidence that the scope's data lived in the registry.
      const rows = db
        .prepare(
          `SELECT * FROM pdpp_instance_binding
            WHERE method IN (${methods.map(() => "?").join(", ")})
            ORDER BY instance`,
        )
        .all(...methods) as {
        instance: string;
        source_id?: string | null;
        method: string | null;
        deleted_at?: string | null;
        generation: number;
        reset_clock: number;
      }[];
      return rows.map((row) => ({
        instance: row.instance,
        sourceId: row.source_id ?? null,
        method: row.method,
        deletedAt: row.deleted_at ?? null,
        generation: row.generation,
        resetClock: row.reset_clock,
      }));
    },

    hasHeldData(instance, streams) {
      if (streams?.length === 0) return false;
      const streamFilter = streams
        ? ` AND stream IN (${streams.map(() => "?").join(", ")})`
        : "";
      const tables = [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_stream_completion",
      ].filter(hasTable);
      return tables.some(
        (table) =>
          db
            .prepare(
              `SELECT 1 FROM ${table} WHERE instance = ?${streamFilter} LIMIT 1`,
            )
            .get(instance, ...(streams ?? [])) !== undefined,
      );
    },

    readSnapshot: <T>(read: () => T): T => db.transaction(read).deferred(),

    hasTakeover(scope) {
      return (
        hasTable("legacy_scope_takeovers") &&
        db
          .prepare("SELECT 1 FROM legacy_scope_takeovers WHERE scope = ?")
          .get(scope) !== undefined
      );
    },

    eligibleLegacyHead(scope) {
      return readEligibleLegacyHead(scope);
    },

    confirmRead(scope, expectedHead, selectionIsCurrent) {
      if (!hasTable("data_files")) return expectedHead === null;
      const validate = () => {
        const currentHead = readEligibleLegacyHead(scope);
        if (!sameHead(currentHead, expectedHead) || !selectionIsCurrent()) {
          return false;
        }
        if (expectedHead === null) return true;
        if (!hasTable("legacy_scope_takeovers")) return false;

        // A non-null producer is explicit ownership evidence from another
        // legacy pipeline. Null covers manual and old connector files.
        db.prepare(
          `
          INSERT OR IGNORE INTO legacy_scope_takeovers (
            scope, superseded_version, superseded_cas_revision,
            superseded_collected_at, superseded_path
          )
          SELECT scope, version, cas_revision, collected_at, path
            FROM data_files
           WHERE scope = ?
             AND (producer IS NULL OR producer NOT IN ('pdpp-projector', 'pdpp-import-projection'))
           ORDER BY julianday(collected_at) DESC, id DESC
        `,
        ).run(scope);
        return true;
      };
      try {
        return expectedHead === null
          ? db.transaction(validate).deferred()
          : db.transaction(validate).immediate();
      } catch (error) {
        if (
          expectedHead !== null &&
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          (error.code === "SQLITE_BUSY" || error.code === "SQLITE_LOCKED")
        ) {
          return false;
        }
        throw error;
      }
    },
  };

  function readEligibleLegacyHead(scope: string): LegacyScopeHead | null {
    if (!hasTable("data_files")) return null;
    const latest = db
      .prepare(
        `
        SELECT id, path, version, cas_revision, collected_at, producer
          FROM data_files
         WHERE scope = ?
         ORDER BY julianday(collected_at) DESC, id DESC
         LIMIT 1
      `,
      )
      .get(scope) as
      | {
          id: number;
          path: string;
          version: number;
          cas_revision: number;
          collected_at: string;
          producer: string | null;
        }
      | undefined;
    if (
      !latest ||
      latest.producer === "pdpp-projector" ||
      latest.producer === "pdpp-import-projection"
    ) {
      return null;
    }
    return {
      id: latest.id,
      path: latest.path,
      version: latest.version,
      casRevision: latest.cas_revision,
      collectedAt: latest.collected_at,
    };
  }
}

function sameHead(
  left: LegacyScopeHead | null,
  right: LegacyScopeHead | null,
): boolean {
  return left === null
    ? right === null
    : right !== null &&
        left.id === right.id &&
        left.path === right.path &&
        left.version === right.version &&
        left.casRevision === right.casRevision &&
        left.collectedAt === right.collectedAt;
}
