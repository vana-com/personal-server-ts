import type { Database } from "better-sqlite3";
import type {
  LegacyScopeAuthority,
  LegacyScopeHead,
  LegacyCoverageVerdict,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";

interface VerdictRow {
  scope: string;
  instance: string;
  legacy_version_id: number;
  canonical_cursor: string;
  verdict: "covered" | "not_covered";
  comparison_case: "same_time" | "canonical_newer";
  reason_counts_json: string;
  applied_exceptions_json: string;
  reason_json: string | null;
  legacy_bytes: number;
  canonical_bytes: number;
  byte_delta: number;
  evaluated_at: string;
}

function reasonForRow(row: VerdictRow) {
  return row.reason_json
    ? (JSON.parse(row.reason_json) as {
        reason: string;
        missingEntityCount: number;
        mismatchedFieldPaths: string[];
      })
    : null;
}

function coverageFromRow(row: VerdictRow): LegacyCoverageVerdict {
  const reason = reasonForRow(row);
  return {
    covered: row.verdict === "covered",
    comparisonCase: row.comparison_case,
    reasonCounts: JSON.parse(
      row.reason_counts_json,
    ) as LegacyCoverageVerdict["reasonCounts"],
    appliedExceptions: JSON.parse(
      row.applied_exceptions_json,
    ) as LegacyCoverageVerdict["appliedExceptions"],
    reason: (row.verdict === "covered"
      ? null
      : (reason?.reason ?? null)) as LegacyCoverageVerdict["reason"],
    missingEntityCount: reason?.missingEntityCount ?? 0,
    mismatchedFieldPaths: reason?.mismatchedFieldPaths ?? [],
    legacyBytes: row.legacy_bytes,
    canonicalBytes: row.canonical_bytes,
    byteDelta: row.byte_delta,
  };
}

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

    writeClock() {
      if (!hasTable("pdpp_write_clock")) return 0;
      return (
        (
          db
            .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
            .get() as { value: number } | undefined
        )?.value ?? 0
      );
    },

    hasTakeover(scope, instance) {
      return (
        hasTable("legacy_scope_takeovers") &&
        db
          .prepare(
            instance === undefined
              ? "SELECT 1 FROM legacy_scope_takeovers WHERE scope = ?"
              : "SELECT 1 FROM legacy_scope_takeovers WHERE scope = ? AND (instance = ? OR instance = '')",
          )
          .get(...(instance === undefined ? [scope] : [scope, instance])) !==
          undefined
      );
    },

    hasCoveredHead(scope, head, instance) {
      return (
        hasTable("legacy_scope_takeovers") &&
        db
          .prepare(
            "SELECT 1 FROM legacy_scope_takeovers WHERE scope = ? AND superseded_path = ? AND (instance = ? OR instance = '')",
          )
          .get(scope, head.path, instance) !== undefined
      );
    },

    isReset(scope) {
      return (
        hasTable("legacy_scope_takeover_resets") &&
        db
          .prepare("SELECT 1 FROM legacy_scope_takeover_resets WHERE scope = ?")
          .get(scope) !== undefined
      );
    },

    cachedVerdict(scope, instance, legacyVersionId, canonicalCursor) {
      if (!hasTable("legacy_scope_takeover_verdicts")) return null;
      const row = db
        .prepare(
          `SELECT * FROM legacy_scope_takeover_verdicts
        WHERE scope = ? AND instance = ? AND legacy_version_id = ? AND canonical_cursor = ?`,
        )
        .get(scope, instance, legacyVersionId, canonicalCursor) as
        VerdictRow | undefined;
      return row ? coverageFromRow(row) : null;
    },

    verdictFor(scope) {
      if (!hasTable("legacy_scope_takeover_verdicts")) return [];
      const rows = db
        .prepare(
          "SELECT * FROM legacy_scope_takeover_verdicts WHERE scope = ? ORDER BY instance",
        )
        .all(scope) as VerdictRow[];
      return rows.map((row) => ({
        scope: row.scope,
        instance: row.instance,
        legacyVersionId: row.legacy_version_id,
        canonicalCursor: row.canonical_cursor,
        verdict: row.verdict,
        comparisonCase: row.comparison_case,
        reasonCounts: JSON.parse(row.reason_counts_json) as Record<
          string,
          number
        >,
        appliedExceptions: JSON.parse(
          row.applied_exceptions_json,
        ) as LegacyCoverageVerdict["appliedExceptions"],
        reason: reasonForRow(row),
        legacyBytes: row.legacy_bytes,
        canonicalBytes: row.canonical_bytes,
        byteDelta: row.byte_delta,
        evaluatedAt: row.evaluated_at,
      }));
    },

    resetTakeover(scope) {
      db.transaction(() => {
        if (hasTable("legacy_scope_takeover_verdicts"))
          db.prepare(
            "DELETE FROM legacy_scope_takeover_verdicts WHERE scope = ?",
          ).run(scope);
        if (hasTable("legacy_scope_takeovers"))
          db.prepare("DELETE FROM legacy_scope_takeovers WHERE scope = ?").run(
            scope,
          );
        if (hasTable("legacy_scope_takeover_resets"))
          db.prepare(
            "INSERT OR REPLACE INTO legacy_scope_takeover_resets (scope) VALUES (?)",
          ).run(scope);
      }).immediate();
    },

    eligibleLegacyHead(scope) {
      return readEligibleLegacyHead(scope);
    },

    confirmRead(scope, expectedHead, selectionIsCurrent, verdict) {
      if (!hasTable("data_files")) return expectedHead === null;
      const validate = () => {
        const currentHead = readEligibleLegacyHead(scope);
        if (!sameHead(currentHead, expectedHead) || !selectionIsCurrent()) {
          return false;
        }
        if (
          verdict &&
          verdict.writeClock !==
            (
              db
                .prepare("SELECT value FROM pdpp_write_clock WHERE id = 1")
                .get() as { value: number }
            ).value
        )
          return false;
        if (expectedHead === null) return true;
        if (verdict?.cached) return true;
        if (!hasTable("legacy_scope_takeovers")) return false;

        if (verdict) {
          if (!hasTable("legacy_scope_takeover_verdicts")) return false;
          const coverage = verdict.coverage;
          db.prepare(
            `INSERT INTO legacy_scope_takeover_verdicts
            (scope, instance, legacy_version_id, canonical_cursor, verdict, comparison_case, reason_counts_json, applied_exceptions_json, reason_json,
             legacy_bytes, canonical_bytes, byte_delta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, instance) DO UPDATE SET
              legacy_version_id = excluded.legacy_version_id,
              canonical_cursor = excluded.canonical_cursor,
              verdict = excluded.verdict,
              comparison_case = excluded.comparison_case,
              reason_counts_json = excluded.reason_counts_json,
              applied_exceptions_json = excluded.applied_exceptions_json,
              reason_json = excluded.reason_json,
              legacy_bytes = excluded.legacy_bytes,
              canonical_bytes = excluded.canonical_bytes,
              byte_delta = excluded.byte_delta,
              evaluated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
          `,
          ).run(
            scope,
            verdict.instance,
            expectedHead.id,
            verdict.canonicalCursor,
            coverage.covered ? "covered" : "not_covered",
            coverage.comparisonCase,
            JSON.stringify(coverage.reasonCounts),
            JSON.stringify(coverage.appliedExceptions),
            coverage.covered && coverage.missingEntityCount === 0
              ? null
              : JSON.stringify({
                  reason: coverage.covered
                    ? "proven_deletion"
                    : coverage.reason,
                  missingEntityCount: coverage.missingEntityCount,
                  mismatchedFieldPaths: coverage.mismatchedFieldPaths,
                }),
            coverage.legacyBytes,
            coverage.canonicalBytes,
            coverage.byteDelta,
          );
          if (!coverage.covered) return true;
          db.prepare(
            `INSERT OR IGNORE INTO legacy_scope_takeovers
            (scope, instance, superseded_version, superseded_cas_revision, superseded_collected_at, superseded_path)
            VALUES (?, ?, ?, ?, ?, ?)`,
          ).run(
            scope,
            verdict.instance,
            expectedHead.version,
            expectedHead.casRevision,
            expectedHead.collectedAt,
            expectedHead.path,
          );
          return true;
        }

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
        return expectedHead === null || verdict?.cached
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
