/**
 * SQLite-backed store for derivative question registrations. Lives in the
 * same index.db as the data index; its own table, created on first use
 * (CREATE TABLE IF NOT EXISTS), so no index schema version bump.
 */

import type Database from "better-sqlite3";
import {
  matchesQuestionFilter,
  type QuestionRegisteredBy,
  type QuestionRegistration,
  type QuestionStore,
} from "@opendatalabs/personal-server-ts-core/derivatives";

const CREATE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS derivative_questions (
  question_id TEXT PRIMARY KEY,
  derived_scope TEXT NOT NULL,
  source_scopes TEXT NOT NULL,
  question TEXT NOT NULL,
  model TEXT,
  -- Vestigial. Registration no longer has a mode: every question takes the
  -- one compute path. The column is kept because it shipped NOT NULL with a
  -- default, so inserts that omit it still succeed and no DROP COLUMN
  -- migration is needed. Nothing reads it.
  mode TEXT NOT NULL DEFAULT 'completion',
  recompute TEXT NOT NULL DEFAULT 'on-change',
  registered_by TEXT NOT NULL,
  status TEXT NOT NULL,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_computed_at TEXT,
  derived_version INTEGER,
  derived_collected_at TEXT
)`;

const CREATE_INDEX_SQL =
  "CREATE INDEX IF NOT EXISTS idx_derivative_questions_derived_scope ON derivative_questions (derived_scope)";

// Databases created before the recompute policy existed migrate in place;
// their registrations keep the old follow-every-change behavior.
const ADD_RECOMPUTE_COLUMN_SQL =
  "ALTER TABLE derivative_questions ADD COLUMN recompute TEXT NOT NULL DEFAULT 'on-change'";

interface Row {
  question_id: string;
  derived_scope: string;
  source_scopes: string;
  question: string;
  model: string | null;
  recompute: QuestionRegistration["recompute"];
  registered_by: string;
  status: QuestionRegistration["status"];
  error: string | null;
  created_at: string;
  updated_at: string;
  last_computed_at: string | null;
  derived_version: number | null;
  derived_collected_at: string | null;
}

function toRegistration(row: Row): QuestionRegistration {
  return {
    questionId: row.question_id,
    derivedScope: row.derived_scope,
    sourceScopes: JSON.parse(row.source_scopes) as string[],
    question: row.question,
    model: row.model,
    recompute: row.recompute,
    registeredBy: JSON.parse(row.registered_by) as QuestionRegisteredBy,
    status: row.status,
    error: row.error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastComputedAt: row.last_computed_at,
    derivedVersion: row.derived_version,
    derivedCollectedAt: row.derived_collected_at,
  };
}

/**
 * Adds the vestigial `mode` column to a table created before it existed.
 *
 * Registration no longer has a mode and nothing reads this column, but it
 * shipped in a release, so databases in the wild may or may not have it.
 * Kept (rather than replaced by a DROP COLUMN) because it is NOT NULL with a
 * default: inserts that omit it succeed either way, so one dead column costs
 * nothing and carries no migration risk. Guarded by `PRAGMA table_info` rather
 * than a caught `ALTER`, so a real failure (locked database, disk full)
 * surfaces here rather than resurfacing later as a confusing error.
 */
function migrateModeColumn(db: Database.Database): void {
  const columns = db
    .prepare("PRAGMA table_info(derivative_questions)")
    .all() as Array<{ name: string }>;
  if (columns.some((column) => column.name === "mode")) return;
  db.exec(
    "ALTER TABLE derivative_questions ADD COLUMN mode TEXT NOT NULL DEFAULT 'completion'",
  );
}

/**
 * Adds the `recompute` column to a table created before it existed, on the
 * same terms as `migrateModeColumn`: guarded by `PRAGMA table_info`, so it is
 * a no-op on a database that already has the column. Existing rows take the
 * column default, `on-change`, the follow-every-change behavior they were
 * registered under.
 */
function migrateRecomputeColumn(db: Database.Database): void {
  const columns = db
    .prepare("PRAGMA table_info(derivative_questions)")
    .all() as Array<{ name: string }>;
  if (columns.some((column) => column.name === "recompute")) return;
  db.exec(ADD_RECOMPUTE_COLUMN_SQL);
}

export function createSqliteQuestionStore(
  db: Database.Database,
): QuestionStore {
  db.exec(CREATE_TABLE_SQL);
  db.exec(CREATE_INDEX_SQL);
  migrateModeColumn(db);
  migrateRecomputeColumn(db);

  const listAll = db.prepare(
    "SELECT * FROM derivative_questions ORDER BY created_at ASC, question_id ASC",
  );
  const getOne = db.prepare(
    "SELECT * FROM derivative_questions WHERE question_id = ?",
  );
  const insertOne = db.prepare(`
    INSERT INTO derivative_questions (
      question_id, derived_scope, source_scopes, question, model,
      recompute, registered_by, status, error, created_at, updated_at,
      last_computed_at, derived_version, derived_collected_at
    ) VALUES (
      @question_id, @derived_scope, @source_scopes, @question, @model,
      @recompute, @registered_by, @status, @error, @created_at, @updated_at,
      @last_computed_at, @derived_version, @derived_collected_at
    )`);
  const updateOne = db.prepare(`
    UPDATE derivative_questions SET
      status = @status,
      error = @error,
      updated_at = @updated_at,
      last_computed_at = @last_computed_at,
      derived_version = @derived_version,
      derived_collected_at = @derived_collected_at
    WHERE question_id = @question_id`);
  const deleteOne = db.prepare(
    "DELETE FROM derivative_questions WHERE question_id = ?",
  );

  return {
    async list(filter) {
      return (listAll.all() as Row[])
        .map(toRegistration)
        .filter((registration) => matchesQuestionFilter(registration, filter));
    },
    async get(questionId) {
      const row = getOne.get(questionId) as Row | undefined;
      return row ? toRegistration(row) : null;
    },
    async insert(registration) {
      insertOne.run({
        question_id: registration.questionId,
        derived_scope: registration.derivedScope,
        source_scopes: JSON.stringify(registration.sourceScopes),
        question: registration.question,
        model: registration.model,
        recompute: registration.recompute,
        registered_by: JSON.stringify(registration.registeredBy),
        status: registration.status,
        error: registration.error,
        created_at: registration.createdAt,
        updated_at: registration.updatedAt,
        last_computed_at: registration.lastComputedAt,
        derived_version: registration.derivedVersion,
        derived_collected_at: registration.derivedCollectedAt,
      });
    },
    async update(questionId, patch) {
      const current = getOne.get(questionId) as Row | undefined;
      if (!current) return null;
      const merged = { ...toRegistration(current), ...patch };
      updateOne.run({
        question_id: questionId,
        status: merged.status,
        error: merged.error,
        updated_at: merged.updatedAt,
        last_computed_at: merged.lastComputedAt,
        derived_version: merged.derivedVersion,
        derived_collected_at: merged.derivedCollectedAt,
      });
      return merged;
    },
    async delete(questionId) {
      return deleteOne.run(questionId).changes > 0;
    },
  };
}
