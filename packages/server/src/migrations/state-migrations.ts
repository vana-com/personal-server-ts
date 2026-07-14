import type Database from "better-sqlite3";
import { detectStuckVersionLedger } from "./detect-stuck-version-ledger.js";

/**
 * Versioned local-state migration framework for the desktop Personal Server.
 *
 * Each release carries a (possibly empty) ordered list of migrations. A
 * migration inspects the on-disk state (`index.db` and friends) and repairs it
 * on boot, so users self-heal on upgrade instead of needing manual surgery.
 *
 * Two shapes:
 *   • one-shot (default) — runs once, then its id is recorded in
 *     `state.json.migrations.applied` and it is never re-checked. Use for
 *     structural, run-once cleanups.
 *   • `everyBoot: true` — its `check()`/`run()` are re-evaluated on every boot
 *     and it is never recorded as applied. Use for idempotent heals whose
 *     triggering condition can recur. The `check()` MUST be cheap and `run()`
 *     a no-op when nothing needs repair.
 *
 * Every actual repair is appended to `state.json.migrations.log` for support
 * visibility.
 */

export interface StateMigrationLogger {
  info: (obj: unknown, msg?: string) => void;
  warn: (obj: unknown, msg?: string) => void;
}

export interface StateMigrationContext {
  db: Database.Database;
  storageRoot: string;
  logger?: StateMigrationLogger;
}

export interface StateMigrationResult {
  /** Whether the run actually changed anything (drives the log's `changed`). */
  changed: boolean;
  /** Short human-readable summary of what was repaired. */
  detail?: string;
}

export interface StateMigration {
  /** Stable, unique id. Convention: `YYYY-MM-DD-kebab-summary`. */
  id: string;
  description: string;
  /** Re-run every boot instead of once. See module doc. Default false. */
  everyBoot?: boolean;
  /** Cheap guard: is the repair needed right now? */
  check(ctx: StateMigrationContext): boolean;
  /**
   * Apply the repair. Should be a no-op when nothing needs fixing.
   *
   * MUST be idempotent even for one-shot (non-`everyBoot`) migrations. The
   * `applied` ledger in state.json is a best-effort skip cache, not a
   * guarantee: a lost or corrupt state.json legitimately resets it, so `run`
   * may execute more than once across boots. Guard destructive work behind
   * `check()` (which is always consulted before `run` when the id is not in the
   * ledger) and make `run` safe to repeat.
   */
  run(ctx: StateMigrationContext): StateMigrationResult;
}

export interface StateMigrationRunLogEntry {
  id: string;
  ranAt: string;
  changed: boolean;
  detail?: string;
}

export interface StateMigrationsState {
  /** Ids of one-shot migrations already run (never includes everyBoot ones). */
  applied: string[];
  /** Bounded history of actual repairs, oldest first. */
  log: StateMigrationRunLogEntry[];
}

export interface RunStateMigrationsOptions {
  migrations?: StateMigration[];
  /** Injectable clock (tests). Defaults to `new Date().toISOString()`. */
  now?: () => string;
  /** Max retained log entries (oldest dropped). Default 50. */
  maxLog?: number;
}

/** The registry applied on every boot. Append new migrations here. */
export const STATE_MIGRATIONS: StateMigration[] = [detectStuckVersionLedger];

const DEFAULT_MAX_LOG = 50;

export function runStateMigrations(
  ctx: StateMigrationContext,
  prior: StateMigrationsState | undefined,
  options: RunStateMigrationsOptions = {},
): StateMigrationsState {
  const migrations = options.migrations ?? STATE_MIGRATIONS;
  const now = options.now ?? (() => new Date().toISOString());
  const maxLog = options.maxLog ?? DEFAULT_MAX_LOG;

  // Defensive: state.json is parsed untyped, so a corrupt or hand-edited file
  // can carry non-array `applied`/`log` (e.g. `{}`). Coerce rather than let
  // `new Set(...)` / spread throw and brick boot.
  const applied = new Set(Array.isArray(prior?.applied) ? prior.applied : []);
  const log: StateMigrationRunLogEntry[] = Array.isArray(prior?.log)
    ? [...prior.log]
    : [];

  for (const migration of migrations) {
    if (!migration.everyBoot && applied.has(migration.id)) continue;

    let needed: boolean;
    try {
      needed = migration.check(ctx);
    } catch (err) {
      // Leave unmarked so a transient failure retries on the next boot.
      ctx.logger?.warn(
        { migration: migration.id, error: (err as Error).message },
        "State migration check failed; skipping",
      );
      continue;
    }

    if (needed) {
      try {
        const result = migration.run(ctx);
        // everyBoot migrations re-observe the same condition on every boot
        // until it clears; without dedupe a persistent condition fills the
        // bounded log with identical entries and evicts real history. Keep
        // one entry per observation streak: skip the push when the latest
        // entry for this id already records the same outcome. One-shot
        // migrations always log (a re-run after ledger loss is worth seeing).
        const latestForId = [...log]
          .reverse()
          .find((entry) => entry.id === migration.id);
        const duplicateObservation =
          migration.everyBoot === true &&
          latestForId !== undefined &&
          latestForId.changed === result.changed &&
          latestForId.detail === result.detail;
        if (!duplicateObservation) {
          log.push({
            id: migration.id,
            ranAt: now(),
            changed: result.changed,
            detail: result.detail,
          });
        }
        ctx.logger?.info(
          {
            migration: migration.id,
            changed: result.changed,
            detail: result.detail,
          },
          "Applied state migration",
        );
      } catch (err) {
        // A failed repair must not be recorded as applied — retry next boot.
        ctx.logger?.warn(
          { migration: migration.id, error: (err as Error).message },
          "State migration failed; leaving state unchanged",
        );
        continue;
      }
    }

    if (!migration.everyBoot) applied.add(migration.id);
  }

  return {
    applied: [...applied],
    log: log.slice(-maxLog),
  };
}
