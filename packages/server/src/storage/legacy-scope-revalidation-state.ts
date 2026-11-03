import type { Database } from "better-sqlite3";
import { legacyCoverageCandidates } from "./legacy-scope-revalidator.js";

/** Conservatively cover all PDPP state, including claims, custody and visibility.
 * The bridge owns only legacy_* marker tables, so marking cannot enqueue itself. */
const dependencyTable =
  /\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM|DROP\s+TABLE(?:\s+IF\s+EXISTS)?|ALTER\s+TABLE)\s+(?:main\.)?["`\[]?(?:data_files|pdpp_[a-z_]+)\b/i;
export interface LegacyRevalidationStatus {
  dirty_since: number | null;
  ceiling_ms: number;
  error_count: number;
  reason: string | null;
}
export interface LegacyRevalidationState {
  db: Database;
  revision(instance: string): number;
  fingerprint(): string;
  candidates(): ReturnType<typeof legacyCoverageCandidates>;
  markDirty(since?: number): void;
  ensureDirty(): void;
  complete(instance: string, scope: string, revision: number): boolean;
  fail(instance: string, scopes: readonly string[]): void;
  status(instance: string, scope: string): LegacyRevalidationStatus | undefined;
  overdue(instance: string, scope: string): boolean;
  diagnostics(): {
    instance: string;
    scope: string;
    dirty_since: number;
    error_count: number;
    reason: string;
  }[];
}
const tracked = new WeakMap<Database, LegacyRevalidationState>();
export function trackLegacyScopeMutations(
  raw: Database,
  options: { ceilingMs: number; now?: () => number },
): LegacyRevalidationState {
  const existing = tracked.get(raw);
  if (existing) return existing;
  const state = makeState(raw, options);
  tracked.set(raw, state);
  tracked.set(state.db, state);
  return state;
}

function makeState(
  raw: Database,
  options: { ceilingMs: number; now?: () => number },
): LegacyRevalidationState {
  const now = options.now ?? Date.now;
  raw.exec(`CREATE TABLE IF NOT EXISTS legacy_scope_revalidation_instances (
    instance TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0 AND revision<=9007199254740991));
    CREATE TABLE IF NOT EXISTS legacy_scope_revalidation_scopes (
    instance TEXT NOT NULL,scope TEXT NOT NULL,dirty_since INTEGER,
    ceiling_ms INTEGER NOT NULL,error_count INTEGER NOT NULL DEFAULT 0,reason TEXT,
    PRIMARY KEY(instance,scope));`);
  const bump =
    raw.prepare(`INSERT INTO legacy_scope_revalidation_instances(instance,revision) VALUES (?,1)
    ON CONFLICT(instance) DO UPDATE SET revision=revision+1`);
  const dirty =
    raw.prepare(`INSERT INTO legacy_scope_revalidation_scopes(instance,scope,dirty_since,ceiling_ms) VALUES (?,?,?,?)
    ON CONFLICT(instance,scope) DO UPDATE SET dirty_since=COALESCE(dirty_since,excluded.dirty_since),ceiling_ms=excluded.ceiling_ms,
      error_count=CASE WHEN dirty_since IS NULL THEN 0 ELSE error_count END,
      reason=CASE WHEN dirty_since IS NULL THEN NULL ELSE reason END
    WHERE dirty_since IS NULL OR ceiling_ms<>excluded.ceiling_ms`);
  const readRevision = raw
    .prepare(
      "SELECT revision FROM legacy_scope_revalidation_instances WHERE instance=?",
    )
    .pluck();
  const readStatus = raw.prepare(
    "SELECT dirty_since,ceiling_ms,error_count,reason FROM legacy_scope_revalidation_scopes WHERE instance=? AND scope=?",
  );
  let dirtyAt: number | null = null;
  const bindingTable = raw.prepare(
    "SELECT 1 FROM sqlite_master WHERE name='pdpp_instance_binding'",
  );
  let bindingsReady = false;
  function candidates() {
    if (!bindingsReady) bindingsReady = bindingTable.get() !== undefined;
    return bindingsReady ? legacyCoverageCandidates(raw) : [];
  }
  function mark(bumpRevision: boolean, since = now()) {
    for (const candidate of candidates()) {
      if (bumpRevision) bump.run(candidate.instance);
      for (const scope of candidate.scopes)
        dirty.run(candidate.instance, scope, since, options.ceilingMs);
    }
  }
  function atomic<T>(
    run: () => T,
    mode: "deferred" | "immediate" | "exclusive" = "immediate",
  ): T {
    const outer = !raw.inTransaction;
    const checkpoint = dirtyAt;
    try {
      return raw
        .transaction(() => {
          const result = run();
          if (outer && dirtyAt !== null) {
            mark(true, dirtyAt);
            dirtyAt = null;
          }
          return result;
        })
        [mode]();
    } catch (error) {
      dirtyAt = checkpoint;
      throw error;
    }
  }
  function mutate<T>(run: () => T, exec = false, force = false): T {
    const write = () => {
      const started = dirtyAt ?? now();
      const before = exec
        ? (raw.prepare("SELECT total_changes()").pluck().get() as number)
        : 0;
      const result = run();
      const changed = exec
        ? (raw.prepare("SELECT total_changes()").pluck().get() as number) >
          before
        : !(
            typeof result === "object" &&
            result !== null &&
            "changes" in result &&
            result.changes === 0
          ) && result !== undefined;
      if (changed || force)
        dirtyAt = dirtyAt === null ? started : Math.min(dirtyAt, started);
      return result;
    };
    return raw.inTransaction ? write() : atomic(write);
  }
  // Wrap the transaction boundary, not each record with a counter write. Native
  // statements stay prepared; one marker update commits with the whole batch.
  const db = new Proxy(raw, {
    get(target, property) {
      if (property === "transaction")
        return (fn: (...args: unknown[]) => unknown) => {
          const invoke = (
            mode: "deferred" | "immediate" | "exclusive",
            args: unknown[],
          ) => atomic(() => fn(...args), mode);
          return Object.assign(
            (...args: unknown[]) => invoke("deferred", args),
            {
              deferred: (...args: unknown[]) => invoke("deferred", args),
              immediate: (...args: unknown[]) => invoke("immediate", args),
              exclusive: (...args: unknown[]) => invoke("exclusive", args),
            },
          );
        };
      if (property === "exec")
        return (sql: string) => {
          if (dependencyTable.test(sql))
            mutate(
              () => target.exec(sql),
              true,
              /\b(?:DROP|ALTER)\s+TABLE/i.test(sql),
            );
          else target.exec(sql);
          return db;
        };
      if (property === "prepare")
        return (sql: string) => {
          const statement = target.prepare(sql);
          if (statement.readonly || !dependencyTable.test(sql))
            return statement;
          const methods = new Map<PropertyKey, unknown>();
          const proxy = new Proxy(statement, {
            get(stmt, key) {
              if (methods.has(key)) return methods.get(key);
              const value = Reflect.get(stmt, key, stmt);
              if (typeof value !== "function") return value;
              const method =
                key === "run" || key === "get" || key === "all"
                  ? (...args: unknown[]) =>
                      mutate(() => value.apply(stmt, args))
                  : (...args: unknown[]) => {
                      const result = value.apply(stmt, args);
                      return result === stmt ? proxy : result;
                    };
              methods.set(key, method);
              return method;
            },
          });
          return proxy;
        };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as Database;
  function status(instance: string, scope: string) {
    return readStatus.get(instance, scope) as
      | {
          dirty_since: number | null;
          ceiling_ms: number;
          error_count: number;
          reason: string | null;
        }
      | undefined;
  }
  return {
    db,
    revision: (instance: string) => Number(readRevision.get(instance) ?? 0),
    fingerprint: () =>
      JSON.stringify(
        raw
          .prepare(
            "SELECT instance,revision FROM legacy_scope_revalidation_instances ORDER BY instance",
          )
          .all(),
      ),
    candidates,
    markDirty(since = now()) {
      raw.transaction(() => mark(true, since)).immediate();
    },
    ensureDirty() {
      raw.transaction(() => mark(false)).immediate();
    },
    complete(instance: string, scope: string, revision: number) {
      if (Number(readRevision.get(instance) ?? 0) !== revision) return false;
      raw
        .prepare(
          "UPDATE legacy_scope_revalidation_scopes SET dirty_since=NULL,error_count=0,reason=NULL WHERE instance=? AND scope=?",
        )
        .run(instance, scope);
      return true;
    },
    fail(instance: string, scopes: readonly string[]) {
      const statement = raw.prepare(
        "UPDATE legacy_scope_revalidation_scopes SET error_count=error_count+1 WHERE instance=? AND scope=? AND dirty_since IS NOT NULL",
      );
      raw.transaction(() => {
        for (const scope of scopes) statement.run(instance, scope);
      })();
    },
    status,
    overdue(instance: string, scope: string) {
      const row = status(instance, scope);
      return (
        row?.dirty_since !== null &&
        row?.dirty_since !== undefined &&
        now() >= row.dirty_since + row.ceiling_ms
      );
    },
    diagnostics() {
      raw
        .prepare(
          `UPDATE legacy_scope_revalidation_scopes SET reason=CASE WHEN error_count>0 THEN 'evaluation_failing' ELSE 'evaluation_overdue' END WHERE dirty_since IS NOT NULL AND dirty_since+ceiling_ms<=? AND (reason IS NULL OR reason<>CASE WHEN error_count>0 THEN 'evaluation_failing' ELSE 'evaluation_overdue' END)`,
        )
        .run(now());
      return raw
        .prepare(
          "SELECT instance,scope,dirty_since,error_count,reason FROM legacy_scope_revalidation_scopes WHERE reason IS NOT NULL",
        )
        .all() as ReturnType<LegacyRevalidationState["diagnostics"]>;
    },
  };
}
