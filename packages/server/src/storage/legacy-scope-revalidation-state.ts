import { LEGACY_SCOPE_WITNESS_IDENTITY } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import type { Database, Statement } from "better-sqlite3";

/** Conservatively cover all PDPP state, including claims, custody and visibility.
 * The bridge owns only legacy_* marker tables, so marking cannot enqueue itself. */
const dependencyTable =
  /\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE(?:\s+OR\s+\w+)?|DELETE\s+FROM|DROP\s+TABLE(?:\s+IF\s+EXISTS)?|ALTER\s+TABLE)\s+(?:main\.)?["`\[]?(?:data_files|pdpp_[a-z_]+)\b/i;
export interface LegacyRevalidationStatus {
  dirty_since: number | null;
  ceiling_ms: number;
  confirmed_revision: number | null;
  deadline: number | null;
  error_count: number;
  reason: string | null;
}
export interface LegacyRevalidationState {
  db: Database;
  revision(instance: string): number;
  fingerprint(): string;
  candidates(): { instance: string; scopes: string[] }[];
  markDirty(since?: number): void;
  observePolicy(fingerprint: string, since: number): void;
  ensureDirty(): void;
  complete(instance: string, scope: string, revision: number): boolean;
  acknowledgeAttempt(instance: string, scope: string, revision: number): void;
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
interface LegacyRevalidationOptions {
  ceilingMs: number;
  now?: () => number;
  /** False only for an evaluation connection in the already-running process. */
  processBoot?: boolean;
}
const tracked = new WeakMap<Database, LegacyRevalidationState>();
export function trackLegacyScopeMutations(
  raw: Database,
  options: LegacyRevalidationOptions,
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
  options: LegacyRevalidationOptions,
): LegacyRevalidationState {
  const now = options.now ?? Date.now;
  raw.exec(`CREATE TABLE IF NOT EXISTS legacy_scope_revalidation_instances (
    instance TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0 AND revision<=9007199254740991));
    CREATE TABLE IF NOT EXISTS legacy_scope_revalidation_scopes (
    instance TEXT NOT NULL,scope TEXT NOT NULL,dirty_since INTEGER,
    ceiling_ms INTEGER NOT NULL,error_count INTEGER NOT NULL DEFAULT 0,reason TEXT,
    confirmed_revision INTEGER,attempted_revision INTEGER,
    PRIMARY KEY(instance,scope));
    CREATE TABLE IF NOT EXISTS legacy_scope_revalidation_policy (
    id INTEGER PRIMARY KEY CHECK(id=1),fingerprint TEXT NOT NULL);`);
  // Older bridge versions did not retain the revision confirmed by a clean
  // marker. Unknown revisions need recovery, not an assumed current proof.
  const columns = raw.pragma(
    "table_info(legacy_scope_revalidation_scopes)",
  ) as { name: string }[];
  for (const column of ["confirmed_revision", "attempted_revision"])
    if (!columns.some((existing) => existing.name === column))
      raw.exec(
        `ALTER TABLE legacy_scope_revalidation_scopes ADD COLUMN ${column} INTEGER`,
      );
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
    "SELECT dirty_since,ceiling_ms,confirmed_revision,dirty_since+ceiling_ms AS deadline,error_count,reason FROM legacy_scope_revalidation_scopes WHERE instance=? AND scope=?",
  );
  // A sweep is not a mutation: keep a matching clean proof clean. Recover a
  // missing marker or a stale clean marker left by an older publisher instead.
  const recover =
    raw.prepare(`INSERT INTO legacy_scope_revalidation_scopes(instance,scope,dirty_since,ceiling_ms) VALUES (?,?,?,?)
    ON CONFLICT(instance,scope) DO UPDATE SET
      dirty_since=CASE WHEN confirmed_revision IS NULL OR confirmed_revision<>? THEN COALESCE(dirty_since,excluded.dirty_since) ELSE dirty_since END,
      ceiling_ms=excluded.ceiling_ms
    WHERE (dirty_since IS NULL AND (confirmed_revision IS NULL OR confirmed_revision<>?)) OR ceiling_ms<>excluded.ceiling_ms`);
  let dirtyAt: number | null = null;
  let forceDirty = false;
  let transactionDepth = 0;
  const totalChanges = raw.prepare("SELECT total_changes()").pluck();
  const bindingTable = raw.prepare(
    "SELECT 1 FROM sqlite_master WHERE name='pdpp_instance_binding'",
  );
  let bindingsReady = false;
  let candidateQuery: Statement<[]> | undefined;
  let instanceQuery: Statement<[]> | undefined;
  function candidates() {
    if (!bindingsReady) bindingsReady = bindingTable.get() !== undefined;
    if (!bindingsReady) return [];
    candidateQuery ??=
      raw.prepare(`SELECT DISTINCT b.instance,t.scope,COALESCE(s.attempted_revision,-1) AS attempted_revision FROM legacy_scope_takeovers t
      JOIN pdpp_instance_binding b ON (t.instance=b.instance AND t.generation=b.generation) OR t.instance=''
      LEFT JOIN legacy_scope_revalidation_scopes s ON s.instance=b.instance AND s.scope=t.scope
      WHERE b.deleted_at IS NULL AND EXISTS(SELECT 1 FROM data_files f WHERE f.scope=t.scope)
      ORDER BY b.instance,attempted_revision,t.scope`);
    const rows = candidateQuery.all() as { instance: string; scope: string }[];
    const result = new Map<string, { instance: string; scopes: string[] }>();
    for (const { instance, scope } of rows) {
      const candidate = result.get(instance) ?? { instance, scopes: [] };
      candidate.scopes.push(scope);
      result.set(instance, candidate);
    }
    return [...result.values()];
  }
  function mark(since = now(), previous: ReturnType<typeof candidates> = []) {
    const affected = new Map(
      previous.map((candidate) => [
        candidate.instance,
        new Set(candidate.scopes),
      ]),
    );
    for (const candidate of candidates()) {
      const scopes = affected.get(candidate.instance) ?? new Set<string>();
      for (const scope of candidate.scopes) scopes.add(scope);
      affected.set(candidate.instance, scopes);
    }
    // Foreground selection precedes the first takeover. Fence every bound
    // instance, including those with no inventory witness or scope marker yet.
    // Keep scope discovery limited to takeovers for background scheduling.
    if (bindingsReady) {
      instanceQuery ??= raw.prepare(
        "SELECT instance FROM pdpp_instance_binding",
      );
      for (const { instance } of instanceQuery.all() as { instance: string }[])
        if (!affected.has(instance)) affected.set(instance, new Set());
    }
    for (const [instance, scopes] of affected) {
      bump.run(instance);
      for (const scope of scopes)
        dirty.run(instance, scope, since, options.ceilingMs);
    }
  }
  function atomic<T>(
    run: () => T,
    mode: "deferred" | "immediate" | "exclusive" = "immediate",
  ): T {
    const outer = transactionDepth === 0 && !raw.inTransaction;
    const checkpoint = dirtyAt;
    const forceCheckpoint = forceDirty;
    try {
      return raw
        .transaction(() => {
          const before = outer ? Number(totalChanges.get()) : 0;
          const previous = outer ? candidates() : [];
          transactionDepth++;
          try {
            const result = run();
            if (outer) {
              if (
                dirtyAt !== null &&
                (forceDirty || Number(totalChanges.get()) > before)
              )
                mark(dirtyAt, previous);
              dirtyAt = null;
              forceDirty = false;
            }
            return result;
          } finally {
            transactionDepth--;
          }
        })
        [mode]();
    } catch (error) {
      dirtyAt = checkpoint;
      forceDirty = forceCheckpoint;
      throw error;
    }
  }
  function mutate<T>(run: () => T, force = false): T {
    const write = () => {
      dirtyAt ??= now();
      forceDirty ||= force;
      return run();
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
          for (const key of ["run", "get", "all"] as const) {
            const native = statement[key].bind(statement) as (
              ...args: unknown[]
            ) => unknown;
            const autocommit = (...args: unknown[]) =>
              mutate(() => native(...args));
            Object.defineProperty(statement, key, {
              configurable: true,
              get() {
                if (transactionDepth > 0 || raw.inTransaction) {
                  // Compare total_changes at the outer boundary. Native calls
                  // need no per-record arrays, closures or proxy dispatch.
                  dirtyAt ??= now();
                  return native;
                }
                return autocommit;
              },
            });
          }
          return statement;
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
          confirmed_revision: number | null;
          deadline: number | null;
          error_count: number;
          reason: string | null;
        }
      | undefined;
  }
  if (options.processBoot !== false) {
    // An older or PDPP-disabled process may have written without this tracker.
    // Invalidate both clean inventory markers and persisted coverage cursors.
    // Never slide a dirty window that was already running before the restart.
    raw
      .transaction(() => {
        const instances = raw
          .prepare(
            "SELECT DISTINCT instance FROM legacy_scope_revalidation_scopes",
          )
          .all() as { instance: string }[];
        for (const { instance } of instances) bump.run(instance);
        raw
          .prepare(
            `UPDATE legacy_scope_revalidation_scopes SET
        dirty_since=COALESCE(dirty_since,?),ceiling_ms=?,
        error_count=CASE WHEN dirty_since IS NULL THEN 0 ELSE error_count END,
        reason=CASE WHEN dirty_since IS NULL THEN NULL ELSE reason END`,
          )
          .run(now(), options.ceilingMs);
      })
      .immediate();
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
      raw.transaction(() => mark(since)).immediate();
    },
    observePolicy(fingerprint: string, since: number) {
      fingerprint = JSON.stringify([
        LEGACY_SCOPE_WITNESS_IDENTITY,
        fingerprint,
      ]);
      raw
        .transaction(() => {
          const previous = raw
            .prepare(
              "SELECT fingerprint FROM legacy_scope_revalidation_policy WHERE id=1",
            )
            .pluck()
            .get();
          if (previous === fingerprint) return;
          mark(since);
          raw
            .prepare(
              "INSERT INTO legacy_scope_revalidation_policy VALUES (1,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint",
            )
            .run(fingerprint);
        })
        .immediate();
    },
    ensureDirty() {
      raw
        .transaction(() => {
          const since = now();
          for (const candidate of candidates()) {
            const revision = Number(readRevision.get(candidate.instance) ?? 0);
            for (const scope of candidate.scopes)
              recover.run(
                candidate.instance,
                scope,
                since,
                options.ceilingMs,
                revision,
                revision,
              );
          }
        })
        .immediate();
    },
    complete(instance: string, scope: string, revision: number) {
      if (Number(readRevision.get(instance) ?? 0) !== revision) return false;
      raw
        .prepare(
          `INSERT INTO legacy_scope_revalidation_scopes(instance,scope,dirty_since,ceiling_ms,confirmed_revision,attempted_revision) VALUES (?,?,NULL,?,?,?)
         ON CONFLICT(instance,scope) DO UPDATE SET dirty_since=NULL,error_count=0,reason=NULL,confirmed_revision=excluded.confirmed_revision,attempted_revision=excluded.attempted_revision
         WHERE dirty_since IS NOT NULL OR error_count<>0 OR reason IS NOT NULL OR confirmed_revision IS NOT excluded.confirmed_revision OR attempted_revision IS NOT excluded.attempted_revision`,
        )
        .run(instance, scope, options.ceilingMs, revision, revision);
      return true;
    },
    acknowledgeAttempt(instance: string, scope: string, revision: number) {
      // An attempt is scheduling progress, never a positive coverage proof.
      // Keep it across boot invalidation so restarts resume the unfinished tail.
      raw
        .transaction(() => {
          if (Number(readRevision.get(instance) ?? 0) !== revision) return;
          raw
            .prepare(
              "UPDATE legacy_scope_revalidation_scopes SET attempted_revision=? WHERE instance=? AND scope=?",
            )
            .run(revision, instance, scope);
        })
        .immediate();
    },
    fail(instance: string, scopes: readonly string[]) {
      const statement = raw.prepare(
        "UPDATE legacy_scope_revalidation_scopes SET error_count=error_count+1 WHERE instance=? AND scope=? AND dirty_since IS NOT NULL",
      );
      raw
        .transaction(() => {
          const since = now();
          const revision = Number(readRevision.get(instance) ?? 0);
          for (const scope of scopes) {
            recover.run(
              instance,
              scope,
              since,
              options.ceilingMs,
              revision,
              revision,
            );
            statement.run(instance, scope);
          }
        })
        .immediate();
    },
    status,
    overdue(instance: string, scope: string) {
      const row = status(instance, scope);
      return (
        row?.dirty_since !== null &&
        row?.dirty_since !== undefined &&
        // A wall-clock rollback can extend the stale window; this is accepted.
        now() >= row.deadline!
      );
    },
    diagnostics() {
      return raw
        .prepare(
          `SELECT instance,scope,dirty_since,error_count,
        CASE WHEN error_count>0 THEN 'evaluation_failing' ELSE 'evaluation_overdue' END AS reason
        FROM legacy_scope_revalidation_scopes
        WHERE dirty_since IS NOT NULL AND dirty_since+ceiling_ms<=?`,
        )
        .all(now()) as ReturnType<LegacyRevalidationState["diagnostics"]>;
    },
  };
}
