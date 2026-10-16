import { statSync } from "node:fs";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import Database from "better-sqlite3";
import {
  DeclarationWitnessSchemaError,
  fromSyncRecordStore,
  witnessDeclarationUpgrade,
  type DeclarationWitnessResult,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

export interface OfflineDeclarationWitnessOptions {
  /** Exact existing PDPP records database path used by the caller's server. */
  dbPath: string;
  /** Existing registry file; defaults to pdpp-declarations.db beside dbPath. */
  declarationsDbPath?: string;
  /** One connection instance ID, NOT a source declaration URL. */
  sourceKey: string;
  stream: string;
  nextSchema: Record<string, unknown>;
  /** Positive safe integer. Each internal page is capped at 1,000 rows. */
  pageSize?: number;
  /** @deprecated Use pageSize. Used only when pageSize is omitted. */
  limit?: number;
  /** Finite nonnegative, cooperative wall-clock budget in milliseconds. */
  budgetMs: number;
}

export type OfflineDeclarationWitnessResult =
  Omit<DeclarationWitnessResult, "nextCursor">;

export type OfflineDeclarationWitnessErrorCode =
  | "invalid_argument"
  | "missing_database"
  | "open_failed"
  | "unsupported_store"
  | "store_unreadable"
  | "missing_source"
  | "missing_stream"
  | "unverifiable_source"
  | "invalid_schema"
  | "read_failed"
  | "close_failed";

/** Fixed, value-free errors. Native errors and their causes are never exposed. */
export class OfflineDeclarationWitnessError extends Error {
  constructor(public readonly code: OfflineDeclarationWitnessErrorCode) {
    super(`Offline declaration witness: ${code}`);
    this.name = "OfflineDeclarationWitnessError";
  }
}

function isUnreadable(error: unknown): boolean {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === "string" && (
    ["EACCES", "EPERM", "EISDIR", "EROFS", "SQLITE_CANTOPEN", "SQLITE_PERM", "SQLITE_AUTH"].includes(code) ||
    code.startsWith("SQLITE_READONLY")
  );
}

/** Binding source_id is the exact key used by declaration-registry.resolve. */
function assertRegisteredSource(db: InstanceType<typeof Database>, sourceKey: string): string {
  let binding: { source_id: string | null; deleted_at: string | null } | undefined;
  try {
    binding = db.prepare(
      "SELECT source_id, deleted_at FROM pdpp_instance_binding WHERE instance = ?",
    ).get(sourceKey) as typeof binding;
  } catch (error) {
    if (isUnreadable(error)) throw new OfflineDeclarationWitnessError("store_unreadable");
    throw new OfflineDeclarationWitnessError("unverifiable_source");
  }
  if (!binding || !binding.source_id || binding.deleted_at !== null) {
    throw new OfflineDeclarationWitnessError("missing_source");
  }
  return binding.source_id;
}

function assertRetainedStreamDeclaration(
  db: InstanceType<typeof Database>, sourceId: string, stream: string,
): void {
  try {
    // Same key and current predicate as declaration-registry.resolve; never
    // derive a source from the instance name or from a connector URI suffix.
    const rows = db.prepare(
      "SELECT snapshot_json FROM pdpp_current_declarations WHERE source_id = ? AND is_current = 1 LIMIT 2",
    ).all(sourceId) as { snapshot_json: string }[];
    if (rows.length !== 1) throw new OfflineDeclarationWitnessError("unverifiable_source");
    const snapshot: unknown = JSON.parse(rows[0]!.snapshot_json);
    if (!snapshot || typeof snapshot !== "object" ||
        !("source_id" in snapshot) || snapshot.source_id !== sourceId ||
        !("streams" in snapshot) || !Array.isArray(snapshot.streams) ||
        !snapshot.streams.every((entry: unknown) =>
          entry !== null && typeof entry === "object" &&
          "name" in entry && typeof entry.name === "string" && entry.name.length > 0)) {
      throw new OfflineDeclarationWitnessError("unverifiable_source");
    }
    if (!snapshot.streams.some((entry: { name: string }) => entry.name === stream)) {
      throw new OfflineDeclarationWitnessError("missing_stream");
    }
  } catch (error) {
    if (error instanceof OfflineDeclarationWitnessError) throw error;
    throw new OfflineDeclarationWitnessError("unverifiable_source");
  }
}

/**
 * Validate a declaration offline, before starting the server.
 *
 * The caller supplies the exact bootstrap database path and MUST guarantee
 * exclusive use of BOTH databases from the start of this call through the upgrade decision.
 * No shared bootstrap lock is available here: readonly is NOT a writer fence
 * or a snapshot, and this API does not detect other running server processes.
 *
 * Two read-only databases and one read-port own every continuation in this call.
 * No database is created, migrated or pruned. Missing/incompatible databases
 * throw typed errors. Only a registered source and a declared stream may pass
 * with checked: 0. Stream authority comes from the current declaration in the
 * separate registry; absent or malformed authority fails closed.
 *
 * The deadline is checked before and after every bounded page, including the
 * terminal page. Synchronous SQLite/JSON parsing/schema compilation cannot be
 * interrupted, so budgetMs is not a hard process timeout. A caller requiring
 * hard cancellation must use a supervised process and reap it before boot.
 * A partial result cannot be resumed across calls; rerun the entire walk.
 * Both databases are closed before this promise resolves or rejects.
 */
export async function runDeclarationWitness(
  options: OfflineDeclarationWitnessOptions,
): Promise<OfflineDeclarationWitnessResult> {
  const pageSize = options?.pageSize !== undefined ? options.pageSize : options?.limit;
  if (
    !options || typeof options.dbPath !== "string" || !options.dbPath ||
    (options.declarationsDbPath !== undefined &&
      (typeof options.declarationsDbPath !== "string" || !options.declarationsDbPath)) ||
    typeof options.sourceKey !== "string" || !options.sourceKey ||
    typeof options.stream !== "string" || !options.stream ||
    typeof pageSize !== "number" || !Number.isSafeInteger(pageSize) || pageSize <= 0 ||
    !Number.isFinite(options.budgetMs) || options.budgetMs < 0
  ) {
    throw new OfflineDeclarationWitnessError("invalid_argument");
  }

  const started = performance.now();
  const { dbPath, sourceKey, stream, budgetMs } = options;
  const limit = Math.min(pageSize, 1_000);
  let schema: Record<string, unknown>;
  try {
    // Freeze the walk's schema against caller mutations between async pages.
    schema = structuredClone(options.nextSchema);
  } catch {
    throw new OfflineDeclarationWitnessError("invalid_schema");
  }

  let db: InstanceType<typeof Database> | undefined;
  let declarationsDb: InstanceType<typeof Database> | undefined;
  let stage: OfflineDeclarationWitnessErrorCode = "open_failed";
  try {
    try {
      if (!statSync(dbPath).isFile()) {
        throw new OfflineDeclarationWitnessError("store_unreadable");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new OfflineDeclarationWitnessError("missing_database");
      }
      if (error instanceof OfflineDeclarationWitnessError) throw error;
      throw new OfflineDeclarationWitnessError(isUnreadable(error) ? "store_unreadable" : "open_failed");
    }
    db = new Database(dbPath, { readonly: true, fileMustExist: true, timeout: 0 });
    stage = "unverifiable_source";
    const sourceId = assertRegisteredSource(db, sourceKey);
    stage = "unsupported_store";
    const store = createSqliteRecordStore(db);
    stage = "unverifiable_source";
    try {
      const path = options.declarationsDbPath ?? join(dirname(dbPath), "pdpp-declarations.db");
      if (!statSync(path).isFile()) throw new Error("unavailable");
      declarationsDb = new Database(path, { readonly: true, fileMustExist: true, timeout: 0 });
    } catch {
      throw new OfflineDeclarationWitnessError("unverifiable_source");
    }
    assertRetainedStreamDeclaration(declarationsDb, sourceId, stream);
    // Witness validation uses nextSchema, never declaration registry lookups.
    const readPort = fromSyncRecordStore({ ...store, forInstance: () => undefined });
    stage = "read_failed";
    let checked = 0;
    let cursor: string | undefined;
    for (;;) {
      if (performance.now() - started >= budgetMs) {
        return { verdict: "partial", checked };
      }
      const page = await witnessDeclarationUpgrade({
        readPort, sourceKey, stream, nextSchema: schema, limit,
        ...(cursor === undefined ? {} : { cursor }),
      });
      checked += page.checked;
      if (page.verdict === "fail") {
        return { verdict: "fail", checked, failure: page.failure };
      }
      if (performance.now() - started >= budgetMs) {
        return { verdict: "partial", checked };
      }
      if (page.verdict === "pass") return { verdict: "pass", checked };
      if (!page.nextCursor) throw new OfflineDeclarationWitnessError("read_failed");
      cursor = page.nextCursor;
    }
  } catch (error) {
    if (error instanceof OfflineDeclarationWitnessError) throw error;
    throw new OfflineDeclarationWitnessError(
      isUnreadable(error) ? "store_unreadable" :
      error instanceof DeclarationWitnessSchemaError ? "invalid_schema" : stage,
    );
  } finally {
    let closeFailed = false;
    for (const handle of [declarationsDb, db]) {
      if (!handle?.open) continue;
      try {
        handle.close();
      } catch {
        closeFailed = true;
      }
    }
    if (closeFailed) throw new OfflineDeclarationWitnessError("close_failed");
  }
}
