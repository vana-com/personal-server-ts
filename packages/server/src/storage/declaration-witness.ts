import { statSync } from "node:fs";
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

/** Current v11 retains connections, but not the declarations authorizing streams. */
function assertRegisteredSource(db: InstanceType<typeof Database>, sourceKey: string): void {
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
}

function assertRetainedStreamDeclaration(): void {
  // Row listings and completion receipts are not retained declarations. Neither
  // proves that an empty/unknown stream belongs to this registered connection.
  // Until the store retains that authoritative binding, no walk may pass.
  throw new OfflineDeclarationWitnessError("unverifiable_source");
}

/**
 * Validate a declaration offline, before starting the server.
 *
 * The caller supplies the exact bootstrap database path and MUST guarantee
 * exclusive use from the start of this call through the upgrade decision.
 * No shared bootstrap lock is available here: readonly is NOT a writer fence
 * or a snapshot, and this API does not detect other running server processes.
 *
 * One database and one read-port object own every continuation in this call.
 * No database is created, migrated or pruned. Missing/incompatible databases
 * throw typed errors. Only a registered source and a declared stream may pass
 * with checked: 0. The current v11 store cannot verify stream declarations,
 * so registered sources currently throw unverifiable_source, even with rows.
 *
 * The deadline is checked before and after every bounded page, including the
 * terminal page. Synchronous SQLite/JSON parsing/schema compilation cannot be
 * interrupted, so budgetMs is not a hard process timeout. A caller requiring
 * hard cancellation must use a supervised process and reap it before boot.
 * A partial result cannot be resumed across calls; rerun the entire walk.
 * The database is closed before this promise resolves or rejects.
 */
export async function runDeclarationWitness(
  options: OfflineDeclarationWitnessOptions,
): Promise<OfflineDeclarationWitnessResult> {
  const pageSize = options?.pageSize !== undefined ? options.pageSize : options?.limit;
  if (
    !options || typeof options.dbPath !== "string" || !options.dbPath ||
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
    assertRegisteredSource(db, sourceKey);
    stage = "unsupported_store";
    const store = createSqliteRecordStore(db);
    assertRetainedStreamDeclaration();
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
    if (db?.open) {
      try {
        db.close();
      } catch {
        throw new OfflineDeclarationWitnessError("close_failed");
      }
    }
  }
}
