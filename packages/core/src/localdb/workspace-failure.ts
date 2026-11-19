import type { SqlDriver, SqlStatement } from "./driver.js";
import {
  workspaceBindingIdentity,
  type WorkspaceBinding,
} from "./workspace-capability.js";

export type WorkspaceFailureReason =
  "admission" | "disk-full" | "stale-authority" | "corrupt-input" | "storage";
export class WorkspaceOperationError extends Error {
  get retryable() {
    return this.reason !== "stale-authority";
  }
  constructor(
    readonly reason: WorkspaceFailureReason,
    readonly receipt: "failed" | "pending" | "unavailable",
    cause: unknown,
  ) {
    super(
      `workspace_${reason}: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
    this.name = "WorkspaceOperationError";
  }
}
export interface WorkspaceAttempt {
  readonly id: number;
  readonly unit: string;
  readonly action: string;
  readonly state: "pending" | "failed" | "succeeded";
  readonly reason: WorkspaceFailureReason | null;
}
export function failureReason(error: unknown): WorkspaceFailureReason {
  const code = (error as { code?: string })?.code,
    message = error instanceof Error ? error.message : String(error);
  if (code === "SQLITE_FULL" || /database or disk is full/i.test(message))
    return "disk-full";
  if (/admission|busy|frame_capacity|value_metadata|value_id/.test(message))
    return "admission";
  if (
    /value_binding|stale_authority|constraint.*workspace_assert|CHECK constraint failed: ok=1/.test(
      message,
    )
  )
    return "stale-authority";
  if (
    /digest|chunk_(offset|conflict|missing)|encoded data|incomplete/.test(
      message,
    )
  )
    return "corrupt-input";
  return "storage";
}
/** Intent commits first; success commits WITH the mutation. If storage cannot
 * record a failure, the pre-existing pending intent is the recovery receipt.
 * A pending intent means inspect/retry, never assume success or skip progress. */
export async function workspaceAttempt(
  db: SqlDriver,
  b: WorkspaceBinding,
  unit: string,
  action: string,
  mutation: readonly SqlStatement[],
): Promise<void> {
  if (unit.length > 1024 || action.length > 64)
    throw new WorkspaceOperationError(
      "admission",
      "unavailable",
      new Error("attempt_identity"),
    );
  const params = [b.operation, unit, action];
  try {
    await db.batch([
      {
        sql: "INSERT INTO workspace_assert SELECT CASE WHEN EXISTS(SELECT 1 FROM workspaces WHERE operation=? AND binding=?) THEN 1 ELSE 0 END",
        params: [b.operation, workspaceBindingIdentity(b)],
      },
      { sql: "DELETE FROM workspace_assert" },
      {
        sql: "INSERT OR IGNORE INTO workspace_attempts(operation,unit,action,state) VALUES(?,?,?,'pending')",
        params,
      },
      {
        sql: "UPDATE workspace_attempts SET state='pending',reason=NULL WHERE operation=? AND unit=? AND action=?",
        params,
      },
    ]);
  } catch (error) {
    throw new WorkspaceOperationError(
      failureReason(error),
      "unavailable",
      error,
    );
  }
  try {
    await db.batch([
      ...mutation,
      {
        sql: "UPDATE workspace_attempts SET state='succeeded',reason=NULL WHERE operation=? AND unit=? AND action=?",
        params,
      },
    ]);
  } catch (error) {
    const reason = failureReason(error);
    let receipt: "failed" | "pending" = "pending";
    try {
      await db.batch([
        {
          sql: "UPDATE workspace_attempts SET state='failed',reason=? WHERE operation=? AND unit=? AND action=? AND state='pending'",
          params: [reason, ...params],
        },
      ]);
      receipt = "failed";
    } catch {
      /* Pending intent was committed before the failed mutation. */
    }
    // The transport may have lost a reply AFTER the transaction committed.
    // Never overwrite the success marker atomically committed with its data.
    try {
      const [outcome] = await db.query<{ state: string }>(
        "SELECT state FROM workspace_attempts WHERE operation=? AND unit=? AND action=?",
        params,
      );
      if (outcome?.state === "succeeded") return;
      receipt = outcome?.state === "failed" ? "failed" : "pending";
    } catch {
      /* The committed intent still requires recovery when reads fail too. */
    }
    throw new WorkspaceOperationError(reason, receipt, error);
  }
}
export async function recordWorkspaceFailure(
  db: SqlDriver,
  b: WorkspaceBinding,
  unit: string,
  action: string,
  error: unknown,
): Promise<never> {
  const reason = failureReason(error);
  if (unit.length > 1024)
    throw new WorkspaceOperationError(reason, "unavailable", error);
  try {
    await db.batch([
      {
        sql: "INSERT INTO workspace_assert SELECT CASE WHEN EXISTS(SELECT 1 FROM workspaces WHERE operation=? AND binding=?) THEN 1 ELSE 0 END",
        params: [b.operation, workspaceBindingIdentity(b)],
      },
      { sql: "DELETE FROM workspace_assert" },
      {
        sql: "INSERT OR IGNORE INTO workspace_attempts(operation,unit,action,state,reason) VALUES(?,?,?,'failed',?)",
        params: [b.operation, unit, action, reason],
      },
      {
        sql: "UPDATE workspace_attempts SET state='failed',reason=? WHERE operation=? AND unit=? AND action=?",
        params: [reason, b.operation, unit, action],
      },
    ]);
  } catch {
    throw new WorkspaceOperationError(reason, "unavailable", error);
  }
  throw new WorkspaceOperationError(reason, "failed", error);
}

export const workspaceAttempts = (db: SqlDriver, b: WorkspaceBinding) => ({
  async next(after: number): Promise<WorkspaceAttempt | null> {
    return (
      (
        await db.query<
          WorkspaceAttempt & Record<string, string | number | null>
        >(
          "SELECT id,unit,action,state,reason FROM workspace_attempts WHERE operation=? AND id>? ORDER BY id LIMIT 1",
          [b.operation, after],
        )
      )[0] ?? null
    );
  },
});
