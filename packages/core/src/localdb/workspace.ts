import {
  workspaceAttempt,
  recordWorkspaceFailure,
} from "./workspace-failure.js";
import type { SqlDriver, SqlStatement } from "./driver.js";
import type {
  BoundedCursor,
  ByteLease,
  WorkspaceBinding,
} from "./workspace-capability.js";

import { workspaceBindingIdentity as bindingIdentity } from "./workspace-capability.js";
export { bindingIdentity };
const assert = (
  condition: string,
  params: SqlStatement["params"],
): SqlStatement => ({
  sql: `INSERT INTO workspace_assert SELECT CASE WHEN ${condition} THEN 1 ELSE 0 END`,
  params,
});
export function workspaceGuard(b: WorkspaceBinding): SqlStatement[] {
  return [
    assert(
      `EXISTS(SELECT 1 FROM workspaces w JOIN connections c ON c.connection_id=? JOIN db_meta m ON m.id=1 JOIN workspace_authority a ON a.connection=c.connection_id WHERE w.operation=? AND w.binding=? AND w.phase NOT IN ('aborted','clean','finished') AND c.control_state IN ('active',?) AND c.generation=? AND m.owner=? AND a.incarnation=? AND a.key_check=? AND a.head=?)`,
      [
        b.connection,
        b.operation,
        bindingIdentity(b),
        b.controlState ?? "active",
        b.generation,
        b.owner,
        b.databaseIncarnation,
        b.keyCheck,
        b.expectedHead,
      ],
    ),
    { sql: "DELETE FROM workspace_assert" },
  ];
}
export const workspaceAssert = assert;

/** Local observed binding, not evidence that a remote publication landed. */
export async function readWorkspaceAuthority(
  db: SqlDriver,
  connection: string,
) {
  const [row] = await db.query<{
    incarnation: string;
    key_check: string;
    head: string;
  }>(
    "SELECT incarnation,key_check,head FROM workspace_authority WHERE connection=?",
    [connection],
  );
  return row
    ? {
        databaseIncarnation: row.incarnation,
        keyCheck: row.key_check,
        expectedHead: row.head,
      }
    : null;
}

/** Trusted host must update this alongside a newly observed key/incarnation/head.
 * This does not contact or authorize a remote registry. Connection deletion and
 * generation are additionally checked against canonical state in every write.
 */
export async function setWorkspaceAuthority(
  db: SqlDriver,
  b: WorkspaceBinding,
): Promise<void> {
  await db.batch([
    {
      sql: "INSERT OR REPLACE INTO workspace_authority VALUES(?,?,?,?)",
      params: [b.connection, b.databaseIncarnation, b.keyCheck, b.expectedHead],
    },
  ]);
}

const activeLeases = new WeakMap<
  ByteLease,
  { released: boolean; owned: boolean }
>();
let current: ByteLease | undefined;
/** A lease is an accounting cap, not an allocation. A record may be as large as
 * the protocol allows (512 MiB), and its admission is six times its size, so the
 * ceiling must cover that or a legal record could never publish. */
export const LEASE_CEILING_BYTES = 4 * 1024 * 1024 * 1024;
const waiters: (() => void)[] = [];
export function checkLease(
  lease: ByteLease,
  operation: string,
  bytes: number,
): void {
  if (
    current !== lease ||
    !activeLeases.has(lease) ||
    activeLeases.get(lease)!.released ||
    lease.operation !== operation ||
    !Number.isSafeInteger(bytes) ||
    bytes < 0 ||
    bytes > lease.capacityBytes
  )
    throw new Error("workspace_admission");
}
export function assertNoOwnedUnit(operation: string): void {
  if (current?.operation === operation && activeLeases.get(current)?.owned)
    throw new Error("workspace_unit_owned");
}
/** Reserve the sole unit before reading/allocating; release the unit before its lease. */
export function ownLease(
  lease: ByteLease,
  operation: string,
  bytes: number,
): () => void {
  checkLease(lease, operation, bytes);
  const state = activeLeases.get(lease)!;
  if (state.owned) throw new Error("workspace_unit_owned");
  state.owned = true;
  let released = false;
  return () => {
    if (!released) {
      released = true;
      state.owned = false;
    }
  };
}
/** One runtime-wide owner, no promise queue. A busy caller persists its id and
 * returns to the scheduler; it must not retain decoded candidates while waiting. */
export const runtimeAdmission = {
  async acquire(
    operation: string,
    bytes: number,
    signal?: AbortSignal,
  ): Promise<ByteLease> {
    if (signal?.aborted) throw new Error("workspace_cancelled");
    if (
      !Number.isSafeInteger(bytes) ||
      bytes <= 0 ||
      bytes > LEASE_CEILING_BYTES
    )
      throw new Error("workspace_admission");
    if (current) throw new Error("workspace_busy");
    const state = { released: false, owned: false };
    const lease: ByteLease = {
      operation,
      capacityBytes: bytes,
      async release() {
        if (state.owned) throw new Error("workspace_unit_owned");
        state.released = true;
        if (current === lease) {
          current = undefined;
          waiters.shift()?.();
        }
      },
    };
    activeLeases.set(lease, state);
    current = lease;
    return lease;
  },
  /** Wait for the owner instead of failing as busy. Nothing is held while
   * waiting but a resolver, and the caller has decoded nothing yet. Waiters are
   * woken in arrival order, so one connection cannot starve the others of a
   * cycle. Never call it while holding a lease: that waits on itself. */
  async acquireWaiting(
    operation: string,
    bytes: number,
    signal?: AbortSignal,
  ): Promise<ByteLease> {
    for (;;) {
      if (signal?.aborted) throw new Error("workspace_cancelled");
      if (!current) return runtimeAdmission.acquire(operation, bytes, signal);
      await new Promise<void>((resolve) => {
        waiters.push(resolve);
        signal?.addEventListener("abort", () => resolve(), { once: true });
      });
    }
  },
  async enqueue(db: SqlDriver, job: string) {
    if (job.length > 256 || encodedSize(job) > 256)
      throw new Error("workspace_job_admission");
    await db.batch([
      {
        sql: "INSERT OR IGNORE INTO workspace_jobs(job) VALUES(?)",
        params: [job],
      },
    ]);
  },
  async nextWaiting(db: SqlDriver, after: number) {
    return (
      (
        await db.query<{ id: number; job: string }>(
          "SELECT id,job FROM workspace_jobs WHERE id>? ORDER BY id LIMIT 1",
          [after],
        )
      )[0] ?? null
    );
  },
  async finish(db: SqlDriver, job: string) {
    await db.batch([
      { sql: "DELETE FROM workspace_jobs WHERE job=?", params: [job] },
    ]);
  },
};
export type WorkspaceRelation =
  | "fold"
  | "streams"
  | "changes"
  | "replacement-membership"
  | "replacement"
  | "publication"
  | "membership"
  | "omissions"
  | "outputs"
  | "uploads"
  | "seed"
  | "partial";
export interface WorkspaceCell {
  readonly key: string;
  readonly payload: string;
}
const encodedSize = (s: string) => new TextEncoder().encode(s).length;

export async function openWorkspace(db: SqlDriver, b: WorkspaceBinding) {
  if (!db.info.persistent)
    throw new Error("workspace_requires_persistent_database");
  if (
    b.controlState === "absent" &&
    (b.generation !== 1 || b.expectedHead !== "null")
  )
    throw new Error("workspace_control_creation_binding");
  const id = bindingIdentity(b);
  if (id.length > 1024 || encodedSize(id) > 1024)
    throw new Error("workspace_binding_admission");
  await db.batch([
    {
      sql: "INSERT OR IGNORE INTO workspace_authority VALUES(?,?,?,?)",
      params: [b.connection, b.databaseIncarnation, b.keyCheck, b.expectedHead],
    },
    {
      sql: "INSERT OR IGNORE INTO workspaces(operation,binding) VALUES(?,?)",
      params: [b.operation, id],
    },
    ...workspaceGuard(b),
  ]);
  const write = async (
    statements: SqlStatement[],
    unit?: string,
    action?: string,
  ) => {
    const mutation = [...workspaceGuard(b), ...statements];
    if (unit && action) await workspaceAttempt(db, b, unit, action, mutation);
    else await db.batch(mutation);
  };
  return {
    binding: b,
    async position() {
      return (
        await db.query<{ position: number }>(
          "SELECT position FROM workspaces WHERE operation=? AND binding=?",
          [b.operation, id],
        )
      )[0]!.position;
    },
    /** Metadata only. Bodies are value tokens. One unit's proposed cell mutations
     * remain invisible until commitUnit; consumers own fold comparisons. */
    async stage(
      unit: string,
      relation: WorkspaceRelation,
      key: string,
      payload: string,
    ) {
      if (
        key.length + payload.length > 64 * 1024 ||
        unit.length > 1024 ||
        encodedSize(key) + encodedSize(payload) > 64 * 1024
      )
        return recordWorkspaceFailure(
          db,
          b,
          unit,
          "stage",
          new Error("workspace_metadata_admission"),
        );
      await write(
        [
          assert(
            "(SELECT phase FROM workspaces WHERE operation=?)='collect' AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?)",
            [b.operation, b.operation, unit],
          ),
          {
            sql: "INSERT OR REPLACE INTO workspace_stage VALUES(?,?,?,?,?)",
            params: [b.operation, unit, relation, key, payload],
          },
        ],
        unit,
        "stage",
      );
    },
    async commitUnit(unit: string, digest: string, previous: number) {
      if (
        unit.length > 1024 ||
        digest.length > 256 ||
        !Number.isSafeInteger(previous) ||
        previous < 0 ||
        previous >= Number.MAX_SAFE_INTEGER
      )
        throw new Error("workspace_receipt_admission");
      await write(
        [
          assert(
            "(EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=? AND digest=? AND position=?)) OR ((SELECT phase='collect' AND position=? FROM workspaces WHERE operation=?) AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?))",
            [
              b.operation,
              unit,
              digest,
              previous + 1,
              previous,
              b.operation,
              b.operation,
              unit,
            ],
          ),
          {
            sql: "INSERT OR REPLACE INTO workspace_cells SELECT operation,relation,key,payload FROM workspace_stage WHERE operation=? AND unit=? AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?)",
            params: [b.operation, unit, b.operation, unit],
          },
          {
            sql: "INSERT OR IGNORE INTO workspace_receipts VALUES(?,?,?,?)",
            params: [b.operation, unit, digest, previous + 1],
          },
          {
            sql: "UPDATE workspaces SET position=MAX(position,?) WHERE operation=?",
            params: [previous + 1, b.operation],
          },
          {
            sql: "DELETE FROM workspace_stage WHERE operation=? AND unit=?",
            params: [b.operation, unit],
          },
        ],
        unit,
        "promote",
      );
    },
    async lookup(
      unit: string,
      relation: WorkspaceRelation,
      key: string,
      lease: ByteLease,
    ) {
      const release = ownLease(lease, b.operation, 64 * 1024 * 24);
      try {
        await db.batch(workspaceGuard(b));
        const row = (
          await db.query<{ payload: string }>(
            `SELECT payload FROM workspace_stage WHERE operation=? AND unit=? AND relation=? AND key=?
           UNION ALL SELECT payload FROM workspace_cells WHERE operation=? AND relation=? AND key=? LIMIT 1`,
            [b.operation, unit, relation, key, b.operation, relation, key],
          )
        )[0];
        return row?.payload ?? null;
      } finally {
        release();
      }
    },
    cursor(relation: WorkspaceRelation): BoundedCursor<WorkspaceCell> {
      let after: string | null = null,
        owned = false,
        closed = false;
      let releaseUnit: (() => void) | undefined;
      return {
        async next(lease) {
          if (closed || owned)
            throw new Error("workspace_cursor_owned_or_closed");
          releaseUnit = ownLease(lease, b.operation, 64 * 1024 * 24);
          owned = true;
          try {
            await db.batch(workspaceGuard(b));
            const where = after === null ? "" : " AND key>?";
            const row = (
              await db.query<{ key: string; payload: string }>(
                `SELECT key,payload FROM workspace_cells WHERE operation=? AND relation=?${where} ORDER BY key LIMIT 1`,
                after === null
                  ? [b.operation, relation]
                  : [b.operation, relation, after],
              )
            )[0];
            if (!row) {
              releaseUnit();
              owned = false;
              return null;
            }
            const bytes = encodedSize(JSON.stringify(row));
            checkLease(lease, b.operation, bytes * 6);
            owned = true;
            after = row.key;
            const release = releaseUnit;
            let released = false;
            return {
              value: row,
              encodedBytes: bytes,
              async release() {
                if (!released) {
                  released = true;
                  owned = false;
                  release();
                }
              },
            };
          } catch (error) {
            releaseUnit?.();
            owned = false;
            throw error;
          }
        },
        async close() {
          closed = true;
          owned = false;
          releaseUnit?.();
        },
      };
    },
    async transition(
      ...[from, to]:
        | ["collect", "folded"]
        | ["folded", "sealed"]
        | ["sealed", "ready"]
        | ["ready", "sent"]
    ) {
      // Remote acceptance requires authoritative registry-outcome integration.
      // No local transition can certify a sent candidate as accepted.
      const allowed: Record<string, string> = {
        collect: "folded",
        folded: "sealed",
        sealed: "ready",
        ready: "sent",
      };
      if (allowed[from] !== to)
        throw new Error("workspace_transition_requires_authority");
      await write([
        assert("(SELECT phase FROM workspaces WHERE operation=?)=?", [
          b.operation,
          from,
        ]),
        ...(to === "ready"
          ? [
              assert(
                "NOT EXISTS(SELECT 1 FROM workspace_cells o WHERE o.operation=? AND o.relation='outputs' AND NOT EXISTS(SELECT 1 FROM workspace_cells u WHERE u.operation=o.operation AND u.relation='uploads' AND u.key=o.key AND u.payload=o.payload))",
                [b.operation],
              ),
            ]
          : []),
        {
          sql: "UPDATE workspaces SET phase=? WHERE operation=?",
          params: [to, b.operation],
        },
      ]);
    },
    async discard() {
      // An authority read or local fence does not cancel an in-flight CAS.
      // Keep sent work and its bytes until remote outcome reconciliation exists.
      await db.batch([
        assert(
          "EXISTS(SELECT 1 FROM workspaces WHERE operation=? AND binding=? AND phase<>'sent')",
          [b.operation, id],
        ),
        { sql: "DELETE FROM workspace_assert" },
        {
          sql: "UPDATE workspaces SET phase='aborted' WHERE operation=? AND binding=? AND phase NOT IN ('clean','sent')",
          params: [b.operation, id],
        },
      ]);
    },
    /** One indexed row/value per call. No remote deletion and no canonical edits. */
    async cleanupOne(): Promise<boolean> {
      const phase = (
        await db.query<{ phase: string }>(
          "SELECT phase FROM workspaces WHERE operation=? AND binding=?",
          [b.operation, id],
        )
      )[0]?.phase;
      if (!["aborted", "finished", "clean"].includes(phase ?? ""))
        throw new Error("workspace_live_cleanup");
      for (const table of [
        "workspace_seed",
        "workspace_partial_passes",
        "workspace_partial_incoming",
        "workspace_partial_deletions",
        "workspace_partial_keys",
        "workspace_partial_streams",
        "workspace_stage",
        "workspace_cells",
        "workspace_receipts",
        "workspace_attempts",
      ]) {
        const keys =
          table === "workspace_partial_passes"
            ? ["connection"]
            : table === "workspace_partial_incoming" ||
                table === "workspace_partial_deletions"
              ? ["op", "stream", "pk_hash"]
              : table === "workspace_seed" || table === "workspace_partial_keys"
                ? ["stream", "pk_hash"]
                : table === "workspace_partial_streams"
                  ? ["stream"]
                  : table === "workspace_stage"
                    ? ["unit", "relation", "key"]
                    : table === "workspace_cells"
                      ? ["relation", "key"]
                      : table === "workspace_attempts"
                        ? ["unit", "action"]
                        : ["unit"];
        const row = (
          await db.query<Record<string, string>>(
            `SELECT ${keys.join(",")} FROM ${table} WHERE operation=? ORDER BY ${keys.join(",")} LIMIT 1`,
            [b.operation],
          )
        )[0];
        if (row) {
          await db.batch([
            {
              sql: `DELETE FROM ${table} WHERE operation=? AND ${keys.map((k) => `${k}=?`).join(" AND ")}`,
              params: [b.operation, ...keys.map((k) => row[k]!)],
            },
          ]);
          return true;
        }
      }
      const value = (
        await db.query<{ id: string }>(
          "SELECT id FROM body_values WHERE operation=? ORDER BY id LIMIT 1",
          [b.operation],
        )
      )[0];
      if (value) {
        const chunk = (
          await db.query<{ offset: number }>(
            "SELECT offset FROM body_value_chunks WHERE value_id=? ORDER BY offset LIMIT 1",
            [value.id],
          )
        )[0];
        await db.batch([
          chunk
            ? {
                sql: "DELETE FROM body_value_chunks WHERE value_id=? AND offset=?",
                params: [value.id, chunk.offset],
              }
            : { sql: "DELETE FROM body_values WHERE id=?", params: [value.id] },
        ]);
        return true;
      }
      await db.batch([
        {
          sql: "UPDATE workspaces SET phase='clean' WHERE operation=?",
          params: [b.operation],
        },
      ]);
      return false;
    },
  };
}
