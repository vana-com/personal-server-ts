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
/** A unit stages while the workspace collects, except that the output objects
 * may also be staged once the fold is done (`folded`) and their upload receipts
 * once every output is sealed (`sealed`). */
const stagePhases = (relation: string): readonly string[] =>
  relation === "outputs"
    ? ["collect", "folded"]
    : relation === "uploads"
      ? ["collect", "sealed"]
      : ["collect"];
const phaseIn = (phases: readonly string[]) =>
  `(SELECT phase FROM workspaces WHERE operation=?) IN (${phases.map(() => "?").join(",")})`;
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
            `${phaseIn(stagePhases(relation))} AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?)`,
            [b.operation, ...stagePhases(relation), b.operation, unit],
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
      const staged = (
        await db.query<{ relation: string }>(
          "SELECT relation FROM workspace_stage WHERE operation=? AND unit=? LIMIT 1",
          [b.operation, unit],
        )
      )[0];
      const phases = stagePhases(staged?.relation ?? "");
      await write(
        [
          assert(
            `(EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=? AND digest=? AND position=?)) OR ((SELECT phase IN (${phases.map(() => "?").join(",")}) AND position=? FROM workspaces WHERE operation=?) AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?))`,
            [
              b.operation,
              unit,
              digest,
              previous + 1,
              ...phases,
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
        ["collect", "folded"] | ["folded", "sealed"] | ["sealed", "ready"]
    ) {
      // `sent` is entered by `markSent`, which records the heads `settleSent`
      // decides on; no local transition can certify a sent candidate as accepted.
      const allowed: Record<string, string> = {
        collect: "folded",
        folded: "sealed",
        sealed: "ready",
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
    /** `ready` -> `sent`, durable before the registry request leaves. Records
     * the head the request expects and the head it would install. */
    async markSent(
      position: number,
      oldHead: string | null,
      candidateHead: string,
    ) {
      const phase = await workspacePhase(db, b.operation);
      if (phase === "sent") {
        const row = (await sentRow(db, b.operation))!;
        if (
          row.position !== position ||
          row.old_head !== oldHead ||
          row.candidate_head !== candidateHead
        )
          throw new Error("workspace_sent_conflict");
        return;
      }
      await write([
        assert("(SELECT phase FROM workspaces WHERE operation=?)='ready'", [
          b.operation,
        ]),
        {
          sql: "INSERT INTO workspace_sent(operation,connection,position,old_head,candidate_head) VALUES(?,?,?,?,?)",
          params: [b.operation, b.connection, position, oldHead, candidateHead],
        },
        {
          sql: "UPDATE workspaces SET phase='sent' WHERE operation=? AND phase='ready'",
          params: [b.operation],
        },
      ]);
    },
    settleSent: (observation: SentObservation) =>
      settleSent(db, b.operation, observation),
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
    cleanupOne: () => cleanupWorkspaceOne(db, b.operation),
  };
}

async function workspacePhase(db: SqlDriver, operation: string) {
  return (
    await db.query<{ phase: string }>(
      "SELECT phase FROM workspaces WHERE operation=?",
      [operation],
    )
  )[0]?.phase;
}
async function sentRow(db: SqlDriver, operation: string) {
  return (
    await db.query<{
      connection: string;
      position: number;
      old_head: string | null;
      candidate_head: string;
    }>(
      "SELECT connection,position,old_head,candidate_head FROM workspace_sent WHERE operation=?",
      [operation],
    )
  )[0];
}
/** What a caller saw of the registry's row for the log: its version and head
 * hash (`null`, version 0: no row). It never says "accepted": the rule below
 * decides. `refused` is the registry's own definite reply to the request
 * itself, never what a later read of the head shows. */
export type SentObservation =
  | {
      readonly kind: "head";
      readonly version: number;
      readonly head: string | null;
    }
  | { readonly kind: "refused" };
export type SentSettlement = "finished" | "aborted" | "sent";
/** The request installs version `position` if the registry head is the row it
 * names (`old_head`, or none at position 1). Versions only grow, so:
 * - the candidate's own row at its version: it landed (finished);
 * - a later version, or another row at its version that an exact-head request
 *   cannot replace: it can never land (aborted; uploaded objects are orphans);
 * - the version before it, holding the expected head, or any state a landing
 *   request could still follow: stay sent. A read of the old head never ends a
 *   sent candidate. No workspace guard: the authority head has moved by then. */
function settlement(
  sent: { position: number; old_head: string | null; candidate_head: string },
  observation: SentObservation,
): SentSettlement {
  if (observation.kind === "refused") return "aborted";
  const { version, head } = observation;
  if (version > sent.position) return "aborted";
  if (version === sent.position)
    return head === sent.candidate_head
      ? "finished"
      : sent.old_head !== null
        ? "aborted"
        : "sent";
  if (version === sent.position - 1 && sent.old_head !== null)
    return head === sent.old_head ? "sent" : "aborted";
  return "sent";
}
export async function settleSent(
  db: SqlDriver,
  operation: string,
  observation: SentObservation,
): Promise<SentSettlement> {
  const phase = await workspacePhase(db, operation);
  if (phase === "finished" || phase === "aborted" || phase === "clean")
    return phase === "finished" ? "finished" : "aborted";
  if (phase !== "sent") throw new Error("workspace_not_sent");
  const to = settlement((await sentRow(db, operation))!, observation);
  if (to === "sent") return "sent";
  await db.batch([
    assert("(SELECT phase FROM workspaces WHERE operation=?)='sent'", [
      operation,
    ]),
    { sql: "DELETE FROM workspace_assert" },
    {
      sql: "UPDATE workspaces SET phase=? WHERE operation=? AND phase='sent'",
      params: [to, operation],
    },
  ]);
  return to;
}
/** Operations of a connection that were sent and not yet settled. */
export async function sentOperations(
  db: SqlDriver,
  connection: string,
): Promise<
  readonly { operation: string; position: number; candidateHead: string }[]
> {
  return (
    await db.query<{
      operation: string;
      position: number;
      candidate_head: string;
    }>(
      "SELECT s.operation,s.position,s.candidate_head FROM workspace_sent s JOIN workspaces w ON w.operation=s.operation WHERE s.connection=? AND w.phase='sent' ORDER BY s.operation",
      [connection],
    )
  ).map((r) => ({
    operation: r.operation,
    position: r.position,
    candidateHead: r.candidate_head,
  }));
}

/** One indexed row/value per call. No remote deletion and no canonical edits.
 * Needs no binding: the workspace of an earlier run is cleaned by its operation
 * id once it is aborted, finished or clean. */
export async function cleanupWorkspaceOne(
  db: SqlDriver,
  operation: string,
): Promise<boolean> {
  const phase = (
    await db.query<{ phase: string }>(
      "SELECT phase FROM workspaces WHERE operation=?",
      [operation],
    )
  )[0]?.phase;
  if (!["aborted", "finished", "clean"].includes(phase ?? ""))
    throw new Error("workspace_live_cleanup");
  for (const table of [
    "workspace_seed",
    "workspace_sent",
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
      table === "workspace_sent" || table === "workspace_partial_passes"
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
        [operation],
      )
    )[0];
    if (row) {
      await db.batch([
        {
          sql: `DELETE FROM ${table} WHERE operation=? AND ${keys.map((k) => `${k}=?`).join(" AND ")}`,
          params: [operation, ...keys.map((k) => row[k]!)],
        },
      ]);
      return true;
    }
  }
  const value = (
    await db.query<{ id: string }>(
      "SELECT id FROM body_values WHERE operation=? ORDER BY id LIMIT 1",
      [operation],
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
      params: [operation],
    },
  ]);
  return false;
}
/** One workspace of the connection that can be cleaned now, if any. */
export async function cleanableOperation(
  db: SqlDriver,
  connection: string,
): Promise<string | null> {
  return (
    (
      await db.query<{ operation: string }>(
        "SELECT operation FROM workspaces WHERE json_extract(binding,'$[2]')=? AND phase IN ('aborted','finished') ORDER BY operation LIMIT 1",
        [connection],
      )
    )[0]?.operation ?? null
  );
}

/**
 * A process that owns the database file is its only writer, so at open every
 * workspace that is not over belongs to a process that is gone: abort it and
 * page its rows and sealed values away. A `sent` workspace stays, because the
 * registry may have landed its request: only a head observation ends it
 * (`settleSent`). A progressive first load that is still collecting stays too:
 * its durable owner resumes it (`openProgressiveLogWorkspace`). The job queue
 * is per process, so every job row left is stale.
 */
export async function reclaimDeadWorkspaces(db: SqlDriver): Promise<void> {
  await db.batch([{ sql: "DELETE FROM workspace_jobs" }]);
  const dead = await db.query<{ operation: string }>(
    `SELECT w.operation FROM workspaces w
      WHERE w.phase NOT IN ('clean','sent')
        AND NOT (w.phase='collect' AND EXISTS (SELECT 1 FROM workspace_partial_passes p WHERE p.operation=w.operation))
      ORDER BY w.operation`,
  );
  for (const { operation } of dead) {
    await db.batch([
      {
        sql: "UPDATE workspaces SET phase='aborted' WHERE operation=? AND phase NOT IN ('aborted','finished','clean','sent')",
        params: [operation],
      },
    ]);
    while (await cleanupWorkspaceOne(db, operation)) {
      /* One indexed metadata row/value per call. */
    }
  }
}
