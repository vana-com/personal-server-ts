// Indexed, lineage-bound facts for progressive replay. No decoded batch escapes
// commitPart; scan facts contain only keys, stamps and stream/batch metadata.
import {
  HEAD_FORMAT,
  type LogKey,
  type LogStamp,
  type LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver, SqlStatement } from "./driver.js";
import type { WorkspaceBinding, ByteLease } from "./workspace-capability.js";
import { checkLease, workspaceGuard, workspaceAssert } from "./workspace.js";
import { workspaceAttempt } from "./workspace-failure.js";
import {
  stageBatch,
  streamStateStatement,
  type BatchIdentity,
  type OperationBatch,
  type BatchStep,
} from "./log-batch.js";
import {
  hideStoredRows,
  partialRowStatement,
  type PartialIdentity,
} from "./partial-load.js";
import { withOrigin } from "./merge.js";
import type { LogState } from "./log-state.js";

export interface KeyFact {
  stream: string;
  pkHash: string;
  key: LogKey;
  lastNamingUnit: number;
  lastRemovalUnit: number;
  futureRemoval: LogStamp | null;
}
export interface Naming {
  meta: LogStreamMeta;
  index: number;
  batch: { generation: number; observedAt: number };
  identity: BatchIdentity;
  head: PartialIdentity;
  skip: boolean;
  begun: boolean;
}
export interface PartialPlan {
  readonly start: number;
  readonly snapshot: boolean;
  readonly total: number;
  readonly finalIdentity: BatchIdentity;
  readonly observedAt: number;
}
const MAX_METADATA = 64 * 1024;

export function workspacePartial(db: SqlDriver, b: WorkspaceBinding) {
  const read = async <T>(relation: string, key: string): Promise<T | null> => {
    await db.batch(workspaceGuard(b));
    const row = (
      await db.query<{ payload: string }>(
        "SELECT payload FROM workspace_cells WHERE operation=? AND relation=? AND key=?",
        [b.operation, relation, key],
      )
    )[0];
    return row ? (JSON.parse(row.payload) as T) : null;
  };
  const put = (relation: string, key: string, value: unknown): SqlStatement => {
    const payload = JSON.stringify(value);
    if (new TextEncoder().encode(payload + key).length > MAX_METADATA)
      throw new Error("workspace_metadata_admission");
    return {
      sql: "INSERT OR REPLACE INTO workspace_cells(operation,relation,key,payload) VALUES(?,?,?,?)",
      params: [b.operation, relation, key, payload],
    };
  };
  const write = async (unit: string, statements: SqlStatement[]) => {
    await workspaceAttempt(db, b, unit, "partial", [
      ...workspaceGuard(b),
      ...statements,
    ]);
  };
  const plan = () => read<PartialPlan>("partial-plan", "plan");
  const naming = async (stream: string) => {
    await db.batch(workspaceGuard(b));
    const row = (
      await db.query<{ payload: string }>(
        "SELECT payload FROM workspace_partial_streams WHERE operation=? AND stream=?",
        [b.operation, stream],
      )
    )[0];
    return row ? (JSON.parse(row.payload) as Naming) : null;
  };
  const key = async (stream: string, pk: string): Promise<KeyFact | null> => {
    await db.batch(workspaceGuard(b));
    const row = (
      await db.query<{
        typed_key: string;
        last_naming: number;
        last_removal: number;
        removal_o: number | null;
        removal_r: string | null;
      }>(
        "SELECT typed_key,last_naming,last_removal,removal_o,removal_r FROM workspace_partial_keys WHERE operation=? AND stream=? AND pk_hash=?",
        [b.operation, stream, pk],
      )
    )[0];
    return row
      ? {
          stream,
          pkHash: pk,
          key: JSON.parse(row.typed_key),
          lastNamingUnit: row.last_naming,
          lastRemovalUnit: row.last_removal,
          futureRemoval:
            row.removal_o === null
              ? null
              : { o: row.removal_o, r: row.removal_r! },
        }
      : null;
  };
  const putNaming = (row: Naming): SqlStatement => {
    const payload = JSON.stringify(row);
    if (new TextEncoder().encode(payload).length > MAX_METADATA)
      throw new Error("workspace_metadata_admission");
    return {
      sql: "INSERT OR REPLACE INTO workspace_partial_streams VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
      params: [
        b.operation,
        row.meta.stream,
        payload,
        JSON.stringify(row.meta.primaryKey),
        row.meta.profile.key,
        row.meta.profile.version,
        row.meta.complete ? 1 : 0,
        row.batch.generation,
        row.batch.observedAt,
        row.identity.dataHash,
        row.identity.blobName,
        row.skip ? 1 : 0,
        row.head.version,
      ],
    };
  };
  return {
    plan,
    async initialize(value: PartialPlan) {
      const old = await plan();
      if (old && JSON.stringify(old) !== JSON.stringify(value))
        throw new Error("workspace_partial_plan_conflict");
      if (!old) await write("plan", [put("partial-plan", "plan", value)]);
    },
    key,
    async held(stream: string, pk: string, index: number) {
      return ((await key(stream, pk))?.lastRemovalUnit ?? -1) > index;
    },
    async noteKey(
      index: number,
      stream: string,
      pkHash: string,
      typedKey: LogKey,
      removal: LogStamp | null,
    ) {
      const old = await key(stream, pkHash);
      const laterRemoval =
        removal !== null && index >= (old?.lastRemovalUnit ?? -1);
      const encodedKey = JSON.stringify(typedKey);
      if (
        new TextEncoder().encode(encodedKey + stream + pkHash).length >
        MAX_METADATA
      )
        throw new Error("workspace_metadata_admission");
      const lastRemoval = laterRemoval ? removal : (old?.futureRemoval ?? null);
      await write("key", [
        {
          sql: "INSERT OR REPLACE INTO workspace_partial_keys VALUES(?,?,?,?,?,?,?,?)",
          params: [
            b.operation,
            stream,
            pkHash,
            encodedKey,
            Math.max(old?.lastNamingUnit ?? -1, index),
            laterRemoval ? index : (old?.lastRemovalUnit ?? -1),
            lastRemoval?.o ?? null,
            lastRemoval?.r ?? null,
          ],
        },
      ]);
    },
    /** List before fetching; subsequent names replace only the last-name facts. */
    async name(
      index: number,
      meta: LogStreamMeta,
      batch: Naming["batch"],
      identity: BatchIdentity,
      list = false,
    ) {
      const old = await naming(meta.stream);
      let row: Naming;
      if (old)
        row =
          index > old.index ? { ...old, meta, index, batch, identity } : old;
      else {
        const p = await plan();
        if (!p) throw new Error("workspace_partial_plan_missing");
        const state = (
          await db.query<{
            complete: number;
            head_generation: number;
            head_version: number;
            last_delete_version: number;
          }>(
            "SELECT complete,head_generation,head_version,last_delete_version FROM stream_state WHERE connection_id=? AND stream=?",
            [b.connection, meta.stream],
          )
        )[0];
        const version =
          Math.max(state?.head_version ?? 0, state?.last_delete_version ?? 0) +
          1;
        const head: PartialIdentity = {
          connectionId: b.connection,
          stream: meta.stream,
          version,
          generation: b.generation,
          dataHash: p.finalIdentity.dataHash,
          headBlob: p.finalIdentity.blobName,
          observedAt: p.observedAt,
        };
        const marker = (
          await db.query<{
            data_hash: string;
            generation: number;
            version: number;
          }>(
            "SELECT data_hash,generation,version FROM stream_partial WHERE connection_id=? AND stream=?",
            [b.connection, meta.stream],
          )
        )[0];
        row = {
          meta,
          index,
          batch,
          identity,
          head,
          skip:
            state?.complete === 1 &&
            state.head_generation === b.generation &&
            state.head_version > state.last_delete_version,
          begun:
            marker?.data_hash === head.dataHash &&
            marker.generation === head.generation &&
            marker.version === head.version,
        };
      }
      const statements: SqlStatement[] = [];
      if (list && !row.skip && !row.begun) {
        statements.push(
          streamStateStatement(b.connection, meta),
          ...hideStoredRows(b.connection, meta.stream),
          partialRowStatement(row.head, 0, (await plan())!.total, 0),
        );
        row = { ...row, begun: true };
      }
      statements.push(putNaming(row));
      await write("name", statements);
    },
    async scanned(index: number, identity: BatchIdentity) {
      const old = await read<BatchIdentity>("partial-parts", String(index));
      if (old && JSON.stringify(old) !== JSON.stringify(identity))
        throw new Error("workspace_partial_digest_conflict");
      if (!old)
        await write("scan", [put("partial-parts", String(index), identity)]);
    },
    async hasScan(index: number, identity: BatchIdentity) {
      const old = await read<BatchIdentity>("partial-parts", String(index));
      if (old && JSON.stringify(old) !== JSON.stringify(identity))
        throw new Error("workspace_partial_digest_conflict");
      return old !== null;
    },
    async applied(index: number, identity: BatchIdentity) {
      const row = (
        await db.query<{ digest: string }>(
          "SELECT digest FROM workspace_receipts WHERE operation=? AND unit=?",
          [b.operation, `partial-${index}`],
        )
      )[0];
      if (row && row.digest !== identity.dataHash)
        throw new Error("workspace_partial_digest_conflict");
      await db.batch(workspaceGuard(b));
      return row !== undefined;
    },
    /** Body, visibility, truthful markers, cursor and receipt are one transaction.
     * The caller retains its single input lease through this awaited commit. */
    async commitPart(
      index: number,
      batch: OperationBatch,
      identity: BatchIdentity,
      newOp: () => string,
      lease: ByteLease,
      state?: LogState,
    ) {
      checkLease(lease, b.operation, 1);
      const p = (await plan())!;
      if (!p || index < 0 || index >= p.total)
        throw new Error("workspace_partial_index");
      if (await this.applied(index, identity)) return;
      const steps = new Map<string, BatchStep>();
      const before: SqlStatement[] = [];
      const after: SqlStatement[] = [];
      for (const meta of batch.streams) {
        const row = await naming(meta.stream);
        if (!row) throw new Error("workspace_partial_name_missing");
        if (row.skip) continue;
        if (!row.begun)
          before.push(...hideStoredRows(b.connection, meta.stream));
        // Final heads are promoted set-wise, including streams absent in this part.
        steps.set(meta.stream, {
          begin: false,
          final: false,
          held: [],
          holdback: { operation: b.operation, index },
          row: {
            head: row.head,
            applied: Math.min(index + 1, p.total - 1),
            total: p.total,
          },
        });
        after.push(putNaming({ ...row, begun: true }));
      }
      const staged = await stageBatch(
        { newOp },
        b.connection,
        batch,
        identity,
        state,
        steps,
      );
      // Both the scan receipt and the immediately preceding applied receipt must exist.
      before.push(
        workspaceAssert(
          "EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation='partial-parts' AND key=?) AND (SELECT COUNT(*) FROM workspace_cells WHERE operation=? AND relation='partial-parts')=? AND (?=0 OR EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?))",
          [
            b.operation,
            String(index),
            b.operation,
            p.total,
            index,
            b.operation,
            `partial-${index - 1}`,
          ],
        ),
      );
      if (index === p.total - 1) after.push(...finishStatements(b));
      after.push({
        sql: "INSERT INTO workspace_receipts(operation,unit,digest,position) VALUES(?,?,?,?)",
        params: [b.operation, `partial-${index}`, identity.dataHash, index + 1],
      });
      try {
        await write(
          `part-${index}`,
          withOrigin("remote", [...before, ...staged.statements, ...after]),
        );
      } finally {
        await db.batch([
          { sql: "DELETE FROM temp.incoming WHERE op=?", params: [staged.op] },
        ]);
      }
    },
    async failed(code: string, hide = false) {
      const p = await plan();
      if (!p) return;
      const statements: SqlStatement[] = [];
      if (hide)
        statements.push({
          sql: "INSERT OR IGNORE INTO partial_hidden SELECT r.connection_id,r.stream,r.pk_hash FROM records r JOIN stream_partial p ON p.connection_id=r.connection_id AND p.stream=r.stream WHERE p.connection_id=? AND p.data_hash=?",
          params: [b.connection, p.finalIdentity.dataHash],
        });
      statements.push({
        sql: "UPDATE stream_partial SET failed=1,last_error=? WHERE connection_id=? AND generation=? AND data_hash=?",
        params: [code, b.connection, b.generation, p.finalIdentity.dataHash],
      });
      await write("failure", statements);
    },
  };
}

/** No stream-sized result/statement list crosses the driver. Indexed facts drive
 * the canonical promotions in the final part's transaction. */
function finishStatements(b: WorkspaceBinding): SqlStatement[] {
  const select = (column: string) =>
    `(SELECT w.${column} FROM workspace_partial_streams w WHERE w.operation=? AND w.stream=stream_state.stream)`;
  return [
    {
      sql: `INSERT OR REPLACE INTO stream_versions(connection_id,stream,version,generation,head_blob,head_format,record_count,observed_at,complete,kind,primary_key,profile_key,profile_version)
      SELECT ?,w.stream,MAX(s.head_version,s.last_delete_version)+1,w.generation,w.blob_name,${HEAD_FORMAT},
      (SELECT COUNT(*) FROM records r WHERE r.connection_id=s.connection_id AND r.stream=s.stream),w.observed_at,w.complete,'applied',w.primary_key,w.profile_key,w.profile_version
      FROM workspace_partial_streams w JOIN stream_state s ON s.connection_id=? AND s.stream=w.stream WHERE w.operation=? AND w.skip=0`,
      params: [b.connection, b.connection, b.operation],
    },
    {
      sql: `UPDATE stream_state SET primary_key=${select("primary_key")},profile_key=${select("profile_key")},profile_version=${select("profile_version")},complete=${select("complete")},head_generation=${select("generation")},head_data_hash=${select("data_hash")},head_blob=${select("blob_name")},head_version=MAX(head_version,last_delete_version)+1
      WHERE connection_id=? AND stream IN (SELECT stream FROM workspace_partial_streams WHERE operation=? AND skip=0)`,
      params: [
        b.operation,
        b.operation,
        b.operation,
        b.operation,
        b.operation,
        b.operation,
        b.operation,
        b.connection,
        b.operation,
      ],
    },
    {
      sql: "DELETE FROM stream_partial WHERE connection_id=? AND stream IN (SELECT stream FROM workspace_partial_streams WHERE operation=? AND skip=0)",
      params: [b.connection, b.operation],
    },
  ];
}
export const PARTIAL_WORKSPACE_SCHEMA = [
  `CREATE TABLE workspace_partial_keys(operation TEXT NOT NULL,stream TEXT NOT NULL,pk_hash TEXT NOT NULL,typed_key TEXT NOT NULL,last_naming INTEGER NOT NULL,last_removal INTEGER NOT NULL,removal_o INTEGER,removal_r TEXT,PRIMARY KEY(operation,stream,pk_hash)) WITHOUT ROWID`,
  `CREATE TABLE workspace_partial_streams(operation TEXT NOT NULL,stream TEXT NOT NULL,payload TEXT NOT NULL,primary_key TEXT NOT NULL,profile_key TEXT,profile_version TEXT NOT NULL,complete INTEGER NOT NULL,generation INTEGER NOT NULL,observed_at INTEGER NOT NULL,data_hash TEXT NOT NULL,blob_name TEXT NOT NULL,skip INTEGER NOT NULL,partial_version INTEGER NOT NULL,PRIMARY KEY(operation,stream)) WITHOUT ROWID`,
];
