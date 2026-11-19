import { stageWorkspaceSeed, promoteWorkspaceSeed } from "./workspace-seed.js";
import type { LogState } from "./log-state.js";
import type { LogEntry } from "@opendatalabs/personal-server-ts-stream-sync";
import { SEEN_BEFORE, seenBeforeParams } from "./merge.js";
import { ELIGIBLE_CHANGE } from "./publication-work.js";
import { workspaceAttempt } from "./workspace-failure.js";
import { workspacePartial } from "./workspace-partial.js";
import { recordWorkspaceFailure } from "./workspace-failure.js";
import { runtimeAdmission } from "./workspace.js";
import type {
  LogKey,
  LogStamp,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlValue, SqlDriver } from "./driver.js";
import type {
  BoundedCursor,
  BoundedValueStore,
  ByteLease,
  OwnedUnit,
  ValueToken,
  WorkspaceBinding,
} from "./workspace-capability.js";
import {
  assertNoOwnedUnit,
  checkLease,
  ownLease,
  bindingIdentity,
  openWorkspace,
  workspaceAssert,
  workspaceGuard,
} from "./workspace.js";

export interface WorkspaceCanonicalRecord {
  readonly pk_hash: string;
  readonly stamp_o: number;
  readonly stamp_r: string;
  readonly stamp_n: number;
  readonly first_o: number | null;
  readonly body: string;
}
export interface WorkspaceCanonicalChange {
  readonly pk: string;
  readonly seq: number;
  readonly recordBytes: number;
  readonly record: WorkspaceCanonicalRecord | null;
}
export interface WorkspaceChangePage {
  readonly recordCount: number;
  records(): Generator<WorkspaceCanonicalChange>;
}
function decodeHex(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}
export interface WorkspaceRecordKey {
  readonly stream: string;
  readonly pkHash: string;
  /** Canonical primary-key tuple in declared field order, including upsert-only cells. */
  readonly key: LogKey;
}
export interface WorkspaceDeletion {
  readonly stamp: LogStamp;
  readonly explicit: boolean;
  readonly key: LogKey;
}
export interface WorkspaceUpsert {
  readonly stamp: LogStamp;
  readonly ordinal: number;
  readonly firstSeen: number | null;
  readonly body: ValueToken;
  readonly source?: ValueToken;
}
/** Keep both maxima. The fold consumer owns their comparator and resurrection emission. */
export interface WorkspaceFoldCell extends WorkspaceRecordKey {
  readonly upsert: WorkspaceUpsert | null;
  readonly deletion: WorkspaceDeletion | null;
}
export interface WorkspaceRows {
  fold: WorkspaceFoldCell;
  streams: { readonly stream: string; readonly metadata: ValueToken };
  partial: WorkspaceRecordKey & {
    readonly lastNamingUnit: number;
    readonly futureRemoval: LogStamp | null;
    readonly held: boolean;
  };
  publication: {
    readonly stream: string;
    readonly watermark: number;
    readonly from: string | null;
    readonly to: string | null;
    readonly completesAfterPublish: boolean;
  } & (
    | { readonly published: false; readonly complete: false }
    | { readonly published: true; readonly complete: boolean }
  );
  membership: WorkspaceRecordKey & { readonly changed: boolean };
  omissions: WorkspaceRecordKey & {
    readonly cutoff: LogStamp;
    readonly fragment: number;
    readonly published: boolean;
  };
  outputs: { readonly objectKey: string; readonly value: ValueToken };
  uploads: { readonly objectKey: string; readonly value: ValueToken };
  seed: WorkspaceFoldCell;
}
export type WorkspaceRowKind = keyof WorkspaceRows;
export interface ReceiptedWorkspaceUnit {
  readonly state: "receipted";
  readonly unit: string;
  readonly digest: string;
  readonly position: number;
}
export interface StagingWorkspaceUnit {
  readonly state: "staging";
  stage<K extends WorkspaceRowKind>(
    kind: K,
    row: WorkspaceRows[K],
  ): Promise<void>;
  stageOmissions(rows: readonly WorkspaceRows["omissions"][]): Promise<void>;
  commit(): Promise<ReceiptedWorkspaceUnit>;
}
/** A reader has no append/seal/abort methods. The token remains bound to its operation. */
export interface WorkspaceValueReader {
  readonly token: ValueToken;
  read(offset: number, lease: ByteLease): Promise<OwnedUnit<Uint8Array>>;
}
export const workspaceValueReader = (
  store: BoundedValueStore,
  token: ValueToken,
): WorkspaceValueReader => ({
  token,
  read: (offset, lease) => store.read(token, offset, lease),
});

/** Order strings by JavaScript UTF-16 code units, including escapes and prefixes. */
export function foldCellKey(stream: string, pkHash?: string): string {
  const ordered = (s: string) => {
    let out = "";
    for (let i = 0; i < s.length; i++)
      out += s.charCodeAt(i).toString(16).padStart(4, "0");
    return out;
  };
  return ordered(stream) + "/" + (pkHash === undefined ? "" : ordered(pkHash));
}

function references<K extends WorkspaceRowKind>(
  kind: K,
  row: WorkspaceRows[K],
): readonly ValueToken[] {
  if (kind === "fold" || kind === "seed")
    return (row as WorkspaceFoldCell).upsert
      ? [
          (row as WorkspaceFoldCell).upsert!.body,
          ...((row as WorkspaceFoldCell).upsert!.source
            ? [(row as WorkspaceFoldCell).upsert!.source!]
            : []),
        ]
      : [];
  if (kind === "streams") return [(row as WorkspaceRows["streams"]).metadata];
  if (kind === "outputs" || kind === "uploads")
    return [(row as WorkspaceRows["outputs"]).value];
  return [];
}
/** At most one 64 KiB metadata page, charged before either SQL read. */
function metadataCursor(
  db: SqlDriver,
  binding: WorkspaceBinding,
  relation: "changes" | "replacement-membership",
): BoundedCursor<{ key: string; payload: string }> {
  let page: { key: string; payload: string }[] = [];
  let index = 0,
    after: string | null = null,
    owned = false,
    closed = false;
  let release: (() => void) | undefined;
  return {
    async next(lease) {
      if (closed || owned) throw new Error("workspace_cursor_owned_or_closed");
      release = ownLease(lease, binding.operation, 64 * 1024 * 24);
      try {
        await db.batch(workspaceGuard(binding));
        if (index === page.length) {
          page = [];
          index = 0;
          const meta = await db.query<{ key: string; k: number; n: number }>(
            `SELECT substr(key,1,128) AS key,LENGTH(CAST(key AS BLOB)) AS k,LENGTH(CAST(payload AS BLOB)) AS n FROM workspace_cells WHERE operation=? AND relation=? ${after === null ? "" : "AND key>?"} ORDER BY key LIMIT 64`,
            after === null
              ? [binding.operation, relation]
              : [binding.operation, relation, after],
          );
          if (meta.length === 0) {
            release();
            return null;
          }
          let end = 0,
            bytes = 0;
          while (end < meta.length) {
            const row = meta[end]!;
            if (row.k > 128 || row.k + row.n > 64 * 1024)
              throw new Error("workspace_metadata_admission");
            if (bytes + row.k + row.n > 64 * 1024) break;
            bytes += row.k + row.n;
            end++;
          }
          page = await db.query<{ key: string; payload: string }>(
            "SELECT key,payload FROM workspace_cells WHERE operation=? AND relation=? AND key>=? AND key<=? ORDER BY key",
            [binding.operation, relation, meta[0]!.key, meta[end - 1]!.key],
          );
        }
        const value = page[index++]!;
        after = value.key;
        owned = true;
        const releaseCurrent = release;
        let released = false;
        return {
          value,
          encodedBytes: new TextEncoder().encode(JSON.stringify(value)).length,
          async release() {
            if (!released) {
              released = true;
              owned = false;
              releaseCurrent();
            }
          },
        };
      } catch (error) {
        release?.();
        owned = false;
        return recordWorkspaceFailure(db, binding, "cursor", "metadata", error);
      }
    },
    async close() {
      closed = true;
      owned = false;
      page = [];
      release?.();
    },
  };
}

/** One encoded input unit; records() is a single-pass decoder. */
function recordPages(
  db: SqlDriver,
  binding: WorkspaceBinding,
  kind: "changes" | "replacement-membership",
  stream: string,
  pageBytes: number,
): BoundedCursor<WorkspaceChangePage> {
  const descriptor = kind === "changes" ? "payload" : "key || ':' || payload";
  const frameDescriptor =
    kind === "changes" ? "w.payload" : "w.key || ':' || w.payload";
  let after: string | null = null,
    owned = false,
    closed = false;
  let release: (() => void) | undefined;
  let dropCurrent: (() => void) | undefined;
  return {
    async next(lease) {
      if (closed || owned) throw new Error("workspace_cursor_owned_or_closed");
      release = ownLease(lease, binding.operation, 64 * 1024 * 24);
      try {
        if (
          !Number.isSafeInteger(pageBytes) ||
          pageBytes < 1 ||
          pageBytes > 65536
        )
          throw new Error("workspace_page_admission");
        await db.batch(workspaceGuard(binding));
        const [window] = await db.query<{ payload: string }>(
          "SELECT payload FROM workspace_cells WHERE operation=? AND relation='replacement' AND key=?",
          [binding.operation, kind === "changes" ? "window" : "members"],
        );
        if (!window || JSON.parse(window.payload)[0] !== stream)
          throw new Error("workspace_window_binding");
        const meta = await db.query<{
          key: string;
          payload: string;
          n: number;
        }>(
          `SELECT key,substr(${descriptor},1,256) AS payload,LENGTH(CAST(${descriptor} AS BLOB)) AS n FROM workspace_cells WHERE operation=? AND relation=? ${after === null ? "" : "AND key>?"} ORDER BY key LIMIT 64`,
          after === null
            ? [binding.operation, kind]
            : [binding.operation, kind, after],
        );
        if (meta.length === 0) {
          release();
          return null;
        }
        let count = 0,
          bytes = 0;
        for (const row of meta) {
          if (row.n > 256) throw new Error("workspace_metadata_admission");
          const size = Number(
            row.payload.slice(row.payload.lastIndexOf(":") + 1),
          );
          if (!Number.isSafeInteger(size) || size < 0)
            throw new Error("workspace_record_admission");
          if (count > 0 && bytes + size > pageBytes) break;
          bytes += size;
          count++;
          if (bytes >= pageBytes) break;
        }
        checkLease(lease, binding.operation, 6 * bytes + 64 * 1024 * 24);
        // The selected range is bounded BEFORE aggregation. ORDER BY is
        // the workspace primary-key order; GROUP_CONCAT holds one frame.
        const [frame] = await db.query<{ page: string }>(
          `SELECT GROUP_CONCAT(encoded,char(10)) AS page FROM (
                SELECT ${kind === "changes" ? "w.key" : "0"} || '|' || hex(CAST(${frameDescriptor} AS BLOB)) || '|' ||
                  CASE WHEN r.body IS NULL THEN '-' ELSE
                    r.stamp_o || '|' || hex(CAST(r.stamp_r AS BLOB)) || '|' || r.stamp_n || '|' ||
                    COALESCE(CAST(r.first_o AS TEXT),'null') || '|' || hex(CAST(r.body AS BLOB)) END AS encoded
                FROM workspace_cells w LEFT JOIN records r ON r.connection_id=? AND r.stream=? AND r.pk_hash=${kind === "changes" ? "substr(w.payload,1,instr(w.payload,':')-1)" : "w.key"}
                WHERE w.operation=? AND w.relation=? AND w.key>=? AND w.key<=? ORDER BY w.key
              )`,
          [
            binding.connection,
            stream,
            binding.operation,
            kind,
            meta[0]!.key,
            meta[count - 1]!.key,
          ],
        );
        let text = frame!.page;
        after = meta[count - 1]!.key;
        owned = true;
        const releaseCurrent = release;
        let released = false,
          readStarted = false;
        const dispose = () => {
          if (!released) {
            released = true;
            owned = false;
            text = "";
            releaseCurrent();
          }
        };
        dropCurrent = dispose;
        return {
          value: {
            recordCount: count,
            *records() {
              if (released || readStarted)
                throw new Error("workspace_unit_owned_or_released");
              readStarted = true;
              let start = 0,
                decoded = 0;
              while (start < text.length) {
                if (released) throw new Error("workspace_unit_released");
                const newline = text.indexOf("\n", start),
                  end = newline < 0 ? text.length : newline;
                let at = start;
                const field = () => {
                  const next = text.indexOf("|", at);
                  const value = text.slice(at, next);
                  at = next + 1;
                  return value;
                };
                const seq = Number(field()),
                  identity = decodeHex(field()),
                  colon = identity.lastIndexOf(":"),
                  pk = identity.slice(0, colon),
                  recordBytes = Number(identity.slice(colon + 1));
                let record: WorkspaceCanonicalRecord | null = null;
                if (text.slice(at, end) !== "-") {
                  const stamp_o = Number(field()),
                    stamp_r = decodeHex(field()),
                    stamp_n = Number(field()),
                    first = field();
                  record = {
                    pk_hash: pk,
                    stamp_o,
                    stamp_r,
                    stamp_n,
                    first_o: first === "null" ? null : Number(first),
                    body: decodeHex(text.slice(at, end)),
                  };
                }
                decoded++;
                yield { pk, seq, recordBytes, record };
                start = end + 1;
              }
              if (released) throw new Error("workspace_unit_released");
              if (decoded !== count)
                throw new Error("workspace_frame_incomplete");
            },
          },
          encodedBytes: text.length,
          async release() {
            dispose();
          },
        };
      } catch (error) {
        release?.();
        owned = false;
        return recordWorkspaceFailure(
          db,
          binding,
          "record-page",
          "read",
          error,
        );
      }
    },
    async close() {
      closed = true;
      owned = false;
      dropCurrent?.();
      release?.();
    },
  };
}

/** Consumer API: typed metadata and sealed references, with runtime revocation
 * for aliases TypeScript cannot consume linearly. No caller-supplied SQL. */
export async function openLogWorkspace(
  db: SqlDriver,
  binding: WorkspaceBinding,
) {
  const storage = await openWorkspace(db, binding);
  let writing = false;
  const api = {
    binding,
    partial: workspacePartial(db, binding),
    async acquire(bytes: number, signal?: AbortSignal) {
      await runtimeAdmission.enqueue(db, binding.operation);
      try {
        return await runtimeAdmission.acquireWaiting(
          binding.operation,
          bytes,
          signal,
        );
      } catch (error) {
        return recordWorkspaceFailure(
          db,
          binding,
          "admission",
          "acquire",
          error,
        );
      }
    },
    position: storage.position,
    failure(error: unknown): Promise<never> {
      return recordWorkspaceFailure(db, binding, "consumer", "plan", error);
    },
    /** These relations contain only replacement metadata. Native set deletion
     * returns a fixed receipt, never a result per historical row. Value-bearing
     * workspaces must use the general guarded cleanup cursor instead. */
    async cleanupReplacement() {
      assertNoOwnedUnit(binding.operation);
      await db.batch([
        workspaceAssert(
          "EXISTS(SELECT 1 FROM workspaces WHERE operation=? AND binding=? AND phase IN ('collect','aborted','clean')) AND NOT EXISTS(SELECT 1 FROM body_values WHERE operation=?) AND NOT EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation NOT IN ('changes','replacement','replacement-membership','omissions','membership','publication')) AND NOT EXISTS(SELECT 1 FROM workspace_stage WHERE operation=? AND relation NOT IN ('changes','replacement','replacement-membership','omissions','membership','publication'))",
          [
            binding.operation,
            bindingIdentity(binding),
            binding.operation,
            binding.operation,
            binding.operation,
          ],
        ),
        { sql: "DELETE FROM workspace_assert" },
        ...[
          "workspace_stage",
          "workspace_cells",
          "workspace_receipts",
          "workspace_attempts",
        ].map((table) => ({
          sql: `DELETE FROM ${table} WHERE operation=?`,
          params: [binding.operation],
        })),
        {
          sql: "UPDATE workspaces SET phase='clean' WHERE operation=?",
          params: [binding.operation],
        },
      ]);
    },
    async admit(lease: ByteLease, bytes: number) {
      try {
        checkLease(lease, binding.operation, bytes);
      } catch (error) {
        return recordWorkspaceFailure(db, binding, "record", "admit", error);
      }
    },
    /** Freeze the latest eligible change per key. SQLite maintains the sequence
     * index on disk; neither input history nor the result enters a JS array.
     * One workspace owns one frozen stream/window. A retry cannot widen it. */
    async freezeChanges(stream: string, from: number, to: number) {
      const identity = JSON.stringify([stream, from, to]);
      if (
        !Number.isSafeInteger(from) ||
        !Number.isSafeInteger(to) ||
        from < 0 ||
        to < from ||
        new TextEncoder().encode(identity).length > 64 * 1024
      )
        return recordWorkspaceFailure(
          db,
          binding,
          "changes",
          "freeze",
          new Error("workspace_metadata_admission"),
        );
      await workspaceAttempt(db, binding, "changes", "freeze", [
        ...workspaceGuard(binding),
        workspaceAssert(
          "NOT EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation='replacement' AND key='window' AND payload<>?)",
          [binding.operation, identity],
        ),
        {
          sql: `INSERT OR IGNORE INTO workspace_cells(operation,relation,key,payload)
          SELECT ?, 'changes', printf('%020d',MAX(seq)), pk_hash || ':' || COALESCE((SELECT LENGTH(CAST(body AS BLOB))+LENGTH(CAST(stamp_r AS BLOB)) FROM records WHERE records.connection_id=record_changes.connection_id AND records.stream=record_changes.stream AND records.pk_hash=record_changes.pk_hash),(SELECT COALESCE(LENGTH(CAST(d.pk_values AS BLOB)),0)+LENGTH(CAST(d.record_key AS BLOB))+LENGTH(CAST(d.stamp_r AS BLOB)) FROM record_changes d WHERE d.connection_id=record_changes.connection_id AND d.stream=record_changes.stream AND d.pk_hash=record_changes.pk_hash AND d.seq>? AND d.seq<=? AND d.op='remove' AND (d.explicit_delete=1 OR d.pk_values IS NOT NULL) ORDER BY d.seq DESC LIMIT 1),0) FROM record_changes
          WHERE connection_id=? AND stream=? AND seq>? AND seq<=? AND ${ELIGIBLE_CHANGE}
            AND NOT EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation='replacement' AND key='window')
          GROUP BY pk_hash`,
          params: [
            binding.operation,
            from,
            to,
            binding.connection,
            stream,
            from,
            to,
            binding.operation,
          ],
        },
        {
          sql: "INSERT OR IGNORE INTO workspace_cells VALUES(?,'replacement','window',?)",
          params: [binding.operation, identity],
        },
      ]);
    },
    /** Freeze omission identities with an indexed INSERT SELECT. Typed keys
     * are resolved only for the bounded prefix the encoder actually visits. */
    async freezeMembership(stream: string, cutoff: LogStamp) {
      const identity = JSON.stringify([stream, cutoff]);
      if (new TextEncoder().encode(identity).length > 64 * 1024)
        return recordWorkspaceFailure(
          db,
          binding,
          "membership",
          "freeze",
          new Error("workspace_metadata_admission"),
        );
      await workspaceAttempt(db, binding, "membership", "freeze", [
        ...workspaceGuard(binding),
        workspaceAssert(
          "NOT EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation='replacement' AND key='members' AND payload<>?)",
          [binding.operation, identity],
        ),
        {
          sql: `INSERT OR IGNORE INTO workspace_cells(operation,relation,key,payload)
          SELECT ?, 'replacement-membership', pk_hash, CAST(LENGTH(CAST(body AS BLOB))+LENGTH(CAST(stamp_r AS BLOB)) AS TEXT) FROM records
          WHERE connection_id=? AND stream=? AND ${SEEN_BEFORE}
            AND NOT EXISTS(SELECT 1 FROM workspace_cells WHERE operation=? AND relation='replacement' AND key='members')`,
          params: [
            binding.operation,
            binding.connection,
            stream,
            ...seenBeforeParams(cutoff.o, cutoff.r),
            binding.operation,
          ],
        },
        {
          sql: "INSERT OR IGNORE INTO workspace_cells VALUES(?,'replacement','members',?)",
          params: [binding.operation, identity],
        },
      ]);
    },
    async membershipCount(): Promise<number> {
      await db.batch(workspaceGuard(binding));
      return (
        await db.query<{ n: number }>(
          "SELECT COUNT(*) AS n FROM workspace_cells WHERE operation=? AND relation='replacement-membership'",
          [binding.operation],
        )
      )[0]!.n;
    },
    membershipCursor(): BoundedCursor<{ pkHash: string; recordBytes: number }> {
      const cursor = metadataCursor(db, binding, "replacement-membership");
      return {
        async next(lease) {
          const unit = await cursor.next(lease);
          return (
            unit && {
              ...unit,
              value: {
                pkHash: unit.value.key,
                recordBytes: Number(unit.value.payload),
              },
            }
          );
        },
        close: cursor.close,
      };
    },
    changeCursor(): BoundedCursor<{
      readonly pk: string;
      readonly seq: number;
      readonly recordBytes: number;
    }> {
      const cursor = metadataCursor(db, binding, "changes");
      return {
        async next(lease) {
          const unit = await cursor.next(lease);
          return (
            unit && {
              ...unit,
              value: {
                pk: unit.value.payload.slice(
                  0,
                  unit.value.payload.lastIndexOf(":"),
                ),
                seq: Number(unit.value.key),
                recordBytes: Number(
                  unit.value.payload.slice(
                    unit.value.payload.lastIndexOf(":") + 1,
                  ),
                ),
              },
            }
          );
        },
        close: cursor.close,
      };
    },
    changeRecordPages(stream: string, pageBytes: number) {
      return recordPages(db, binding, "changes", stream, pageBytes);
    },
    membershipRecordPages(stream: string, pageBytes: number) {
      return recordPages(
        db,
        binding,
        "replacement-membership",
        stream,
        pageBytes,
      );
    },
    async replayableUnit(
      unit: string,
      digest: string,
    ): Promise<StagingWorkspaceUnit | ReceiptedWorkspaceUnit> {
      const [receipt] = await db.query<{ position: number }>(
        "SELECT position FROM workspace_receipts WHERE operation=? AND unit=?",
        [binding.operation, unit],
      );
      return api.unit(
        unit,
        digest,
        receipt ? receipt.position - 1 : await storage.position(),
      );
    },
    async unit(
      unit: string,
      digest: string,
      previous: number,
    ): Promise<StagingWorkspaceUnit | ReceiptedWorkspaceUnit> {
      await db.batch(workspaceGuard(binding));
      const receipt = (
        await db.query<{ digest: string; position: number }>(
          "SELECT digest,position FROM workspace_receipts WHERE operation=? AND unit=?",
          [binding.operation, unit],
        )
      )[0];
      if (receipt) {
        if (receipt.digest !== digest || receipt.position !== previous + 1)
          throw new Error("workspace_receipt_conflict");
        return { state: "receipted", unit, digest, position: receipt.position };
      }
      let committed = false;
      return {
        state: "staging",
        async stage(kind, row) {
          if (committed) throw new Error("workspace_unit_receipted");
          if (writing) throw new Error("workspace_unit_busy");
          writing = true;
          try {
            if (kind === "publication") {
              const state = row as WorkspaceRows["publication"];
              if (!state.published && state.complete)
                throw new Error("workspace_early_completion");
            }
            const payload = JSON.stringify(row);
            if (payload.length > 64 * 1024)
              return await recordWorkspaceFailure(
                db,
                binding,
                unit,
                "stage",
                new Error("workspace_metadata_admission"),
              );
            const snapshot = JSON.parse(payload) as typeof row;
            const refs = references(kind, snapshot);
            const key =
              kind === "fold" || kind === "seed" || kind === "streams"
                ? foldCellKey(
                    (snapshot as WorkspaceRecordKey).stream,
                    (snapshot as WorkspaceRecordKey).pkHash,
                  )
                : "objectKey" in snapshot
                  ? JSON.stringify([snapshot.objectKey])
                  : "pkHash" in snapshot
                    ? JSON.stringify([snapshot.stream, snapshot.pkHash])
                    : JSON.stringify([snapshot.stream]);
            // Validate each sealed reference against durable metadata, including the full
            // binding. Sealed values cannot be aborted while the workspace is active.
            for (const token of refs) {
              if (
                token.kind !== "sealed-value" ||
                bindingIdentity(token.binding) !== bindingIdentity(binding)
              )
                throw new Error("workspace_value_binding");
              await db.batch([
                ...workspaceGuard(binding),
                workspaceAssert(
                  "EXISTS(SELECT 1 FROM body_values WHERE id=? AND operation=? AND bytes=? AND digest=? AND encoding=? AND sealed=1 AND aborted=0)",
                  [
                    token.id,
                    binding.operation,
                    token.bytes,
                    token.sha256,
                    token.encoding,
                  ],
                ),
              ]);
            }
            await storage.stage(unit, kind, key, payload);
          } finally {
            writing = false;
          }
        },
        async stageOmissions(rows) {
          if (committed) throw new Error("workspace_unit_receipted");
          if (writing) throw new Error("workspace_unit_busy");
          writing = true;
          try {
            if (rows.length > 64)
              return await recordWorkspaceFailure(
                db,
                binding,
                unit,
                "stage",
                new Error("workspace_metadata_admission"),
              );
            if (rows.length === 0) return;
            const values: SqlValue[] = [];
            let bytes = 0;
            for (const row of rows) {
              const payload = JSON.stringify(row),
                snapshot = JSON.parse(payload) as WorkspaceRows["omissions"],
                key = JSON.stringify([snapshot.stream, snapshot.pkHash]);
              bytes +=
                new TextEncoder().encode(payload).length +
                new TextEncoder().encode(key).length;
              if (bytes > 64 * 1024)
                return await recordWorkspaceFailure(
                  db,
                  binding,
                  unit,
                  "stage",
                  new Error("workspace_metadata_admission"),
                );
              values.push(binding.operation, unit, "omissions", key, payload);
            }
            await workspaceAttempt(db, binding, unit, "stage", [
              ...workspaceGuard(binding),
              workspaceAssert(
                "(SELECT phase FROM workspaces WHERE operation=?)='collect' AND NOT EXISTS(SELECT 1 FROM workspace_receipts WHERE operation=? AND unit=?)",
                [binding.operation, binding.operation, unit],
              ),
              {
                sql: `INSERT OR REPLACE INTO workspace_stage VALUES ${rows.map(() => "(?,?,?,?,?)").join(",")}`,
                params: values,
              },
            ]);
          } finally {
            writing = false;
          }
        },
        async commit() {
          if (committed) throw new Error("workspace_unit_receipted");
          if (writing) throw new Error("workspace_unit_busy");
          writing = true;
          try {
            await storage.commitUnit(unit, digest, previous);
            committed = true;
          } finally {
            writing = false;
          }
          return { state: "receipted", unit, digest, position: previous + 1 };
        },
      };
    },
    async lookup<K extends WorkspaceRowKind>(
      unit: string,
      kind: K,
      key: string,
      lease: ByteLease,
    ): Promise<WorkspaceRows[K] | null> {
      const payload = await storage.lookup(unit, kind, key, lease);
      return payload === null
        ? null
        : (JSON.parse(payload) as WorkspaceRows[K]);
    },
    cursor<K extends WorkspaceRowKind>(
      kind: K,
    ): BoundedCursor<{ readonly key: string; readonly row: WorkspaceRows[K] }> {
      const cursor = storage.cursor(kind);
      return {
        async next(lease) {
          const unit = await cursor.next(lease);
          if (!unit) return null;
          try {
            return {
              value: {
                key: unit.value.key,
                row: JSON.parse(unit.value.payload) as WorkspaceRows[K],
              },
              encodedBytes: unit.encodedBytes,
              release: unit.release,
            };
          } catch (error) {
            await unit.release();
            throw error;
          }
        },
        close: cursor.close,
      };
    },
    stageSeed: (entry: LogEntry, primaryKey: readonly string[]) =>
      stageWorkspaceSeed(db, binding, entry, primaryKey),
    promoteSeed: (
      expected: LogState,
      target: LogState,
      controlVersion: number,
    ) => promoteWorkspaceSeed(db, binding, expected, target, controlVersion),
    transition: storage.transition,
    discard: storage.discard,
    cleanupOne: storage.cleanupOne,
  };
  return api;
}
