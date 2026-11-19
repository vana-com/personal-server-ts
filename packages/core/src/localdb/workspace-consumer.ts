import { stageWorkspaceSeed, promoteWorkspaceSeed } from "./workspace-seed.js";
import type { LogState } from "./log-state.js";
import type { LogEntry } from "@opendatalabs/personal-server-ts-stream-sync";
import { recordWorkspaceFailure } from "./workspace-failure.js";
import { runtimeAdmission } from "./workspace.js";
import type {
  LogKey,
  LogStamp,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { SqlDriver } from "./driver.js";
import type {
  BoundedCursor,
  BoundedValueStore,
  ByteLease,
  OwnedUnit,
  ValueToken,
  WorkspaceBinding,
} from "./workspace-capability.js";
import {
  bindingIdentity,
  openWorkspace,
  workspaceAssert,
  workspaceGuard,
} from "./workspace.js";

export interface WorkspaceRecordKey {
  readonly stream: string;
  readonly pkHash: string;
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
/** Consumer API: typed metadata and sealed references, with runtime revocation
 * for aliases TypeScript cannot consume linearly. No caller-supplied SQL. */
export async function openLogWorkspace(
  db: SqlDriver,
  binding: WorkspaceBinding,
) {
  const storage = await openWorkspace(db, binding);
  let writing = false;
  return {
    binding,
    async acquire(bytes: number, signal?: AbortSignal) {
      await runtimeAdmission.enqueue(db, binding.operation);
      try {
        return await runtimeAdmission.acquire(binding.operation, bytes, signal);
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
}
