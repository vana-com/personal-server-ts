import {
  WorkspaceOperationError,
  workspaceAttempt,
  recordWorkspaceFailure,
} from "./workspace-failure.js";
import { sha256 } from "@noble/hashes/sha2";
import type { SqlDriver } from "./driver.js";
import type {
  BoundedValueStore,
  ValueWriterToken,
  ValueToken,
  WorkspaceBinding,
} from "./workspace-capability.js";
import {
  bindingIdentity,
  ownLease,
  runtimeAdmission,
  workspaceGuard,
  workspaceAssert,
} from "./workspace.js";

type ValueRow = {
  id: string;
  operation: string;
  bytes: number;
  digest: string;
  encoding: "binary" | "utf8";
  offset: number;
  sealed: number;
  aborted: number;
};
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
/** Slice inside SQLite so even a corrupt/older oversized chunk cannot create
 * an oversized native reply. The primary key finds the enclosing chunk. */
async function valueChunk(
  db: SqlDriver,
  id: string,
  offset: number,
  capacity: number,
): Promise<Uint8Array> {
  const row = (
    await db.query<{ body: Uint8Array | null }>(
      "SELECT CASE WHEN offset+length(body)>? THEN substr(body,?-offset+1,?) ELSE NULL END AS body FROM body_value_chunks WHERE value_id=? AND offset<=? ORDER BY offset DESC LIMIT 1",
      [offset, offset, capacity, id, offset],
    )
  )[0];
  if (!row?.body?.length) throw new Error("workspace_chunk_missing");
  return row.body;
}
/** Persistent chunk-backed fallback. No whole-value readback at seal. The caller
 * supplies ids so the portable storage implementation imports no host runtime. */
export function createSqlWorkspaceValues(
  db: SqlDriver,
  newId: () => string,
  frameCapacityBytes = 64 * 1024,
): BoundedValueStore {
  if (!db.info.persistent)
    throw new Error("workspace_requires_persistent_database");
  if (
    !Number.isSafeInteger(frameCapacityBytes) ||
    frameCapacityBytes < 4096 ||
    frameCapacityBytes > 4 * 1024 * 1024
  )
    throw new Error("workspace_frame_capacity");
  const chunkCapacity = Math.min(
    64 * 1024,
    Math.floor((frameCapacityBytes - 2048) / 6),
  );
  let busy = false,
    owned = false;
  const run = async <T>(fn: () => Promise<T>): Promise<T> => {
    if (busy || owned) throw new Error("workspace_value_busy");
    busy = true;
    try {
      return await fn();
    } finally {
      busy = false;
    }
  };
  const reported = <T>(
    binding: WorkspaceBinding,
    unit: string,
    action: string,
    result: Promise<T>,
  ): Promise<T> =>
    result.catch((error) => {
      if (error instanceof WorkspaceOperationError) throw error;
      return recordWorkspaceFailure(db, binding, unit, action, error);
    });
  const row = async (t: ValueWriterToken | ValueToken) => {
    await db.batch(workspaceGuard(t.binding));
    const v = (
      await db.query<ValueRow>(
        "SELECT * FROM body_values WHERE id=? AND operation=?",
        [t.id, t.binding.operation],
      )
    )[0];
    if (!v || v.aborted) throw new Error("workspace_value_missing");
    return v;
  };
  const sealed = (b: WorkspaceBinding, v: ValueRow): ValueToken => ({
    kind: "sealed-value",
    binding: b,
    id: v.id,
    bytes: v.bytes,
    sha256: v.digest,
    encoding: v.encoding,
  });
  const store: BoundedValueStore = {
    version: 1,
    supportsBorrowedSeal: true,
    frameCapacityBytes,
    admission: runtimeAdmission,
    begin(b, bytes, digest, encoding) {
      return reported(
        b,
        "value-begin",
        "begin",
        run(async () => {
          if (
            !Number.isSafeInteger(bytes) ||
            bytes < 0 ||
            !/^[a-f0-9]{64}$/.test(digest)
          )
            throw new Error("workspace_value_metadata");
          if (new TextEncoder().encode(bindingIdentity(b)).length > 1024)
            throw new Error("workspace_binding_admission");
          const id = newId();
          if (id.length > 128) throw new Error("workspace_value_id_admission");
          await workspaceAttempt(db, b, "value-begin", "begin", [
            ...workspaceGuard(b),
            {
              sql: "INSERT INTO body_values(id,operation,bytes,digest,encoding) VALUES(?,?,?,?,?)",
              params: [id, b.operation, bytes, digest, encoding],
            },
          ]);
          return { kind: "value-writer", binding: b, id };
        }),
      );
    },
    append(t, offset, chunk, lease) {
      return reported(
        t.binding,
        t.id,
        "append",
        run(async () => {
          const releaseUnit = ownLease(
            lease,
            t.binding.operation,
            chunk.length * 6 + 2048,
          );
          try {
            if (
              chunk.length === 0 ||
              chunk.length > chunkCapacity ||
              !Number.isSafeInteger(offset) ||
              offset < 0
            )
              return await recordWorkspaceFailure(
                db,
                t.binding,
                t.id,
                "append",
                new Error("workspace_chunk_admission"),
              );
            const v = await row(t);
            if (v.sealed) throw new Error("workspace_value_sealed");
            if (offset < v.offset) {
              const match = (
                await db.query<{ ok: number }>(
                  "SELECT 1 AS ok FROM body_value_chunks WHERE value_id=? AND offset=? AND body=?",
                  [t.id, offset, chunk],
                )
              )[0];
              if (!match) throw new Error("workspace_chunk_conflict");
              return { nextOffset: v.offset };
            }
            if (offset !== v.offset || offset + chunk.length > v.bytes)
              throw new Error("workspace_chunk_offset");
            await workspaceAttempt(db, t.binding, t.id, "append", [
              ...workspaceGuard(t.binding),
              workspaceAssert(
                "EXISTS(SELECT 1 FROM body_values WHERE id=? AND offset=? AND sealed=0 AND aborted=0)",
                [t.id, offset],
              ),
              {
                sql: "INSERT INTO body_value_chunks VALUES(?,?,?)",
                params: [t.id, offset, chunk],
              },
              {
                sql: "UPDATE body_values SET offset=? WHERE id=?",
                params: [offset + chunk.length, t.id],
              },
            ]);
            return { nextOffset: offset + chunk.length };
          } finally {
            releaseUnit();
          }
        }),
      );
    },
    seal(t, borrowedLease) {
      return reported(
        t.binding,
        t.id,
        "seal",
        run(async () => {
          const v = await row(t);
          if (v.sealed) return sealed(t.binding, v);
          if (v.offset !== v.bytes)
            throw new Error("workspace_value_incomplete");
          // Own a bounded verification window before reading a single chunk.
          const lease =
            borrowedLease ??
            (await runtimeAdmission.acquire(
              t.binding.operation,
              chunkCapacity * 6 + 2048,
            ));
          const releaseUnit = ownLease(
            lease,
            t.binding.operation,
            chunkCapacity * 6 + 2048,
          );
          try {
            const hash = sha256.create(),
              decoder =
                v.encoding === "utf8"
                  ? new TextDecoder("utf-8", { fatal: true })
                  : null;
            let at = 0;
            while (at < v.bytes) {
              const chunk = await valueChunk(db, t.id, at, chunkCapacity);
              hash.update(chunk);
              decoder?.decode(chunk, { stream: true });
              at += chunk.length;
            }
            decoder?.decode();
            if (at !== v.bytes || hex(hash.digest()) !== v.digest)
              throw new Error("workspace_value_digest");
            await workspaceAttempt(db, t.binding, t.id, "seal", [
              ...workspaceGuard(t.binding),
              workspaceAssert(
                "EXISTS(SELECT 1 FROM body_values WHERE id=? AND offset=bytes AND aborted=0)",
                [t.id],
              ),
              {
                sql: "UPDATE body_values SET sealed=1 WHERE id=?",
                params: [t.id],
              },
            ]);
            return sealed(t.binding, v);
          } finally {
            releaseUnit();
            if (!borrowedLease) await lease.release();
          }
        }),
      );
    },
    status(t) {
      return run(async () => {
        const v = await row(t);
        return {
          offset: v.offset,
          sealed: v.sealed ? sealed(t.binding, v) : null,
        };
      });
    },
    read(t, offset, lease) {
      return run(async () => {
        const releaseUnit = ownLease(
          lease,
          t.binding.operation,
          chunkCapacity * 6 + 2048,
        );
        try {
          const v = await row(t);
          if (
            !v.sealed ||
            v.bytes !== t.bytes ||
            v.digest !== t.sha256 ||
            v.encoding !== t.encoding
          )
            throw new Error("workspace_value_token");
          if (!Number.isSafeInteger(offset) || offset < 0 || offset > v.bytes)
            throw new Error("workspace_chunk_offset");
          const value =
            offset === v.bytes
              ? new Uint8Array()
              : await valueChunk(db, t.id, offset, chunkCapacity);
          owned = true;
          let released = false;
          return {
            value,
            encodedBytes: value.length,
            async release() {
              if (!released) {
                released = true;
                owned = false;
                releaseUnit();
              }
            },
          };
        } catch (error) {
          releaseUnit();
          throw error;
        }
      });
    },
    abort(t) {
      return run(async () => {
        const v = await row(t);
        if (v.sealed) throw new Error("workspace_value_live");
        // Chunks may be numerous. Abort marks the parent dead; cleanup pages them.
        await db.batch([
          ...workspaceGuard(t.binding),
          {
            sql: "UPDATE body_values SET aborted=1 WHERE id=?",
            params: [t.id],
          },
        ]);
      });
    },
  };
  return store;
}
