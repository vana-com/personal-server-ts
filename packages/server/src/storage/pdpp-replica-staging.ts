import { createHash, randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { Admission } from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  binaryWriter,
  deleteBinary,
  verifyBinary,
} from "./pdpp-binary-chunks.js";

export const STAGED_OBJECT_LEASE_MS = 60 * 60 * 1000;
export const STAGED_OBJECT_CLEANUP_BATCH = 100;

const migration = `
CREATE TABLE IF NOT EXISTS pdpp_transport_staged_objects (
 object_id TEXT PRIMARY KEY, admission_id TEXT NOT NULL, repository_id TEXT NOT NULL,
 owner TEXT NOT NULL, namespace_key TEXT NOT NULL, created_at INTEGER NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('receiving','complete','verified','attached','aborted')),
 size_bytes INTEGER, sha256 TEXT, attached_at INTEGER);
CREATE INDEX IF NOT EXISTS pdpp_staged_objects_cleanup
 ON pdpp_transport_staged_objects(state,created_at,object_id);
`;

declare const stagedObjectBrand: unique symbol;
export interface StagedObject {
  readonly [stagedObjectBrand]: true;
}

type HandleData = {
  objectId: string;
  admissionId: string;
  repositoryId: string;
  owner: string;
};
const handles = new WeakMap<StagedObject, HandleData>();

type ExpectedObject = { blobId: string; sha256: string; sizeBytes: number };

export function createReplicaStagingStore(input: {
  db: Database;
  repositoryId: string;
  owner: string;
  now?: () => number;
  assertOpen?: () => void;
}) {
  const { db, repositoryId, owner } = input;
  const now = input.now ?? Date.now;
  db.exec(migration);

  function handle(data: HandleData): StagedObject {
    const value = Object.freeze({}) as StagedObject;
    handles.set(value, data);
    return value;
  }

  function rowFor(objectId: string) {
    return db
      .prepare("SELECT * FROM pdpp_transport_staged_objects WHERE object_id=?")
      .get(objectId) as
      | {
          object_id: string;
          admission_id: string;
          repository_id: string;
          owner: string;
          namespace_key: string;
          created_at: number;
          state: string;
          size_bytes: number | null;
          sha256: string | null;
        }
      | undefined;
  }

  function removeObject(objectId: string) {
    const row = rowFor(objectId);
    if (!row) return false;
    deleteBinary(db, "staging", row.namespace_key);
    db.prepare(
      "DELETE FROM pdpp_transport_staged_objects WHERE object_id=?",
    ).run(objectId);
    return true;
  }

  function begin(admission: Admission) {
    if (admission.repositoryId !== repositoryId || admission.owner !== owner)
      throw new Error("admission authority mismatch");
    const objectId = randomUUID();
    const namespaceKey = randomUUID();
    const writer = binaryWriter(db, "staging", namespaceKey);
    const hash = createHash("sha256");
    let sizeBytes = 0;
    let closed = false;
    const staged = handle({
      objectId,
      admissionId: admission.admissionId,
      repositoryId,
      owner,
    });
    db.prepare(
      `INSERT INTO pdpp_transport_staged_objects
       (object_id,admission_id,repository_id,owner,namespace_key,created_at,state)
       VALUES (?,?,?,?,?,?,'receiving')`,
    ).run(
      objectId,
      admission.admissionId,
      repositoryId,
      owner,
      namespaceKey,
      now(),
    );
    return {
      handle: staged,
      write(bytes: Uint8Array) {
        if (closed) throw new Error("staged object writer is closed");
        input.assertOpen?.();
        const next = sizeBytes + bytes.length;
        if (!Number.isSafeInteger(next) || next > admission.payloadBytes) {
          abort(admission);
          throw new Error("staged object exceeds admitted payload");
        }
        db.transaction(() => writer.write(bytes))();
        hash.update(bytes);
        sizeBytes = next;
      },
      complete() {
        if (closed) throw new Error("staged object writer is closed");
        input.assertOpen?.();
        const written = writer.finish();
        if (written !== sizeBytes)
          throw new Error("staged object length mismatch");
        const sha256 = `sha256:${hash.digest("hex")}`;
        db.prepare(
          `UPDATE pdpp_transport_staged_objects
           SET state='complete',size_bytes=?,sha256=? WHERE object_id=? AND state='receiving'`,
        ).run(sizeBytes, sha256, objectId);
        closed = true;
        return staged;
      },
      abort() {
        if (closed) return;
        closed = true;
        abort(admission);
      },
    };
  }

  function verify(staged: StagedObject, expected: ExpectedObject) {
    const data = handles.get(staged);
    if (!data) throw new Error("unknown staged object handle");
    const row = rowFor(data.objectId);
    if (
      !row ||
      row.state !== "complete" ||
      row.repository_id !== repositoryId ||
      row.owner !== owner ||
      row.admission_id !== data.admissionId ||
      row.size_bytes !== expected.sizeBytes ||
      row.sha256 !== expected.sha256 ||
      !verifyBinary(
        db,
        "staging",
        row.namespace_key,
        expected.sha256,
        expected.sizeBytes,
      )
    )
      throw new Error("staged object verification failed");
    db.prepare(
      "UPDATE pdpp_transport_staged_objects SET state='verified' WHERE object_id=? AND state='complete'",
    ).run(data.objectId);
  }

  /** Call inside the import outcome transaction; returns the internal temp key. */
  function attach(staged: StagedObject, expected: ExpectedObject): string {
    if (!db.inTransaction)
      throw new Error("staged object attach requires a transaction");
    const data = handles.get(staged);
    if (!data || data.repositoryId !== repositoryId || data.owner !== owner)
      throw new Error("foreign staged object handle");
    const row = rowFor(data.objectId);
    if (
      !row ||
      row.state !== "verified" ||
      row.repository_id !== repositoryId ||
      row.owner !== owner ||
      row.admission_id !== data.admissionId ||
      row.size_bytes !== expected.sizeBytes ||
      row.sha256 !== expected.sha256 ||
      !verifyBinary(
        db,
        "staging",
        row.namespace_key,
        expected.sha256,
        expected.sizeBytes,
      )
    )
      throw new Error("stale or unverified staged object handle");
    const changed = db
      .prepare(
        `UPDATE pdpp_transport_staged_objects SET state='attached',attached_at=?
         WHERE object_id=? AND state='verified'`,
      )
      .run(now(), data.objectId).changes;
    if (changed !== 1) throw new Error("staged object attach lost its race");
    return row.namespace_key;
  }

  function abort(admission: Admission) {
    db.transaction(() => {
      const rows = db
        .prepare(
          `SELECT object_id FROM pdpp_transport_staged_objects
           WHERE admission_id=? AND state<>'attached'`,
        )
        .all(admission.admissionId) as { object_id: string }[];
      for (const row of rows) removeObject(row.object_id);
    }).immediate();
  }

  /** A replay owns the same admission id and must discard its prior orphan first. */
  function reclaimAdmission(admission: Admission) {
    if (admission.repositoryId !== repositoryId || admission.owner !== owner)
      throw new Error("admission authority mismatch");
    return db
      .transaction(() => {
        const rows = db
          .prepare(
            `SELECT object_id FROM pdpp_transport_staged_objects
             WHERE admission_id=? AND state<>'attached'`,
          )
          .all(admission.admissionId) as { object_id: string }[];
        for (const row of rows) removeObject(row.object_id);
        return rows.length;
      })
      .immediate();
  }

  function cleanup(limit = STAGED_OBJECT_CLEANUP_BATCH) {
    const cutoff = now() - STAGED_OBJECT_LEASE_MS;
    return db
      .transaction(() => {
        const rows = db
          .prepare(
            `SELECT object_id FROM pdpp_transport_staged_objects
             WHERE state<>'attached' AND created_at<=?
             ORDER BY created_at,object_id LIMIT ?`,
          )
          .all(cutoff, Math.min(limit, STAGED_OBJECT_CLEANUP_BATCH)) as {
          object_id: string;
        }[];
        for (const row of rows) removeObject(row.object_id);
        return rows.length;
      })
      .immediate();
  }

  /** Delete only the temporary key after its bytes have been published elsewhere. */
  function cleanupAttachedTemporaryBytes(limit = STAGED_OBJECT_CLEANUP_BATCH) {
    return db
      .transaction(() => {
        const rows = db
          .prepare(
            `SELECT namespace_key FROM pdpp_transport_staged_objects
             WHERE state='attached' AND EXISTS (
               SELECT 1 FROM pdpp_binary_manifests m
               WHERE m.namespace='staging' AND m.blob_id=namespace_key
             )
             ORDER BY attached_at,object_id LIMIT ?`,
          )
          .all(Math.min(limit, STAGED_OBJECT_CLEANUP_BATCH)) as {
          namespace_key: string;
        }[];
        for (const row of rows) deleteBinary(db, "staging", row.namespace_key);
        return rows.length;
      })
      .immediate();
  }

  return {
    begin,
    verify,
    attach,
    abort,
    reclaimAdmission,
    cleanup,
    cleanupAttachedTemporaryBytes,
    leaseMs: STAGED_OBJECT_LEASE_MS,
  };
}
