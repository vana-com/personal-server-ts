import type { Database } from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { keccak256 } from "viem";
import { z } from "zod";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  replicaEnvelopeSchema,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  assembleReplicaPayload,
  decodeReplicaFragment,
  fragmentReplicaPayload,
  fromBase64,
  isReplicaScope,
  replicaDigest,
  replicaMetadataHash,
  toBase64,
  REPLICA_MAX_BLOB_BYTES,
  type PreparedFragment,
  type ReplicaFragment,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  replicaRegistrationState,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type { ReplicationExport } from "./pdpp-replication-sqlite.js";
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";

const migration = `
CREATE TABLE IF NOT EXISTS pdpp_transport_state (
 id INTEGER PRIMARY KEY CHECK(id=1), owner TEXT NOT NULL, writer TEXT NOT NULL,
 baseline_cursor INTEGER NOT NULL DEFAULT 0, baseline_done INTEGER NOT NULL DEFAULT 0,
 tail_cursor INTEGER, sequence INTEGER NOT NULL DEFAULT 0, previous_json TEXT, scan_cursor TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_batches (
 batch TEXT PRIMARY KEY, sequence INTEGER UNIQUE NOT NULL, previous_json TEXT,
 collected_at TEXT NOT NULL, digest TEXT NOT NULL, payload BLOB NOT NULL, prepared INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_outbox (
 scope TEXT PRIMARY KEY, batch TEXT NOT NULL, plaintext BLOB NOT NULL, encrypted BLOB NOT NULL,
 data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'ready',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_inbox (
 scope TEXT PRIMARY KEY, fragment_json TEXT, state TEXT NOT NULL DEFAULT 'ready',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0, error TEXT);
CREATE TABLE IF NOT EXISTS pdpp_transport_imported (
 writer TEXT NOT NULL, batch TEXT NOT NULL, sequence INTEGER NOT NULL, digest TEXT NOT NULL,
 PRIMARY KEY(writer,batch), UNIQUE(writer,sequence));
`;
const blobSchema = z.strictObject({ blobId: z.string(), bytes: z.string() });
const payloadSchema = z.strictObject({
  envelope: replicaEnvelopeSchema,
  blobs: z.array(blobSchema),
});
type State = {
  owner: string;
  writer: string;
  baseline_cursor: number;
  baseline_done: number;
  tail_cursor: number | null;
  sequence: number;
  previous_json: string | null;
  scan_cursor: string | null;
};
type Batch = {
  batch: string;
  sequence: number;
  previous_json: string | null;
  collected_at: string;
  digest: string;
  payload: Buffer;
  prepared: number;
  attempts: number;
};
type Outbox = {
  scope: string;
  batch: string;
  plaintext: Buffer;
  encrypted: Buffer;
  data_hash: `0x${string}`;
  metadata_hash: `0x${string}`;
  state: string;
  attempts: number;
  next_attempt: number;
};
type Inbox = {
  scope: string;
  fragment_json: string | null;
  state: string;
  attempts: number;
  next_attempt: number;
};

/** Internal experiment only. No bootstrap wiring; false by default, no production evidence adapter. */
export function createReplicaTransportWorker(deps: {
  db: Database;
  enabled?: boolean;
  expected: () => EnvelopeExpectation;
  exporter: ReplicationExport;
  receiver: ReturnType<typeof createReplicaReceiver>;
  credential: unknown;
  transport: ReplicaTransportPort;
  now?: () => number;
  maxBlobBytes?: number;
  targetChunkBytes?: number;
  pageSize?: number;
}) {
  const { db, transport } = deps;
  const now = deps.now ?? Date.now;
  const cap = deps.maxBlobBytes ?? REPLICA_MAX_BLOB_BYTES;
  if (!Number.isSafeInteger(cap) || cap < 1 || cap > REPLICA_MAX_BLOB_BYTES)
    throw new RangeError("invalid storage cap");
  db.exec(migration);
  const enabled = () => deps.enabled === true;
  const state = () =>
    db.prepare("SELECT * FROM pdpp_transport_state WHERE id=1").get() as State;
  function initialize() {
    const owner = deps.expected().owner;
    db.prepare(
      "INSERT OR IGNORE INTO pdpp_transport_state (id,owner,writer) VALUES (1,?,?)",
    ).run(owner, randomUUID().replaceAll("-", ""));
    if (state().owner !== owner)
      throw new Error("transport owner binding is immutable");
  }
  function retainPage() {
    db.transaction(() => {
      initialize();
      const s = state();
      const options = { limit: deps.pageSize ?? 50 };
      const page = s.baseline_done
        ? deps.exporter.readTailPage({
            ...options,
            ...(s.tail_cursor === null ? {} : { afterSequence: s.tail_cursor }),
          })
        : deps.exporter.readBaselinePage({
            ...options,
            afterSequence: s.baseline_cursor,
          });
      if (page.operations.length) {
        const batch = randomUUID().replaceAll("-", "");
        const envelope: ReplicaEnvelope = {
          format: "vana-pdpp-replica",
          version: 1,
          owner: s.owner,
          batchId: batch,
          operations: page.operations,
        };
        // Fail closed on retained source/declaration drift before advancing the export cursor.
        decodeReplicaEnvelope(canonicalJson(envelope), deps.expected());
        const blobs = [
          ...new Map(
            page.operations
              .flatMap((op) =>
                op.kind === "blob-claim"
                  ? [op.blob]
                  : op.kind === "upsert"
                    ? op.blobs
                    : [],
              )
              .map((blob) => [blob.blobId, blob]),
          ).values(),
        ].map((blob) => {
          const bytes = deps.exporter.readPinnedBlobBytes(blob.blobId);
          if (
            !bytes ||
            bytes.length !== blob.sizeBytes ||
            replicaDigest(bytes) !== blob.sha256
          )
            throw new Error("missing pinned replica bytes");
          return { blobId: blob.blobId, bytes: toBase64(bytes) };
        });
        const bytes = new TextEncoder().encode(
          canonicalJson({ envelope, blobs }),
        );
        const digest = replicaDigest(bytes);
        db.prepare(
          "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,payload) VALUES (?,?,?,?,?,?)",
        ).run(
          batch,
          s.sequence + 1,
          s.previous_json,
          new Date(now()).toISOString(),
          digest,
          bytes,
        );
        db.prepare(
          "UPDATE pdpp_transport_state SET sequence=?, previous_json=? WHERE id=1",
        ).run(s.sequence + 1, canonicalJson({ batch, digest }));
      }
      // Queue + export cursor commit together. They acknowledge durable local responsibility, not publication.
      if (!s.baseline_done) {
        deps.exporter.acknowledgeBaselinePage(
          deps.exporter.getBaselineCheckpoint(),
          page.nextAfterSequence,
        );
        db.prepare(
          "UPDATE pdpp_transport_state SET baseline_cursor=?, baseline_done=? WHERE id=1",
        ).run(page.nextAfterSequence, page.hasMore ? 0 : 1);
      } else
        db.prepare(
          "UPDATE pdpp_transport_state SET tail_cursor=? WHERE id=1",
        ).run(page.nextAfterSequence);
    }).immediate();
  }
  async function prepare() {
    const batches = db
      .prepare(
        "SELECT * FROM pdpp_transport_batches WHERE prepared=0 AND next_attempt<=? ORDER BY attempts,sequence LIMIT 4",
      )
      .all(now()) as Batch[];
    for (const batch of batches) {
      try {
        const s = state();
        const parts = await fragmentReplicaPayload({
          owner: s.owner,
          writer: s.writer,
          batch: batch.batch,
          sequence: batch.sequence,
          previous: batch.previous_json
            ? (JSON.parse(batch.previous_json) as Predecessor)
            : null,
          bytes: batch.payload,
          collectedAt: batch.collected_at,
          encrypt: transport.encrypt,
          maxBlobBytes: cap,
          targetChunkBytes: deps.targetChunkBytes,
        });
        db.transaction(() => {
          // Concurrent preparation may choose different randomized ciphertext. Only the first committed bytes can go on wire.
          const current = db
            .prepare(
              "SELECT prepared FROM pdpp_transport_batches WHERE batch=?",
            )
            .get(batch.batch) as { prepared: number };
          if (current.prepared) return;
          for (const part of parts)
            db.prepare(
              "INSERT INTO pdpp_transport_outbox (scope,batch,plaintext,encrypted,data_hash,metadata_hash) VALUES (?,?,?,?,?,?)",
            ).run(
              part.scope,
              batch.batch,
              part.plaintext,
              part.encrypted,
              part.dataHash,
              part.metadataHash,
            );
          db.prepare(
            "UPDATE pdpp_transport_batches SET prepared=1,error=NULL WHERE batch=?",
          ).run(batch.batch);
        }).immediate();
      } catch (error) {
        db.prepare(
          "UPDATE pdpp_transport_batches SET prepared=?,attempts=attempts+1,next_attempt=?,error=? WHERE batch=?",
        ).run(
          error instanceof RangeError ? -1 : 0,
          now() + Math.min(3600000, 1000 * 2 ** Math.min(batch.attempts, 12)),
          String(error),
          batch.batch,
        );
      }
    }
  }
  const retry = (
    table: "pdpp_transport_outbox" | "pdpp_transport_inbox",
    row: { scope: string; attempts: number },
    error: unknown,
    permanent = false,
  ) => {
    const delay = Math.min(3600000, 1000 * 2 ** Math.min(row.attempts, 12));
    db.prepare(
      `UPDATE ${table} SET attempts=attempts+1,next_attempt=?,error=?,state=? WHERE scope=?`,
    ).run(
      now() + delay,
      String(error),
      permanent ? "quarantined" : "ready",
      row.scope,
    );
  };
  async function publish() {
    // Least-attempted first, due rows only. Old permanently failing rows cannot monopolize LIMIT 50.
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_transport_outbox WHERE state='ready' AND next_attempt<=? ORDER BY attempts, rowid LIMIT 50",
      )
      .all(now()) as Outbox[];
    for (const row of rows) {
      const part: PreparedFragment = {
        scope: row.scope,
        plaintext: row.plaintext,
        encrypted: row.encrypted,
        dataHash: row.data_hash,
        metadataHash: row.metadata_hash,
      };
      try {
        let status = replicaRegistrationState(
          await transport.evidence(row.scope),
          {
            owner: state().owner,
            scope: row.scope,
            dataHash: row.data_hash,
            metadataHash: row.metadata_hash,
          },
        );
        if (status === "absent") {
          await transport.put(part);
          await transport.register(part);
          status = replicaRegistrationState(
            await transport.evidence(row.scope),
            {
              owner: state().owner,
              scope: row.scope,
              dataHash: row.data_hash,
              metadataHash: row.metadata_hash,
            },
          );
        }
        if (status === "conflict")
          retry(
            "pdpp_transport_outbox",
            row,
            "immutable registration conflict",
            true,
          );
        else if (status === "confirmed")
          db.prepare(
            "UPDATE pdpp_transport_outbox SET state='published',error=NULL WHERE scope=?",
          ).run(row.scope);
        else retry("pdpp_transport_outbox", row, "registration not confirmed");
      } catch (error) {
        retry("pdpp_transport_outbox", row, error);
      }
    }
  }
  async function discover() {
    const page = await transport.list(state().scan_cursor);
    db.transaction(() => {
      for (const scope of page.scopes.filter(isReplicaScope))
        db.prepare(
          "INSERT OR IGNORE INTO pdpp_transport_inbox (scope) VALUES (?)",
        ).run(scope);
      db.prepare(
        "UPDATE pdpp_transport_state SET scan_cursor=? WHERE id=1",
      ).run(page.cursor);
    }).immediate();
    // A null cursor restarts from page one next cycle. No timestamp high-water mark can hide a late registration.
  }
  async function download() {
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NULL AND next_attempt<=? ORDER BY attempts,rowid LIMIT 50",
      )
      .all(now()) as Inbox[];
    for (const row of rows) {
      try {
        const evidence = await transport.evidence(row.scope);
        const status = replicaRegistrationState(evidence, {
          owner: state().owner,
          scope: row.scope,
        });
        if (status === "conflict") {
          retry(
            "pdpp_transport_inbox",
            row,
            "immutable registration conflict",
            true,
          );
          continue;
        }
        if (status !== "confirmed") {
          retry("pdpp_transport_inbox", row, "registration not confirmed");
          continue;
        }
        const encrypted = await transport.get(row.scope);
        if (encrypted.length > cap)
          throw new Error("replica ciphertext exceeds storage cap");
        const plaintext = await transport.decrypt(row.scope, encrypted);
        const fragment = decodeReplicaFragment(
          plaintext,
          row.scope,
          state().owner,
        );
        if (
          keccak256(plaintext) !== evidence.head!.dataHash ||
          replicaMetadataHash(
            row.scope,
            fragment.collectedAt,
            encrypted.length,
          ) !== evidence.head!.metadataHash
        )
          throw new Error("replica commitment mismatch");
        db.prepare(
          "UPDATE pdpp_transport_inbox SET fragment_json=?,error=NULL WHERE scope=?",
        ).run(canonicalJson(fragment), row.scope);
      } catch (error) {
        // Network and unavailable bytes are retryable; authenticated malformed bytes remain visible and backed off.
        retry("pdpp_transport_inbox", row, error);
      }
    }
  }
  function importReady() {
    const rows = db
      .prepare(
        "SELECT * FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='ready'",
      )
      .all() as Inbox[];
    const groups = new Map<
      string,
      { row: Inbox; fragment: ReplicaFragment }[]
    >();
    for (const row of rows) {
      const fragment = JSON.parse(row.fragment_json!) as ReplicaFragment;
      const key = canonicalJson([fragment.writer, fragment.batch]);
      groups.set(key, [...(groups.get(key) ?? []), { row, fragment }]);
    }
    for (const entries of groups.values()) {
      const first = entries[0]!.fragment;
      if (entries.length !== first.count) continue;
      const imported = db
        .prepare(
          "SELECT * FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(first.writer, first.batch) as
        { digest: string; sequence: number } | undefined;
      if (!imported && first.previous) {
        const previous = db
          .prepare(
            "SELECT * FROM pdpp_transport_imported WHERE writer=? AND batch=? AND sequence=? AND digest=?",
          )
          .get(
            first.writer,
            first.previous.batch,
            first.sequence - 1,
            first.previous.digest,
          );
        if (!previous) continue;
      }
      try {
        const bytes = assembleReplicaPayload(entries.map((e) => e.fragment));
        const encoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        const payload = payloadSchema.parse(JSON.parse(encoded));
        if (
          canonicalJson(payload) !== encoded ||
          payload.envelope.batchId !== first.batch
        )
          throw new Error("invalid replica payload binding");
        // Trusted retained declarations, never claims copied from the downloaded envelope.
        decodeReplicaEnvelope(canonicalJson(payload.envelope), deps.expected());
        const descriptors = payload.envelope.operations.flatMap((op) =>
          op.kind === "blob-claim"
            ? [op.blob]
            : op.kind === "upsert"
              ? op.blobs
              : [],
        );
        const blobs = payload.blobs.map((blob) => {
          const bytes = fromBase64(blob.bytes);
          if (
            !descriptors.some(
              (d) =>
                d.blobId === blob.blobId &&
                d.sha256 === replicaDigest(bytes) &&
                d.sizeBytes === bytes.length,
            )
          )
            throw new Error("unbound replica binary");
          return { blobId: blob.blobId, bytes };
        });
        db.transaction(() => {
          if (
            imported &&
            (imported.digest !== first.digest ||
              imported.sequence !== first.sequence)
          )
            throw new Error("replica batch equivocation");
          // Nested receiver transaction shares this DB: import and durable acknowledgement are atomic.
          deps.receiver.import({
            credential: deps.credential,
            envelope: payload.envelope,
            blobs,
          });
          if (!imported)
            db.prepare(
              "INSERT INTO pdpp_transport_imported VALUES (?,?,?,?)",
            ).run(first.writer, first.batch, first.sequence, first.digest);
          for (const entry of entries)
            db.prepare(
              "UPDATE pdpp_transport_inbox SET state='imported',error=NULL WHERE scope=?",
            ).run(entry.row.scope);
        }).immediate();
      } catch (error) {
        // Missing declaration/connection authority can be supplied later. Retain verified fragments for retry.
        for (const entry of entries)
          db.prepare(
            "UPDATE pdpp_transport_inbox SET error=? WHERE scope=?",
          ).run(String(error), entry.row.scope);
      }
    }
  }
  let running = false;
  return {
    async cycle() {
      if (!enabled() || running) return;
      running = true;
      try {
        const failures: unknown[] = [];
        // A failed network phase must not prevent progress on work already retained locally.
        for (const phase of [
          retainPage,
          prepare,
          publish,
          discover,
          download,
          importReady,
          () => deps.receiver.retry({ credential: deps.credential }),
        ]) {
          try {
            await phase();
          } catch (error) {
            failures.push(error);
          }
        }
        if (failures.length)
          throw new AggregateError(
            failures,
            "Replica transport cycle incomplete",
          );
      } finally {
        running = false;
      }
    },
  };
}
