import type { Database } from "better-sqlite3";
import { randomUUID } from "node:crypto";
import { keccak256 } from "viem";
import { createHash } from "node:crypto";
import {
  binaryWriter,
  readBinaryChunks,
  deleteBinary,
} from "./pdpp-binary-chunks.js";
import {
  encodeReplicaPayload,
  fragmentReplicaStream,
  assembleReplicaStream,
  inspectReplicaPayload,
} from "@opendatalabs/personal-server-ts-core/replication/stream";
import {
  canonicalJson,
  decodeReplicaEnvelope,
  type EnvelopeExpectation,
  type ReplicaEnvelope,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  decodeReplicaFragment,
  isReplicaScope,
  replicaMetadataHash,
  REPLICA_MAX_BLOB_BYTES,
  type PreparedFragment,
  type ReplicaFragment,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  replicaRegistrationState,
  replicaAwaitingFinality,
  replicaChainCommitment,
  type ReplicaTransportPort,
  type ReplicaRegistrationEvidence,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import type { ReplicationExport } from "./pdpp-replication-sqlite.js";
import type { createReplicaReceiver } from "./pdpp-replication-receiver.js";

// One process owns a transport writer per database; other local instances serialize cycles.
const activeDatabases = new Set<Database | string>();

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
  total_bytes: number;
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
  wait_since: number | null;
  checked_block: string | null;
};
type Inbox = {
  scope: string;
  fragment_json: string | null;
  state: string;
  attempts: number;
  next_attempt: number;
  wait_since: number | null;
  checked_block: string | null;
};

/** Internal experiment only. No bootstrap wiring; false by default, no runtime scheduling. */
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
  for (const table of ["pdpp_transport_outbox", "pdpp_transport_inbox"]) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all() as {
      name: string;
    }[];
    for (const [name, type] of [
      ["wait_since", "INTEGER"],
      ["checked_block", "TEXT"],
    ])
      if (!columns.some((c) => c.name === name))
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${type}`);
  }
  if (
    !(
      db.prepare("PRAGMA table_info(pdpp_transport_batches)").all() as {
        name: string;
      }[]
    ).some((row) => row.name === "total_bytes")
  )
    db.exec(
      "ALTER TABLE pdpp_transport_batches ADD COLUMN total_bytes INTEGER",
    );
  db.exec(
    `CREATE TABLE IF NOT EXISTS pdpp_transport_preparing (token TEXT NOT NULL, scope TEXT NOT NULL, batch TEXT NOT NULL, plaintext BLOB NOT NULL, encrypted BLOB NOT NULL, data_hash TEXT NOT NULL, metadata_hash TEXT NOT NULL, PRIMARY KEY(token,scope));`,
  );
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
  async function retainPage() {
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
    const batch = randomUUID().replaceAll("-", "");
    let digest = "",
      totalBytes = 0;
    try {
      if (page.operations.length) {
        const envelope: ReplicaEnvelope = {
          format: "vana-pdpp-replica",
          version: 1,
          owner: s.owner,
          batchId: batch,
          operations: page.operations,
        };
        decodeReplicaEnvelope(canonicalJson(envelope), deps.expected());
        const writer = binaryWriter(db, "payload", batch);
        const hash = createHash("sha256");
        for await (const bytes of encodeReplicaPayload(
          envelope,
          async function* (id) {
            yield* deps.exporter.readPinnedBlobChunks(id);
          },
        )) {
          db.transaction(() => writer.write(bytes))();
          hash.update(bytes);
          totalBytes += bytes.length;
        }
        writer.finish();
        digest = `sha256:${hash.digest("hex")}`;
      }
      db.transaction(() => {
        const current = state();
        if (
          current.sequence !== s.sequence ||
          current.baseline_cursor !== s.baseline_cursor ||
          current.baseline_done !== s.baseline_done ||
          current.tail_cursor !== s.tail_cursor
        )
          throw new Error("replica retention checkpoint conflict");
        if (page.operations.length) {
          db.prepare(
            "INSERT INTO pdpp_transport_batches (batch,sequence,previous_json,collected_at,digest,payload,total_bytes) VALUES (?,?,?,?,?,?,?)",
          ).run(
            batch,
            s.sequence + 1,
            s.previous_json,
            new Date(now()).toISOString(),
            digest,
            new Uint8Array(),
            totalBytes,
          );
          db.prepare(
            "UPDATE pdpp_transport_state SET sequence=?, previous_json=? WHERE id=1",
          ).run(s.sequence + 1, canonicalJson({ batch, digest }));
        }
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
    } catch (error) {
      deleteBinary(db, "payload", batch);
      throw error;
    }
  }
  async function* payloadBytes(batch: Batch): AsyncIterable<Uint8Array> {
    if (batch.total_bytes !== null) {
      yield* readBinaryChunks(db, "payload", batch.batch);
      return;
    }
    // Durable batches retained by older workers remain retryable.
    const size = (
      db
        .prepare(
          "SELECT length(payload) AS size FROM pdpp_transport_batches WHERE batch=?",
        )
        .get(batch.batch) as { size: number }
    ).size;
    for (let offset = 0; offset < size; offset += 64 * 1024)
      yield (
        db
          .prepare(
            "SELECT substr(payload,?,?) AS bytes FROM pdpp_transport_batches WHERE batch=?",
          )
          .get(offset + 1, 64 * 1024, batch.batch) as { bytes: Buffer }
      ).bytes;
  }
  async function prepare() {
    const batches = db
      .prepare(
        "SELECT batch,sequence,previous_json,collected_at,digest,prepared,attempts,coalesce(total_bytes,length(payload)) AS total_bytes,total_bytes IS NULL AS legacy FROM pdpp_transport_batches WHERE prepared=0 AND next_attempt<=? ORDER BY attempts,sequence LIMIT 4",
      )
      .all(now()) as (Batch & { legacy: number })[];
    for (const batch of batches) {
      const token = randomUUID();
      try {
        const s = state();
        let chunkBytes = deps.targetChunkBytes ?? 4 * 1024 * 1024;
        while (true) {
          try {
            for await (const part of fragmentReplicaStream({
              owner: s.owner,
              writer: s.writer,
              batch: batch.batch,
              sequence: batch.sequence,
              previous: batch.previous_json
                ? (JSON.parse(batch.previous_json) as Predecessor)
                : null,
              collectedAt: batch.collected_at,
              digest: batch.digest,
              totalBytes: batch.total_bytes,
              bytes: () =>
                payloadBytes(
                  batch.legacy
                    ? ({ ...batch, total_bytes: null } as unknown as Batch)
                    : batch,
                ),
              encrypt: transport.encrypt,
              maxBlobBytes: cap,
              targetChunkBytes: chunkBytes,
            }))
              db.prepare(
                "INSERT INTO pdpp_transport_preparing VALUES (?,?,?,?,?,?,?)",
              ).run(
                token,
                part.scope,
                batch.batch,
                part.plaintext,
                part.encrypted,
                part.dataHash,
                part.metadataHash,
              );
            break;
          } catch (error) {
            db.prepare(
              "DELETE FROM pdpp_transport_preparing WHERE token=?",
            ).run(token);
            if (
              !(error instanceof RangeError) ||
              !String(error).includes("encrypted fragment exceeds") ||
              chunkBytes === 1
            )
              throw error;
            chunkBytes = Math.max(1, Math.floor(chunkBytes / 2));
          }
        }
        db.transaction(() => {
          const current = db
            .prepare(
              "SELECT prepared FROM pdpp_transport_batches WHERE batch=?",
            )
            .get(batch.batch) as { prepared: number };
          if (!current.prepared) {
            db.prepare(
              "INSERT INTO pdpp_transport_outbox (scope,batch,plaintext,encrypted,data_hash,metadata_hash) SELECT scope,batch,plaintext,encrypted,data_hash,metadata_hash FROM pdpp_transport_preparing WHERE token=?",
            ).run(token);
            db.prepare(
              "UPDATE pdpp_transport_batches SET prepared=1,error=NULL WHERE batch=?",
            ).run(batch.batch);
          }
          db.prepare("DELETE FROM pdpp_transport_preparing WHERE token=?").run(
            token,
          );
        }).immediate();
      } catch (error) {
        db.prepare("DELETE FROM pdpp_transport_preparing WHERE token=?").run(
          token,
        );
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
      `UPDATE ${table} SET attempts=attempts+1,next_attempt=?,error=?,state=?,wait_since=NULL,checked_block=NULL WHERE scope=?`,
    ).run(
      now() + delay,
      String(error),
      permanent ? "quarantined" : "ready",
      row.scope,
    );
  };
  type DeliveryTable = "pdpp_transport_outbox" | "pdpp_transport_inbox";
  type WaitingRow = Outbox | Inbox;
  let finalizedHead: bigint | undefined;
  let lastHeadPoll = -Infinity;
  async function pollFinalizedHead() {
    if (!transport.finality || now() - lastHeadPoll < 2000) return;
    lastHeadPoll = now();
    // A failed hint cannot authorize progress or move a durable error retry.
    try {
      finalizedHead = await transport.finality.head();
      if (typeof finalizedHead !== "bigint" || finalizedHead < 0n)
        throw new Error("invalid scheduling head");
    } catch {
      finalizedHead = undefined;
    }
  }
  function eligibleWaitingSql() {
    if (finalizedHead === undefined) return "1";
    // Filter parked waits before LIMIT so they cannot hide fresh/error work.
    const head = String(finalizedHead);
    return `(wait_since IS NULL OR checked_block IS NULL OR
      length(checked_block)<${head.length} OR (length(checked_block)=${head.length} AND checked_block<'${head}') OR
      wait_since<=${now() - 600000})`;
  }
  function waitForFinality(
    table: DeliveryTable,
    row: WaitingRow,
    evidence: ReplicaRegistrationEvidence,
  ) {
    const since = row.wait_since ?? now();
    const old = row.checked_block === null ? null : BigInt(row.checked_block);
    const observed = evidence.chain!.blockNumber;
    const progressed = old === null || observed > old;
    const checked = old !== null && old > observed ? old : observed;
    db.prepare(
      `UPDATE ${table} SET attempts=0,wait_since=?,checked_block=?,next_attempt=?,error=NULL WHERE scope=?`,
    ).run(
      since,
      String(checked),
      now() +
        ((transport.finality !== undefined && !progressed) ||
        now() - since >= 600000
          ? 30000
          : 2000),
      row.scope,
    );
  }
  async function publish() {
    // Due deadlines rotate waiting/error rows behind fresh work. Parked waits do not consume the budget.
    const rows = db
      .prepare(
        `SELECT scope,batch,data_hash,metadata_hash,state,attempts,next_attempt,wait_since,checked_block FROM pdpp_transport_outbox WHERE state='ready' AND next_attempt<=? AND ${eligibleWaitingSql()} ORDER BY next_attempt, rowid LIMIT 50`,
      )
      .all(now()) as Outbox[];
    for (const row of rows) {
      try {
        let evidence = await transport.evidence(row.scope);
        let status = replicaRegistrationState(evidence, {
          owner: state().owner,
          scope: row.scope,
          dataHash: row.data_hash,
          metadataHash: row.metadata_hash,
        });
        if (status === "absent") {
          const bytes = db
            .prepare(
              "SELECT plaintext,encrypted FROM pdpp_transport_outbox WHERE scope=?",
            )
            .get(row.scope) as Pick<Outbox, "plaintext" | "encrypted">;
          const part: PreparedFragment = {
            scope: row.scope,
            plaintext: bytes.plaintext,
            encrypted: bytes.encrypted,
            dataHash: row.data_hash,
            metadataHash: row.metadata_hash,
          };
          await transport.put(part);
          await transport.register(part);
          evidence = await transport.evidence(row.scope);
          status = replicaRegistrationState(evidence, {
            owner: state().owner,
            scope: row.scope,
            dataHash: row.data_hash,
            metadataHash: row.metadata_hash,
          });
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
            "UPDATE pdpp_transport_outbox SET state='published',attempts=0,wait_since=NULL,error=NULL WHERE scope=?",
          ).run(row.scope);
        else if (
          replicaAwaitingFinality(evidence, {
            owner: state().owner,
            scope: row.scope,
            dataHash: row.data_hash,
            metadataHash: row.metadata_hash,
          })
        )
          waitForFinality("pdpp_transport_outbox", row, evidence);
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
        `SELECT * FROM pdpp_transport_inbox WHERE state='ready' AND fragment_json IS NULL AND next_attempt<=? AND ${eligibleWaitingSql()} ORDER BY next_attempt,rowid LIMIT 50`,
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
          if (
            replicaAwaitingFinality(evidence, {
              owner: state().owner,
              scope: row.scope,
            })
          )
            waitForFinality("pdpp_transport_inbox", row, evidence);
          else retry("pdpp_transport_inbox", row, "registration not confirmed");
          continue;
        }
        // Retain the exact head whose hash-pair preimage was verified against the chain.
        const head = evidence.head!;
        const encrypted = await transport.get(row.scope);
        if (encrypted.length > cap)
          throw new Error("replica ciphertext exceeds storage cap");
        const plaintext = await transport.decrypt(row.scope, encrypted);
        const fragment = decodeReplicaFragment(
          plaintext,
          row.scope,
          state().owner,
        );
        const dataHash = keccak256(plaintext);
        const metadataHash = replicaMetadataHash(
          row.scope,
          fragment.collectedAt,
          encrypted.length,
        );
        // The chain is the authority even when the Gateway head matches the downloaded bytes.
        if (
          replicaChainCommitment(dataHash, metadataHash).toLowerCase() !==
            evidence.chain!.commitment.toLowerCase() ||
          dataHash !== head.dataHash ||
          metadataHash !== head.metadataHash
        )
          throw new Error("replica commitment mismatch");
        db.prepare(
          "UPDATE pdpp_transport_inbox SET fragment_json=?,attempts=0,wait_since=NULL,error=NULL WHERE scope=?",
        ).run(canonicalJson(fragment), row.scope);
      } catch (error) {
        // Network and unavailable bytes are retryable; authenticated malformed bytes remain visible and backed off.
        retry("pdpp_transport_inbox", row, error);
      }
    }
  }
  async function importReady() {
    // JSON metadata only: no retained content strings from incomplete or other groups.
    const groups = db
      .prepare(
        `SELECT json_extract(fragment_json,'$.writer') AS writer, json_extract(fragment_json,'$.batch') AS batch, count(*) AS rows, json_extract(fragment_json,'$.count') AS count FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='ready' GROUP BY writer,batch HAVING rows=count ORDER BY json_extract(fragment_json,'$.sequence'),writer,batch`,
      )
      .all() as { writer: string; batch: string }[];
    for (const group of groups) {
      const metadata = db
        .prepare(
          `SELECT scope,json_extract(fragment_json,'$.index') AS position FROM pdpp_transport_inbox WHERE state='ready' AND json_extract(fragment_json,'$.writer')=? AND json_extract(fragment_json,'$.batch')=? ORDER BY position`,
        )
        .all(group.writer, group.batch) as {
        scope: string;
        position: number;
      }[];
      const readFragment = (scope: string) =>
        JSON.parse(
          (
            db
              .prepare(
                "SELECT fragment_json FROM pdpp_transport_inbox WHERE scope=?",
              )
              .get(scope) as { fragment_json: string }
          ).fragment_json,
        ) as ReplicaFragment;
      const first = readFragment(metadata[0]!.scope);
      const imported = db
        .prepare(
          "SELECT digest,sequence FROM pdpp_transport_imported WHERE writer=? AND batch=?",
        )
        .get(first.writer, first.batch) as
        { digest: string; sequence: number } | undefined;
      if (
        !imported &&
        first.previous &&
        !db
          .prepare(
            "SELECT 1 FROM pdpp_transport_imported WHERE writer=? AND batch=? AND sequence=? AND digest=?",
          )
          .get(
            first.writer,
            first.previous.batch,
            first.sequence - 1,
            first.previous.digest,
          )
      )
        continue;
      const bytes = () =>
        assembleReplicaStream(async function* () {
          for (const row of metadata) yield readFragment(row.scope);
        });
      const staging: string[] = [];
      try {
        const writers = new Map<
          number,
          { key: string; writer: ReturnType<typeof binaryWriter> }
        >();
        const payload = await inspectReplicaPayload(
          bytes,
          deps.expected(),
          (_blobId, chunk, blobIndex) => {
            let target = writers.get(blobIndex);
            if (!target) {
              const key = randomUUID();
              staging.push(key);
              target = { key, writer: binaryWriter(db, "staging", key) };
              writers.set(blobIndex, target);
            }
            db.transaction(() => target.writer.write(chunk))();
          },
        );
        if (payload.envelope.batchId !== first.batch)
          throw new Error("invalid replica payload binding");
        const stagedBlobs = payload.blobs.map((blob, index) => {
          let target = writers.get(index);
          if (!target) {
            const key = randomUUID();
            staging.push(key);
            target = { key, writer: binaryWriter(db, "staging", key) };
          }
          if (target.writer.finish() !== blob.sizeBytes)
            throw new Error("invalid replica binary size");
          return {
            blobId: blob.blobId,
            key: target.key,
            sizeBytes: blob.sizeBytes,
          };
        });
        db.transaction(() => {
          if (
            imported &&
            (imported.digest !== first.digest ||
              imported.sequence !== first.sequence)
          )
            throw new Error("replica batch equivocation");
          deps.receiver.import({
            credential: deps.credential,
            envelope: payload.envelope,
            stagedBlobs,
          });
          if (!imported)
            db.prepare(
              "INSERT INTO pdpp_transport_imported VALUES (?,?,?,?)",
            ).run(first.writer, first.batch, first.sequence, first.digest);
          for (const row of metadata)
            db.prepare(
              "UPDATE pdpp_transport_inbox SET state='imported',error=NULL WHERE scope=?",
            ).run(row.scope);
        }).immediate();
      } catch (error) {
        for (const row of metadata)
          db.prepare(
            "UPDATE pdpp_transport_inbox SET error=? WHERE scope=?",
          ).run(String(error), row.scope);
      } finally {
        for (const key of staging) deleteBinary(db, "staging", key);
      }
    }
  }
  let running = false;
  const databaseKey = db.name && db.name !== ":memory:" ? db.name : db;
  return {
    async cycle() {
      if (!enabled() || running || activeDatabases.has(databaseKey)) return;
      running = true;
      activeDatabases.add(databaseKey);
      try {
        // Only this process owns the worker. None of these hidden stages can be published.
        db.transaction(() => {
          db.prepare("DELETE FROM pdpp_transport_preparing").run();
          for (const table of ["pdpp_binary_chunks", "pdpp_binary_manifests"]) {
            db.prepare(
              `DELETE FROM ${table} WHERE namespace='staging' OR (namespace='payload' AND NOT EXISTS (SELECT 1 FROM pdpp_transport_batches b WHERE b.batch=${table}.blob_id))`,
            ).run();
          }
        }).immediate();
        const failures: unknown[] = [];
        // A failed network phase must not prevent progress on work already retained locally.
        for (const phase of [
          retainPage,
          prepare,
          pollFinalizedHead,
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
        activeDatabases.delete(databaseKey);
      }
    },
  };
}
