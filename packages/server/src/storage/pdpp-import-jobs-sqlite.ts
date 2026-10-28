/**
 * Node SQLite adapter of the PDPP import job contract (version 1). Tables
 * live in the record store's database; publication applies the staged
 * latest-operation index through `ingestBatch` and `completeStreams` inside
 * one `writeTransaction`, so history, arrival, blob claims and replication
 * capture (when enabled) are the store's own. See
 * docs/261028-pdpp-import-job.md.
 */

import type { Database } from "better-sqlite3";
import { open } from "node:fs/promises";
import {
  ImportJobError,
  PDPP_IMPORT_JOB_CONTRACT_VERSION,
  type ImportBatchReceipt,
  type ImportCommitReceipt,
  type ImportConnectorState,
  type ImportJobRecord,
  type ImportPublishInput,
  type ImportSpoolHandle,
  type PdppImportJobCapability,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-import-job";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  StreamCompletionError,
  type createSqliteRecordStore,
} from "./pdpp-records-sqlite-store.js";

type SqliteRecordStore = Pick<
  ReturnType<typeof createSqliteRecordStore>,
  "ingestBatch" | "getInstanceBinding" | "writeTransaction" | "completeStreams"
>;

export type SqliteImportFaultPoint =
  | "stage:before-commit"
  | "stage:after-commit"
  | "publish:before-commit"
  | "publish:after-commit";

export interface SqliteImportJobCapabilityOptions {
  /** Index rows applied per `ingestBatch` call at publication. */
  pageSize?: number;
  /** Where a spool handle's bytes are; enables `readSpool`. */
  spoolPath?: (spool: ImportSpoolHandle) => string;
  /** Test hook: throw (or kill the process) at a commit boundary. */
  fault?: (point: SqliteImportFaultPoint) => void;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS pdpp_import_jobs (
  job_id TEXT PRIMARY KEY,
  instance TEXT NOT NULL,
  state TEXT NOT NULL,
  record TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pdpp_import_batches (
  job_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  receipt TEXT NOT NULL,
  PRIMARY KEY (job_id, seq)
);
CREATE TABLE IF NOT EXISTS pdpp_import_staged (
  job_id TEXT NOT NULL,
  stream TEXT NOT NULL,
  record_key TEXT NOT NULL,
  ord INTEGER NOT NULL,
  key_json TEXT NOT NULL,
  op TEXT NOT NULL,
  data TEXT,
  emitted_at TEXT NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (job_id, stream, record_key)
);
CREATE INDEX IF NOT EXISTS pdpp_import_staged_order
  ON pdpp_import_staged (job_id, ord);
CREATE TABLE IF NOT EXISTS pdpp_import_connector_state (
  instance TEXT PRIMARY KEY,
  generation INTEGER NOT NULL,
  job_id TEXT NOT NULL,
  state TEXT NOT NULL,
  committed_at TEXT NOT NULL
);
`;

interface StagedRowDb {
  stream: string;
  record_key: string;
  ord: number;
  key_json: string;
  op: "upsert" | "delete";
  data: string | null;
  emitted_at: string;
}

export function createSqliteImportJobCapability(
  db: Database,
  store: SqliteRecordStore,
  options: SqliteImportJobCapabilityOptions = {},
): PdppImportJobCapability {
  const pageSize = options.pageSize ?? 256;
  const fault = options.fault ?? (() => {});
  db.exec(SCHEMA);

  const readJobStmt = db.prepare(
    "SELECT record FROM pdpp_import_jobs WHERE job_id = ?",
  );
  const insertJobStmt = db.prepare(
    "INSERT INTO pdpp_import_jobs (job_id, instance, state, record) VALUES (?, ?, ?, ?) ON CONFLICT (job_id) DO NOTHING",
  );
  const updateJobStmt = db.prepare(
    "UPDATE pdpp_import_jobs SET state = ?, record = ? WHERE job_id = ?",
  );
  const readReceiptStmt = db.prepare(
    "SELECT receipt FROM pdpp_import_batches WHERE job_id = ? AND seq = ?",
  );
  const insertReceiptStmt = db.prepare(
    "INSERT INTO pdpp_import_batches (job_id, seq, receipt) VALUES (?, ?, ?)",
  );
  const stageLastStmt = db.prepare(`
    INSERT INTO pdpp_import_staged (job_id, stream, record_key, ord, key_json, op, data, emitted_at, digest)
    VALUES (@job_id, @stream, @record_key, @ord, @key_json, @op, @data, @emitted_at, @digest)
    ON CONFLICT (job_id, stream, record_key) DO UPDATE SET
      ord = excluded.ord, key_json = excluded.key_json, op = excluded.op,
      data = excluded.data, emitted_at = excluded.emitted_at, digest = excluded.digest
  `);
  const stageFirstStmt = db.prepare(`
    INSERT INTO pdpp_import_staged (job_id, stream, record_key, ord, key_json, op, data, emitted_at, digest)
    VALUES (@job_id, @stream, @record_key, @ord, @key_json, @op, @data, @emitted_at, @digest)
    ON CONFLICT (job_id, stream, record_key) DO NOTHING
  `);
  const stagedPageStmt = db.prepare(
    "SELECT stream, record_key, ord, key_json, op, data, emitted_at FROM pdpp_import_staged WHERE job_id = ? AND ord > ? ORDER BY ord LIMIT ?",
  );
  const stagedCountStmt = db.prepare(
    "SELECT COUNT(*) AS n FROM pdpp_import_staged WHERE job_id = ?",
  );
  const dropStagedStmt = db.prepare(
    "DELETE FROM pdpp_import_staged WHERE job_id = ?",
  );
  const putStateStmt = db.prepare(`
    INSERT INTO pdpp_import_connector_state (instance, generation, job_id, state, committed_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (instance) DO UPDATE SET
      generation = excluded.generation, job_id = excluded.job_id,
      state = excluded.state, committed_at = excluded.committed_at
  `);
  const readStateStmt = db.prepare(
    "SELECT * FROM pdpp_import_connector_state WHERE instance = ?",
  );

  function readJob(jobId: string): ImportJobRecord | undefined {
    const row = readJobStmt.get(jobId) as { record: string } | undefined;
    return row && (JSON.parse(row.record) as ImportJobRecord);
  }
  function writeJob(job: ImportJobRecord): void {
    updateJobStmt.run(job.state, JSON.stringify(job), job.jobId);
  }
  function readReceipt(
    jobId: string,
    seq: number,
  ): ImportBatchReceipt | undefined {
    const row = readReceiptStmt.get(jobId, seq) as
      { receipt: string } | undefined;
    return row && (JSON.parse(row.receipt) as ImportBatchReceipt);
  }

  function publish(input: ImportPublishInput): ImportCommitReceipt {
    const result = store.writeTransaction(() => {
      const job = readJob(input.job.jobId);
      if (!job) throw new ImportJobError("job_not_found");
      if (job.state === "committed" && job.commit) return job.commit;
      if (job.state !== "open") throw new ImportJobError("job_not_open");
      if (job.nextSeq !== input.job.nextSeq)
        throw new ImportJobError("batch_count_mismatch");
      const { instance, sourceId, method, generation } = job.binding;
      const binding = store.getInstanceBinding(instance);
      if (
        binding.deletedAt !== null ||
        binding.sourceId !== sourceId ||
        binding.method !== method ||
        binding.generation !== generation
      )
        throw new ImportJobError("binding_mismatch");
      const declare = (stream: string) => {
        const declaration = input.declarations.forInstance(instance, stream);
        if (!declaration)
          throw new ImportJobError(
            "stream_not_declared",
            `stream '${stream}' is no longer declared`,
          );
        return declaration;
      };

      const operations = (stagedCountStmt.get(job.jobId) as { n: number }).n;
      let accepted = 0;
      let unchanged = 0;
      let rejected = 0;
      let after = -1;
      for (;;) {
        const page = stagedPageStmt.all(
          job.jobId,
          after,
          pageSize,
        ) as StagedRowDb[];
        if (page.length === 0) break;
        after = page[page.length - 1].ord;
        const envelopes: PdppRecordEnvelopeInput[] = page.map((row) => ({
          instance,
          stream: row.stream,
          key: JSON.parse(row.key_json) as PdppRecordEnvelopeInput["key"],
          data:
            row.data === null
              ? null
              : (JSON.parse(row.data) as Record<string, unknown>),
          emitted_at: row.emitted_at,
          op: row.op,
        }));
        const outcome = store.ingestBatch(
          envelopes,
          (stream) => declare(stream).semantics,
          (stream) => declare(stream).primaryKey,
          { method, generation },
          input.declarations.validateData,
          (stream) => declare(stream).binding,
        );
        accepted += outcome.accepted;
        unchanged += outcome.unchanged;
        rejected += outcome.rejected.length;
      }

      const completedStreams: string[] = [];
      if (input.completion) {
        try {
          const { receipts } = store.completeStreams(
            {
              instance,
              sourceId,
              method,
              generation,
              sourceCollectedAt: input.completion.sourceCollectedAt,
              collectionTimeBasis: "host_run_finished",
              streams: input.completion.streams,
            },
            (_sourceId, stream) =>
              input.declarations.forInstance(instance, stream)?.primaryKey,
          );
          completedStreams.push(...receipts.map((receipt) => receipt.stream));
        } catch (error) {
          if (error instanceof StreamCompletionError)
            throw new ImportJobError("completion_failed", error.reason);
          throw error;
        }
      }
      if (input.connectorState !== undefined)
        putStateStmt.run(
          instance,
          generation,
          job.jobId,
          input.connectorState,
          input.committedAt,
        );
      const receipt: ImportCommitReceipt = {
        jobId: job.jobId,
        contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,
        instance,
        generation,
        batches: job.nextSeq,
        records: job.records,
        operations,
        accepted,
        unchanged,
        rejected: job.rejected + rejected,
        completedStreams,
        connectorStateSha256: input.connectorStateSha256,
        committedAt: input.committedAt,
      };
      writeJob({
        ...job,
        state: "committed",
        updatedAt: input.committedAt,
        commit: receipt,
      });
      dropStagedStmt.run(job.jobId);
      fault("publish:before-commit");
      return receipt;
    });
    fault("publish:after-commit");
    return result;
  }

  return {
    contractVersion: PDPP_IMPORT_JOB_CONTRACT_VERSION,

    async readBinding(instance) {
      const binding = store.getInstanceBinding(instance);
      return {
        sourceId: binding.sourceId,
        method: binding.method,
        generation: binding.generation,
        deleted: binding.deletedAt !== null,
      };
    },

    async createJob(job) {
      insertJobStmt.run(
        job.jobId,
        job.binding.instance,
        job.state,
        JSON.stringify(job),
      );
      return readJob(job.jobId)!;
    },

    async readJob(jobId) {
      return readJob(jobId);
    },

    async stageBatch({ job, receipt, operations }) {
      const stored = db
        .transaction((): ImportBatchReceipt => {
          const existing = readReceipt(receipt.jobId, receipt.seq);
          if (existing) return existing;
          const current = readJob(job.jobId);
          if (!current || current.state !== "open")
            throw new ImportJobError("job_not_open");
          if (current.nextSeq !== receipt.seq)
            throw new ImportJobError("batch_out_of_order");
          for (const operation of operations) {
            (operation.keep === "first" ? stageFirstStmt : stageLastStmt).run({
              job_id: job.jobId,
              stream: operation.stream,
              record_key: operation.recordKey,
              ord: operation.order,
              key_json: operation.keyJson,
              op: operation.op,
              data: operation.dataJson,
              emitted_at: operation.emittedAt,
              digest: operation.digest,
            });
          }
          insertReceiptStmt.run(
            receipt.jobId,
            receipt.seq,
            JSON.stringify(receipt),
          );
          writeJob(job);
          fault("stage:before-commit");
          return receipt;
        })
        .immediate();
      fault("stage:after-commit");
      return stored;
    },

    async readBatchReceipt(jobId, seq) {
      return readReceipt(jobId, seq);
    },

    async publish(input) {
      return publish(input);
    },

    async abort(jobId, reason, at) {
      return db
        .transaction((): ImportJobRecord | undefined => {
          const job = readJob(jobId);
          if (!job || job.state !== "open") return job;
          const aborted: ImportJobRecord = {
            ...job,
            state: "aborted",
            abortReason: reason,
            updatedAt: at,
          };
          writeJob(aborted);
          dropStagedStmt.run(jobId);
          return aborted;
        })
        .immediate();
    },

    async readConnectorState(
      instance,
    ): Promise<ImportConnectorState | undefined> {
      const row = readStateStmt.get(instance) as
        | {
            instance: string;
            generation: number;
            job_id: string;
            state: string;
            committed_at: string;
          }
        | undefined;
      return (
        row && {
          instance: row.instance,
          generation: row.generation,
          jobId: row.job_id,
          state: row.state,
          committedAt: row.committed_at,
        }
      );
    },

    ...(options.spoolPath
      ? {
          async readSpool(
            spool: ImportSpoolHandle,
            offset: number,
            maxBytes: number,
          ) {
            const file = await open(options.spoolPath!(spool), "r");
            try {
              const buffer = new Uint8Array(maxBytes);
              const { bytesRead } = await file.read(
                buffer,
                0,
                maxBytes,
                offset,
              );
              return buffer.subarray(0, bytesRead);
            } finally {
              await file.close();
            }
          },
        }
      : {}),
  };
}
